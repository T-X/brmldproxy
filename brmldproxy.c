/* SPDX-FileCopyrightText: 2023 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <arpa/inet.h> // inet_pton()
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h> // IFNAMSIZ, if_nametoindex()
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "brmldproxy.h"
#include "brmonmdb.h"
#include "listener.h"
#include "list.h"

/*
 * brmldproxy - an MLD proxy for a Linux bridge
 *
 * If only given a bridge then proxies MLD between each bridge port.
 *
 * What's the difference between MLD being forwarded by the bridge?
 * Multiple MLD reports containing the same multicast group(s) will
 * be combined in a single MLD report.
 *
 * How is this achieved?
 * The bridge will adopt any multicast listener it snooped. And will
 * act as a single, reporting host on behalf. Dummy network interfaces
 * and "tc" are used to achieve this.
 */

/*
 * "-p" / --proxied-response-port
 * - if not set then implies that either:
 *   - if "-i" is set: each port of "-i" is also a "-p" port
 *   - else if "-i" is not set: each port, excluding "-e"
 *     ports, are also "-p" ports
 *
 * "-e" / --excluded-port
 * - if not set: no special implications
 *
 * "-i" / --included-port
 * - if not set then implies that: each port, excluding "-e"
 *   ports, are also "-i" ports
 *
 * Note: the "-b" bridge interface itself is handled just like
 * a bridge port for "-i" / "-e" / "-p"
 */

#define PD_FWMARK "0x0800000"

void signal_handler_shutdown(int signum)
{
	bridge_monitor_mdb_shutdown();
}

void signal_handler_status(int signum)
{
	bridge_monitor_mdb_status();
}

void setup_signal_handler(void)
{
	struct sigaction new_action, old_action;

	new_action.sa_handler = &signal_handler_shutdown;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;

	sigaction(SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGINT, &new_action, NULL);

	sigaction(SIGHUP, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGHUP, &new_action, NULL);

	sigaction(SIGTERM, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGTERM, &new_action, NULL);

	sigaction(SIGUSR1, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN) {
		new_action.sa_handler = &signal_handler_status;
		sigaction(SIGUSR1, &new_action, NULL);
	}
}

static void usage()
{
	printf("Usage: brmldproxy -b <bridge> [<options> ...]\n\n");
	printf("    -b <bridge>                         bridge interface brmldproxy will run on\n");
	printf("\nOptions:\n");
	printf("    -4                                  IPv4-only mode (not yet implemented)\n");
	printf("    -6                                  IPv6-only mode (default)\n");
	printf("    -i <bridge-port>                    bridge port to proxy (from)\n");
	// TODO:
	//printf("    -i <bridge-port>[@<bridge-port]     bridge port to proxy (from)\n");
	printf("    -e <bridge-port>                    bridge port to exclude from proxying\n");
	// TODO:
	//printf("    -e <bridge-port>[@<bridge-port]     bridge port to exclude from proxying\n");
	printf("    -p <bridge-port>                    bridge port to proxy to\n");
	printf("    -I <mcast-address>[/mask]           multicast IP address (range) to include in proxying\n");
	//printf("    -I <mcast-address>[/mask][@br-port] multicast IP address (range) to include in proxying\n");
	printf("    -E <mcast-address>[/mask]           multicast IP address (range) to exclude from proxying\n");
	//printf("    -E <mcast-address>[/mask][@br-port] multicast IP address (range) to exclude from proxying\n");
	// TODO: insert filters to avoid MLD being forwarded on configured ports:
	//printf("    -f\n");
}

static int parse_bridge_arg(struct bridge *br, int argc, char *argv[],
		int *have_incl_ports, int *have_excl_ports, int *have_prox_ports)
{
	int opt;
	int ipv6_only = 0;

	INIT_LIST_HEAD(&br->included_ports_list);
	INIT_LIST_HEAD(&br->excluded_ports_list);
	INIT_LIST_HEAD(&br->proxied_ports_list);
	INIT_LIST_HEAD(&br->group_filter_list_v4);
	INIT_LIST_HEAD(&br->group_filter_list_v6);
	memset(br->name, 0, sizeof(br->name));

	*have_incl_ports = *have_excl_ports = *have_prox_ports = 0;

	while ((opt = getopt(argc, argv, "46b:i:e:p:I:E:h")) != -1) {
		switch (opt) {
		case '4':
			fprintf(stderr, "Error: IPv4 not yet implemented\n");
			return -EINVAL;
		case '6':
			ipv6_only = 1;
			break;
		case 'b':
			if (strlen(br->name)) {
				/* TODO: implement/allow this later? */
				fprintf(stderr, "Error: Multiple \"-b <bridge>\" arguments not supported\n\n");
				usage();
				return -EINVAL;
			}

			if (strlen(optarg) + 1 > sizeof(br->name)) {
				fprintf(stderr, "Error: bridge name \"%s\" is too long\n", optarg);
				return -EINVAL;
			}

			strcpy(br->name, optarg);
			break;
		case 'i':
			*have_incl_ports = 1;
			break;
		case 'e':
			*have_excl_ports = 1;
			break;
		case 'p':
			*have_prox_ports = 1;
			break;
		case 'h':
			usage();
			exit(0);
		}
	}

	if (*have_incl_ports && *have_excl_ports) {
		fprintf(stderr, "Error: Using both \"-i\" and \"-e\" is not allowed\n\n");
		usage();
		return -EINVAL;
	}

	if (!strlen(br->name)) {
		fprintf(stderr, "Error: Missing mandatory \"-b <bridge>\" option\n\n");
		usage();
		return -EINVAL;
	}

	br->ifindex = if_nametoindex(br->name);
	if (!br->ifindex) {
		fprintf(stderr,
			"Error: Could not determine interface index of bridge \"%s\"\n\n",
			br->name);
		usage();
		return -EINVAL;
	}

	if (!ipv6_only)
		fprintf(stderr, "Warning: IPv4 not yet implemented, use \"-6\" to suppress this warning\n");

	return 0;
}

static int add_bridge_port(struct list_head *ports, const char *name, unsigned int ifindex)
{
	struct brport *port;
	int ret;

	port = malloc(sizeof(*port));
	if (!port)
		return -ENOMEM;

	ret = snprintf(port->name, sizeof(port->name), "%s", name);
	if (ret < 0) {
		free(port);
		return -EINVAL;
	}

	port->ifindex = ifindex;
	port->prifindex = 0;
	memset(port->prname, 0, sizeof(port->prname));
	INIT_LIST_HEAD(&port->node);
	INIT_LIST_HEAD(&port->listener_list_v4);
	INIT_LIST_HEAD(&port->listener_list_v6);

	list_add_tail(&port->node, ports);
	return 0;
}

static int add_bridge_port_by_name(struct list_head *ports, const char *name)
{
	unsigned int ifindex;

	ifindex = if_nametoindex(name);
	if (!ifindex) {
		fprintf(stderr,
			"Error: Could not get interface index for bridge port \"%s\"\n",
			name);
		return -ENOENT;
	}

	return add_bridge_port(ports, name, ifindex);
}

static void free_ports(struct list_head *head)
{
	struct brport *port, *tmp;

	list_for_each_entry_safe(port, tmp, head, node) {
		list_del(&port->node);
		free(port);
	}
}

/* TODO: replace with netlink maybe? */
static int get_bridge_mld_version(struct bridge *br)
{
	const char *format = "/sys/class/net/%s/bridge/multicast_mld_version";
	unsigned int filename_size_max = strlen(format) - strlen("%s") + IFNAMSIZ;
	char filename[filename_size_max];
	char mld_version[16];
	FILE *file;
	int ret;

	ret = snprintf(filename, filename_size_max, format, br->name);
	if (ret < 0 || !(file = fopen(filename, "r")) ||
	    !fgets(mld_version, sizeof(mld_version), file) ||
	    !(ret = atoi(mld_version))) {
		fprintf(stderr,
			"Error: Could not parse bridge MLD version for \"%s\"\n",
			br->name);
		return -EINVAL;
	}

	return ret;
}

/* TODO: replace with netlink maybe? */
static int get_bridge_ports(struct bridge *br, struct list_head *ports)
{
	const char *format = "/sys/class/net/%s/brif/";
	unsigned int filename_size_max = strlen(format) - strlen("%s") + IFNAMSIZ;
	char filename[filename_size_max];
	struct dirent *ent;
	DIR *dir;
	int ret;

	ret = snprintf(filename, filename_size_max, format, br->name);
	if (ret < 0) {
		fprintf(stderr,
			"Error: Could not parse bridge ports for \"%s\"\n",
			br->name);
		return ret;
	}

	dir = opendir(filename);
	if (!dir) {
		fprintf(stderr,
			"Error: Could not parse bridge ports for \"%s\"\n",
			br->name);
		return -ENOTDIR;
	}

	/* treat bridge interface like a bridge port */
	ret = add_bridge_port(ports, br->name, br->ifindex);
	if (ret < 0)
		goto out;

	while ((ent = readdir(dir))) {
		if (!strcmp(ent->d_name, ".") ||
		    !strcmp(ent->d_name, ".."))
			continue;

		ret = add_bridge_port_by_name(ports, ent->d_name);
		if (ret < 0)
			break;
	}
	closedir(dir);

out:
	if (ret < 0)
		free_ports(ports);

	return ret;
}

static int migrate_port_to_list(struct list_head *ports, struct list_head *to, const char *name)
{
	struct brport *port;

	list_for_each_entry(port, ports, node) {
		if (strcmp(port->name, name))
			continue;

		list_move_tail(&port->node, to);
		return 0;
	}

	fprintf(stderr, "Error: Could not add bridge port \"%s\" - unavailable or already added?\n", name);
	return -ENOENT;
}

static int parse_inet_pton(const char *src, struct sockaddr_storage *dst)
{
	int ret, af = AF_INET;

	ret = inet_pton(af, src, &((struct sockaddr_in *)dst)->sin_addr);
	if (ret == 1)
		goto out;

	af = AF_INET6;
	ret = inet_pton(af, src, &((struct sockaddr_in6 *)dst)->sin6_addr);
	if (ret == 1)
		goto out;

	return -EINVAL;
out:
	dst->ss_family = af;
	return af;
}

static void parse_filter_prefixfull_to_mask(int af,
					    struct sockaddr_storage *mask)
{
	if (af == AF_INET) {
		struct sockaddr_in *mask4 = (struct sockaddr_in *)mask;

		mask4->sin_family = AF_INET;
		memset(&mask4->sin_addr, 0xff, sizeof(mask4->sin_addr));
	/* af == AF_INET6 */
	} else {
		struct sockaddr_in6 *mask6 = (struct sockaddr_in6 *)mask;

		mask6->sin6_family = AF_INET6;
		memset(&mask6->sin6_addr, 0xff, sizeof(mask6->sin6_addr));
	}
}

static uint32_t parse_filter_u32_mask(unsigned short len)
{
	return htonl(~((uint32_t)((1ULL << (32 - len)) - 1)));
}

static int parse_filter_prefixlen_to_mask_v4(struct sockaddr_storage *mask,
					     unsigned long len)
{
	struct sockaddr_in *mask4 = (struct sockaddr_in *)mask;

	if (len > 32)
		return -EINVAL;

	mask4->sin_family = AF_INET;
	mask4->sin_addr.s_addr = parse_filter_u32_mask(len);

	return 0;
}

static int parse_filter_prefixlen_to_mask_v6(struct sockaddr_storage *mask,
					     unsigned long len)
{
	struct sockaddr_in6 *mask6 = (struct sockaddr_in6 *)mask;
	int i;

	if (len > 128)
		return -EINVAL;

	mask6->sin6_family = AF_INET6;

	for (i = 0; len > 32; i++, len -= 32)
		mask6->sin6_addr.s6_addr32[i] = ~0;

	mask6->sin6_addr.s6_addr32[i] = parse_filter_u32_mask(len);

	return 0;
}

static int parse_filter_prefixlen_to_mask(struct sockaddr_storage *group,
					  const char *prefixlen_str,
					  struct sockaddr_storage *mask)
{
	unsigned long ret;
	char *endptr;

	errno = 0;

	ret = strtoul(prefixlen_str, &endptr, 10);
	if (errno == ERANGE || !endptr || *endptr != '\0')
		return -EINVAL;

	if (group->ss_family ==	AF_INET)
		return parse_filter_prefixlen_to_mask_v4(mask, ret);
	else
		return parse_filter_prefixlen_to_mask_v6(mask, ret);
}

static int parse_filter_addr(const char *addr,
			     struct sockaddr_storage *group,
			     struct sockaddr_storage *mask)
{
	char buffer[2 * INET6_ADDRSTRLEN + strlen("/") + 1];
	char *group_str = buffer, *mask_str = buffer;
	char *delim;
	int ret;

	strncpy(buffer, addr, sizeof(buffer));
	memset(group, 0, sizeof(*group));
	memset(mask, 0, sizeof(*mask));


	delim = strchr(buffer, '/');
	if (delim) {
		*delim = '\0';
		mask_str = delim + 1;
	}

	ret = parse_inet_pton(group_str, group);
	if (ret < 0)
		return ret;

	/* 1st case: no mask specified, set all-ones mask */
	if (!delim) {
		parse_filter_prefixfull_to_mask(ret, mask);
		goto out;
	}

	/* 2nd case: mask specified as length */
	ret = parse_filter_prefixlen_to_mask(group, mask_str, mask);
	if (!ret)
		goto out;

	/* 3rd case: mask specified as address */
	ret = parse_inet_pton(mask_str, mask);
	if (ret >= 0 && group->ss_family == mask->ss_family)
		goto out;

	return -EINVAL;
out:
	return 0;
}

static int get_args_final(struct bridge *br, struct list_head *ports, int argc, char *argv[])
{
	struct sockaddr_storage group, mask;
	struct list_head *to;
	int opt, ret, mode;

	optind = 1;

//	while ((opt = getopt(argc, argv, "b:46i:e:p:I:E:fh")) != -1) {
	while ((opt = getopt(argc, argv, "46b:i:e:p:I:E:h")) != -1) {
		switch (opt) {
		case '4':
		case '6':
		case 'b':
			/* already parsed previously */
			break;
		case 'i':
			to = &br->included_ports_list;
			ret = migrate_port_to_list(ports, to, optarg);
			if (ret < 0)
				return ret;
			break;
		case 'e':
			to = &br->excluded_ports_list;
			ret = migrate_port_to_list(ports, to, optarg);
			if (ret < 0)
				return ret;
			break;
		case 'p':
			/* TODO: br0 as proxied port currently unsupported/buggy,
			 * might need adjusted tc rules to work?
			 */
			if (!strcmp(optarg, br->name)) {
				fprintf(stderr, "Error: bridge device as proxied port currently unsupported\n");
				return -EINVAL;
			}

			to = &br->proxied_ports_list;
			ret = migrate_port_to_list(ports, to, optarg);
			if (ret < 0)
				return ret;
			break;
		case 'I':
		case 'E':
			mode = opt == 'I' ? MCAST_INCLUDE : MCAST_EXCLUDE;

			ret = parse_filter_addr(optarg, &group, &mask);
			if (ret < 0)
				return ret;

			ret = listener_filter_add_group(br, &group, &mask,
							mode);
			if (ret < 0)
				return ret;
			break;
		default:
			fprintf(stderr, "Error: Unknown option \"%c\"\n\n", opt);
			usage();
			return -EINVAL;
		case 'h':
			/* already parsed previously */
			break;
		}
	}

	if (ports == &br->proxied_ports_list) {
		/* TODO: br0 as proxied port currently unsupported/buggy,
		 * might need adjusted tc rules to work?
		 */
		to = &br->included_ports_list;
		ret = migrate_port_to_list(ports, to, br->name);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int parse_args(struct bridge *br, int argc, char *argv[])
{
	int have_incl_ports, have_excl_ports, have_prox_ports;
	struct list_head *ports;
	int ret;

	ret = parse_bridge_arg(br, argc, argv, &have_incl_ports, &have_excl_ports, &have_prox_ports);
	if (ret < 0)
		return ret;

	/* default bridge port type: */
	if (have_incl_ports)
		ports = &br->excluded_ports_list;
	else if (have_prox_ports)
		ports = &br->included_ports_list;
	else
		ports = &br->proxied_ports_list;

	ret = get_bridge_mld_version(br);
	if (ret < 1) {
		return -EINVAL;
	} else if (ret > 1) {
		fprintf(stderr, "Error: MLD version %i not yet supported\n", ret);
		return -EINVAL;
	}

	ret = get_bridge_ports(br, ports);
	if (ret < 0)
		return ret;

	ret = get_args_final(br, ports, argc, argv);
	if (ret < 0)
		return ret;

	return 0;
}

static void print_port_config(struct bridge *br)
{
	struct brport *port;

	printf("Port configuration for %s:\n", br->name);
	printf("* included:\n");
	list_for_each_entry(port, &br->included_ports_list, node) {
		printf("\t%s\n", port->name);
	}
	printf("* excluded:\n");
	list_for_each_entry(port, &br->excluded_ports_list, node) {
		printf("\t%s\n", port->name);
	}
	printf("* proxied:\n");
	list_for_each_entry(port, &br->proxied_ports_list, node) {
		printf("\t%s\n", port->name);
	}
}

static int system_format(const char *format, ...)
{
	char cmd[256];
	va_list aptr;
	int ret;

	va_start(aptr, format);
	ret = vsnprintf(cmd, sizeof(cmd), format, aptr);
	va_end(aptr);

	if (ret < 0)
		return ret;

//	printf("cmd: %s\n", cmd);
	return system(cmd);
}

static int setup_proxy_port_iface(struct bridge *br, struct brport *port)
{
	static short i = 0;

	int ret;

	while (i >= 0) {
		ret = system_format("ip link add dev brmldp%hu type dummy", i);
		/* created successfully */
		if (ret == 0)
			break;

		/* unexpected error */
		if (ret != 1)
			return -ENOEXEC;

		/* ret == 1: interface brmldp$i already exists, try next one */
		i++;
	}

	if (i < 0)
		return -ENOMEM;

	ret = snprintf(port->prname, sizeof(port->prname), "brmldp%hu", i);
	if (ret < 0)
		return -EINVAL;

	port->prifindex = if_nametoindex(port->prname);
	if (!port->prifindex)
		return -ENOENT;

	ret = system_format("ip link set address $(cat /sys/class/net/%s/address) arp on up dev brmldp%hu", br->name, i);
	if (ret != 0)
		return -ENOEXEC;

	i++;
	return 0;
}

/**
 * setup_proxy_port_rx() - copy MLD report on proxied port into dummy iface
 * @br: the bridge for which MLD proxying is applied on
 * @port: the proxied port which will respond with proxied/bundled MLD report
 *
 * Enable reception of a copy of MLD reports on a proxied port via tc into the
 * according dummy interface.
 *
 * Note: Needs to be copied, not redirected, so that the bridge can still learn
 * these listeners. So that another proxied port could adopt them from this
 * proxied port. Final filtering needs to be done after bridge forwarding,
 * on the outgoing port. Also see setup_proxy_port_tx().
 *
 * Return: Zero on success, -ENOEXEC otherwise.
 */
static int setup_proxy_port_rx(struct bridge *br, struct brport *port)
{
	int ret = 0;

	ret |= system_format("tc qdisc add dev %s handle ffff: ingress", port->name);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 handle 1: u32 divisor 1", port->name);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 u32 ht 1: match u8 0 0x00 action mirred ingress mirror dev %s", port->name, port->prname);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 handle 2: u32 divisor 1", port->name);
	ret |= system_format("tc filter add dev %s parent ffff: handle 2::131 protocol ipv6 prio 4223 u32 ht 2: match u8 131 0xff at 48 link 1:", port->name);
	ret |= system_format("tc filter add dev %s parent ffff: handle 2::132 protocol ipv6 prio 4223 u32 ht 2: match u8 132 0xff at 48 link 1:", port->name);
	ret |= system_format("tc filter add dev %s parent ffff: handle 2::143 protocol ipv6 prio 4223 u32 ht 2: match u8 143 0xff at 48 link 1:", port->name);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 u32 match ip6 protocol 0 0xff match u32 0x3a000502 0xffffffff at 40 match u32 0x00000000 0xffff0000 at 44 link 2:", port->name);

	if (ret)
		return -ENOEXEC;

	return 0;
}

/**
 * setup_proxy_port_rx_query() - copy MLD query on proxied port into dummy iface
 * @br: the bridge for which MLD proxying is applied on
 * @port: the proxied port which will respond with proxied/bundled MLD report
 *
 * Enable reception of a copy of MLD queries on a proxied port via tc into the
 * according dummy interface.
 *
 * Should only be instantiated if there is going to be an MLD listener on the
 * dummy interface. To avoid unnecessary MLD reports, with the only entry
 * being for the solicited-node multicast address for the link-local address
 * of the dummy inteface itself.
 *
 * Return: Zero on success, -ENOEXEC otherwise.
 */
int setup_proxy_port_rx_query(struct bridge *br, struct brport *port)
{
	int ret = 0;

	ret |= system_format("tc filter add dev %s parent ffff: handle 2::130 protocol ipv6 prio 4223 u32 ht 2: match u8 130 0xff at 48 link 1:", port->name);

	if (ret)
		return -ENOEXEC;

	return 0;
}

/**
 * setup_proxy_port_tx() - only allow MLD reports from dummy ifaces
 * @br: the bridge for which MLD proxying is applied on
 * @port: the proxied port which will respond with proxied/bundled MLD
 *
 * Only allow transmissions of MLD reports on the given proxied port for packets
 * that were redirected from the according dummy interface.
 *
 * This is ensured by checking the presence of a specific firewall mark,
 * PD_FWMARK. If present, then the packet is allowed, otherwise dropped.
 * Also see setup_proxy_port_rx() and setup_proxy_port_tx_redir().
 *
 * TODO: also do this for excluded ports? or fully exclude them?
 *
 * Return: Zero on success, -ENOEXEC otherwise.
 */
static int setup_proxy_port_tx(struct bridge *br, struct brport *port)
{
	int ret = 0;

	ret |= system_format("tc qdisc add dev %s handle fffe: root fq_codel", port->name);
	ret |= system_format("tc filter add dev %s parent fffe: protocol ipv6 prio 4223 handle 1: u32 divisor 1", port->name);
	ret |= system_format("tc filter add dev %s parent fffe: protocol ipv6 prio 4223 u32 ht 1: match u8 0 0x00 action drop", port->name);
	ret |= system_format("tc filter add dev %s parent fffe: protocol ipv6 prio 4223 handle 2: u32 divisor 1", port->name);
	ret |= system_format("tc filter add dev %s parent fffe: protocol ipv6 prio 4223 u32 ht 2: match u8 131 0xff at 48 link 1:", port->name);
	ret |= system_format("tc filter add dev %s parent fffe: protocol ipv6 prio 4223 u32 ht 2: match u8 132 0xff at 48 link 1:", port->name);
	ret |= system_format("tc filter add dev %s parent fffe: protocol ipv6 prio 4223 u32 ht 2: match u8 143 0xff at 48 link 1:", port->name);
	ret |= system_format("tc filter add dev %s parent fffe: protocol ipv6 prio 4222 handle %s/%s fw classid 1:1", port->name, PD_FWMARK, PD_FWMARK);
	ret |= system_format("tc filter add dev %s parent fffe: protocol ipv6 prio 4223 u32 match ip6 protocol 0 0xff match u32 0x3a000502 0xffffffff at 40 match u32 0x00000000 0xffff0000 at 44 link 2:", port->name);
	ret |= system_format("tc filter add dev %s parent fffe: protocol ipv6 prio 4224 matchall classid 1:1", port->name);

	if (ret)
		return -ENOEXEC;

	return 0;
}

/**
 * setup_proxy_ports_wait() - wait for unnecessary unsolicited MLD reports
 *
 * Wait for unnecessary unsolicited MLD reports generated by the dummy
 * interface's own address listeners to pass before installing
 * dummy->proxy-port redirections. To keep the proxied port side
 * quiet of MLD reports if no proxied listeners are present.
 *
 * The wait should at least be "Unsolicited Report Interval", which defaults
 * to 1 second according RFC3810. Choosing 5 seconds here to be on the safe
 * side.
 */
static void setup_proxy_ports_wait(void)
{
	sleep(5);
}

/**
 * setup_proxy_port_tx_redir() - redirect MLD from dummy iface to its proxied port
 * @br: the bridge for which MLD proxying is applied on
 * @port: the proxied port which will respond with proxied/bundled MLD
 *
 * Redirect any MLD packet transmitted by the dummy interface which is
 * assigned to the given proxied port to this proxied port.
 *
 * Note: Contrary to the RX equivalent, can simply be redirected. There is no
 * need/use for receiving a copy on the dummy interface itself right now.
 * (Or maybe do copy, "redirect"->"mirror", for easier monitoring of the full
 * MLD exchange on the dummy interface with tcpdump etc.?)
 *
 * This also adds a firewall mark to the packet, PD_FWMARK, so that
 * setup_proxy_port_tx() will not filter this proxied MLD packet.
 *
 * Return: Zero on success, -ENOEXEC otherwise.
 */
static int setup_proxy_port_tx_redir(struct bridge *br, struct brport *port)
{
	int ret = 0;

	ret |= system_format("tc qdisc add dev %s handle ffff: root fq_codel", port->prname);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 handle 1: u32 divisor 1", port->prname);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 u32 ht 1: match u8 0 0x00 action skbedit mark %s pipe action mirred egress redirect dev %s", port->prname, PD_FWMARK, port->name);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 handle 2: u32 divisor 1", port->prname);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 u32 ht 2: match u8 130 0xff at 48 link 1:", port->prname);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 u32 ht 2: match u8 131 0xff at 48 link 1:", port->prname);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 u32 ht 2: match u8 132 0xff at 48 link 1:", port->prname);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 u32 ht 2: match u8 143 0xff at 48 link 1:", port->prname);
	ret |= system_format("tc filter add dev %s parent ffff: protocol ipv6 prio 4223 u32 match ip6 protocol 0 0xff match u32 0x3a000502 0xffffffff at 40 match u32 0x00000000 0xffff0000 at 44 link 2:", port->prname);

	if (ret)
		return -ENOEXEC;

	return 0;
}

/* TODO: replace with netlink maybe? */
static int setup_proxy_ports(struct bridge *br)
{
	struct brport *port;
	int ret;

	list_for_each_entry(port, &br->proxied_ports_list, node) {
		ret = setup_proxy_port_iface(br, port);
		if (ret < 0)
			return ret;

		ret = setup_proxy_port_rx(br, port);
		if (ret < 0)
			return ret;

		ret = setup_proxy_port_tx(br, port);
		if (ret < 0)
			return ret;
	}

	setup_proxy_ports_wait();

	list_for_each_entry(port, &br->proxied_ports_list, node) {
		ret = setup_proxy_port_tx_redir(br, port);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static void teardown_proxy_port_tx_redir(struct brport *port)
{
	system_format("tc filter delete dev %s parent ffff: protocol ipv6 prio 4223 u32", port->prname);
	system_format("tc qdisc del dev %s handle ffff: root fq_codel", port->prname);
}

static void teardown_proxy_port_tx(struct brport *port)
{
	system_format("tc filter delete dev %s parent fffe: protocol ipv6 prio 4222 fw", port->name);
	system_format("tc filter delete dev %s parent fffe: protocol ipv6 prio 4223 u32", port->name);
	system_format("tc qdisc del dev %s handle fffe: root fq_codel", port->name);
}

static void teardown_proxy_port_rx(struct brport *port)
{
	system_format("tc filter delete dev %s parent ffff: protocol ipv6 prio 4223 u32", port->name);
	system_format("tc qdisc del dev %s handle ffff: ingress", port->name);
}

void teardown_proxy_port_rx_query(struct brport *port)
{
	system_format("tc filter delete dev %s parent ffff: handle 2::130 protocol ipv6 prio 4223 u32", port->name);
}

static void teardown_proxy_port_iface(struct brport *port)
{
	system_format("ip link del %s", port->prname);
}

static void teardown_proxy_port(struct brport *port)
{
	if (!port->prname[0])
		return;

	listener_flush(port);
	teardown_proxy_port_tx_redir(port);
	teardown_proxy_port_tx(port);
	teardown_proxy_port_rx(port);
	teardown_proxy_port_iface(port);
}

static void teardown_proxy_ports(struct bridge *br)
{
	struct brport *port;

	list_for_each_entry(port, &br->proxied_ports_list, node) {
		teardown_proxy_port(port);
	}
}

int main(int argc, char *argv[])
{
	struct bridge br;
	int ret = 0;

	setup_signal_handler();

	ret = parse_args(&br, argc, argv);
	if (ret < 0)
		goto err;

	print_port_config(&br);

	ret = setup_proxy_ports(&br);
	if (ret < 0)
		goto out;

	bridge_monitor_mdb(listener_update, listener_reduce_lifes, listener_flush_dead, listener_dump, &br);

out:
	teardown_proxy_ports(&br);
err:
	free_ports(&br.included_ports_list);
	free_ports(&br.excluded_ports_list);
	free_ports(&br.proxied_ports_list);

	return ret ? 1 : 0;
}
