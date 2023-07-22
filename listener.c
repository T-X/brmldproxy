/* SPDX-FileCopyrightText: 2023 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <arpa/inet.h> // inet_pton()
#include <errno.h>
#include <linux/types.h> // __u16
#include <netinet/in.h> // in_addr
#include <stdio.h>
#include <stdlib.h> // malloc
#include <string.h> // memset
#include <unistd.h>
#include <linux/rtnetlink.h> // RTM_NEWMDB, RTM_DELMDB

#include "brmldproxy.h"

struct listener {
	int sd;		// sd on the proxy port interface
	int ifindex;	// the port where the listener originally came from
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	} group;
	struct list_head node;
};

struct filter {
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	} group;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	} mask;
	int mode;
	struct list_head node;
};

static int listener_filter_check_v4(struct bridge *br,
				    const struct in_addr *group)
{
	int ret = MCAST_INCLUDE;
	/* TODO */
	return  ret;
}

static struct in6_addr listener_and_in6_addr(const struct in6_addr *in1,
					     const struct in6_addr *in2)
{
	struct in6_addr out = { .s6_addr32[0] = in1->s6_addr32[0] & in2->s6_addr32[0],
				.s6_addr32[1] = in1->s6_addr32[1] & in2->s6_addr32[1],
				.s6_addr32[2] = in1->s6_addr32[2] & in2->s6_addr32[2],
				.s6_addr32[3] = in1->s6_addr32[3] & in2->s6_addr32[3] };

	return out;
}

static int listener_filter_check_entry_v6(const struct in6_addr *group, struct filter *filter)
{
	struct in6_addr masked_filter, masked_group;

	masked_filter = listener_and_in6_addr(&filter->group.ip6, &filter->mask.ip6);
	masked_group = listener_and_in6_addr(group, &filter->mask.ip6);

	if (!memcmp(&masked_filter, &masked_group, sizeof(masked_filter)))
		return filter->mode;
	else
		return !filter->mode;
}

static int listener_filter_check_v6(struct bridge *br,
				    const struct in6_addr *group)
{
	struct filter *filter;
	int ret = MCAST_INCLUDE;

	if (list_empty(&br->group_filter_list_v6))
		return ret;

	filter = list_first_entry(&br->group_filter_list_v6, struct filter, node);
	if (filter->mode == MCAST_INCLUDE)
		ret = MCAST_EXCLUDE;

	list_for_each_entry(filter, &br->group_filter_list_v6, node) {
		if (ret == filter->mode)
			continue;

		ret = listener_filter_check_entry_v6(group, filter);
	}

	return ret;
}

static int listener_filter_check(struct bridge *br, int addr_family,
				 const void *group)
{
	switch (addr_family) {
	case AF_INET:
		return listener_filter_check_v4(br, (struct in_addr *)group);
	case AF_INET6:
		return listener_filter_check_v6(br, (struct in6_addr *)group);
	}

	return MCAST_INCLUDE;
}

static void listener_add_v4(struct bridge *br, int ifindex, const struct in_addr *group)
{
}

static int listener_create_socket_v6(int prifindex, const struct in6_addr *group)
{
	int sd;					// Socket descriptor
	struct sockaddr_in6 multicastAddr;	// Multicast addresse structure
	struct ipv6_mreq multicastRequest;	// Multicast address join structure

	// Construct bind structure
	memset(&multicastAddr, 0, sizeof(multicastAddr));	// Zero out structure
	multicastAddr.sin6_family = AF_INET6;		// Internet address family
	// TODO: change from :: to ::1? ->
	multicastAddr.sin6_addr = in6addr_any;		// Any incoming interface
	multicastAddr.sin6_port = htons(0);		// Multicast port - let the OS decide

	// Create a best-effort datagram socket using UDP
	if((sd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket() failed");
		return -1;
	}

	// TODO: use setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, ...)?

	// Bind to the multicast port
	if(bind(sd, (struct sockaddr *) &multicastAddr, sizeof(multicastAddr)) < 0) {
		perror("bind() failed");
		return -1;
	}

	// Specify the multicast group
	multicastRequest.ipv6mr_multiaddr = *group;

	// Accept multicast from specified interface
	//multicastRequest.ipv6mr_interface = if_nametoindex(interface);
	multicastRequest.ipv6mr_interface = prifindex;

	// Join the multicast address
	if(setsockopt(sd, IPPROTO_IPV6, IPV6_JOIN_GROUP, (void *) &multicastRequest,
		sizeof(multicastRequest)) < 0) {
		perror("setsockopt() failed");
		return -1;
	}

	return sd;
}

static int listener_add_socket_v6(struct brport *port, int ifindex, int sd, const struct in6_addr *group) {
	struct listener *listener;

	listener = malloc(sizeof(*listener));
	if (!listener)
		return -ENOMEM;

	memset(listener, 0, sizeof(*listener));

	listener->sd = sd;
	listener->ifindex = ifindex;
	listener->group.ip6 = *group;
	INIT_LIST_HEAD(&listener->node);

	list_add_tail(&listener->node, &port->listener_list_v6);

	return 0;
}

static void listener_add_v6(struct bridge *br, int ifindex, const struct in6_addr *group)
{
	struct brport *port;
	int sd, ret;

	printf("~~~ %s:%i: start\n", __func__, __LINE__);
	list_for_each_entry(port, &br->proxied_ports_list, node) {
		if (port->ifindex == ifindex)
			continue;

		/* TODO: add assertion that listener does not exist yet */

		if (list_empty(&port->listener_list_v6))
			setup_proxy_port_tx_redir(br, port);

		sd = listener_create_socket_v6(port->prifindex, group);
		if (sd < 0) {
			fprintf(stderr, "Error: Could not create IPv6 multicast listening socket\n");
			/* TODO: return error */
			return;
		}

		ret = listener_add_socket_v6(port, ifindex, sd, group);
		if (ret < 0) {
			fprintf(stderr, "Error: Could not add IPv6 multicast listening socket\n");
			close(sd);
			/* TODO: return error */
			return;
		}
		printf("~~~ %s:%i: listener added to port %i (%i) successfully: sd: %i\n", __func__, __LINE__, port->ifindex, port->prifindex, sd);
	}
	printf("~~~ %s:%i: end\n", __func__, __LINE__);
}

static void listener_add(struct bridge *br, int port_ifindex, int addr_family, const void *group)
{
	switch (addr_family) {
	case AF_INET:
		listener_add_v4(br, port_ifindex, (const struct in_addr *)group);
		break;
	case AF_INET6:
		listener_add_v6(br, port_ifindex, (const struct in6_addr *)group);
		break;
	default:
		return;
	}
}

static void listener_del_v4(struct bridge *br, int ifindex, const struct in_addr *group)
{
}

static void listener_del_v6(struct bridge *br, int ifindex, const struct in6_addr *group)
{
	struct listener *listener;
	struct brport *port;

	list_for_each_entry(port, &br->proxied_ports_list, node) {
		if (port->ifindex == ifindex)
			continue;
	
		list_for_each_entry(listener, &port->listener_list_v6, node) {
			if (memcmp(group, &listener->group.ip6, sizeof(*group)))
				continue;

			list_del(&listener->node);
			close(listener->sd);
			break;
		}

		if (list_empty(&port->listener_list_v6))
			teardown_proxy_port_tx_redir(port);
	}
}

static void listener_del(struct bridge *br, int port_ifindex, int addr_family, const void *group)
{
	switch (addr_family) {
	case AF_INET:
		listener_del_v4(br, port_ifindex, (const struct in_addr *)group);
		break;
	case AF_INET6:
		listener_del_v6(br, port_ifindex, (const struct in6_addr *)group);
		break;
	default:
		return;
	}
}

void listener_update(struct bridge *br, int br_ifindex, int port_ifindex, __u16 nlmsg_type, int addr_family, const void *group)
{
	struct brport *port;
	printf("~~~ %s:%i: start\n", __func__, __LINE__);

	if (br->ifindex != br_ifindex)
		return;

	list_for_each_entry(port, &br->excluded_ports_list, node) {
		if (port->ifindex == port_ifindex)
			return;
	}

	if (listener_filter_check(br, addr_family, group) == MCAST_EXCLUDE)
		return;

	switch (nlmsg_type) {
	case RTM_NEWMDB:
		listener_add(br, port_ifindex, addr_family, group);
		break;
	case RTM_DELMDB:
		listener_del(br, port_ifindex, addr_family, group);
		break;
	}
}

void listener_flush(struct brport *port)
{
	struct listener *listener;

	list_for_each_entry(listener, &port->listener_list_v4, node) {
		list_del(&listener->node);
		close(listener->sd);
	}

	list_for_each_entry(listener, &port->listener_list_v6, node) {
		list_del(&listener->node);
		close(listener->sd);
	}
}

int listener_filter_add_group(struct bridge *br,
			      struct sockaddr_storage *group,
			      struct sockaddr_storage *mask,
			      int mode)
{
	struct filter *filter;

	filter = malloc(sizeof(*filter));
	if (!filter)
		return -ENOMEM;

	filter->mode = mode;
	INIT_LIST_HEAD(&filter->node);

	switch (group->ss_family) {
	case AF_INET:
		filter->group.ip4 = ((struct sockaddr_in *)group)->sin_addr;
		filter->mask.ip4 = ((struct sockaddr_in *)mask)->sin_addr;
		list_add_tail(&filter->node, &br->group_filter_list_v4);
		return 0;
	case AF_INET6:
		filter->group.ip6 = ((struct sockaddr_in6 *)group)->sin6_addr;
		filter->mask.ip6 = ((struct sockaddr_in6 *)mask)->sin6_addr;
		list_add_tail(&filter->node, &br->group_filter_list_v6);
		return 0;
	default:
		free(filter);
	}

	return -EINVAL;
}
