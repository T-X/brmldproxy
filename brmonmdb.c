/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * brmonitor.c		"bridge monitor"
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Stephen Hemminger <shemminger@vyatta.com>
 *
 * Originally from the iproute2's bridge tool, adopted for brmldproxy.
 */

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_bridge.h>

#include <arpa/inet.h> // socklen_t
#include <string.h> // memset()
#include <stdio.h>
#include <stdlib.h> // exit()
#include <errno.h>
#include <time.h> // time()
#include <unistd.h> // close()

#include "brmldproxy.h"

static int running = 1;
static int status_dump = 0;

#define BRMMDB_CHECK_TIME 3
#define BRMMDB_CHECK_TIMEOUT 30

/*#include "libnetlink.h"
//#include "utils.h"

//#ifndef NDA_RTA
//#define NDA_RTA(r) \
//	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
//#endif*/

#define MDB_RTA(r) \
		((struct rtattr *)(((char *)(r)) + RTA_ALIGN(sizeof(struct br_mdb_entry))))

#define MDB_RTR_RTA(r) \
		((struct rtattr *)(((char *)(r)) + RTA_ALIGN(sizeof(__u32))))

#ifndef MDBA_RTA
#define MDBA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct br_port_msg))))
#endif

struct rtnl_ctrl_data {
	int	nsid;
};


struct rtnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;
	int			proto;
//	FILE		       *dump_fp;
#define RTNL_HANDLE_F_LISTEN_ALL_NSID		0x01
#define RTNL_HANDLE_F_SUPPRESS_NLERR		0x02
#define RTNL_HANDLE_F_STRICT_CHK		0x04
	int			flags;

	struct bridge		*bridge;
	int			(*update_cb)(struct bridge *br,
					     int port_ifindex,
					     __u16 nlmsg_type,
					     int addr_family,
					     const void *group);
	void			(*pre_dump_cb)(struct bridge *br);
	int			(*post_dump_cb)(struct bridge *br);
	void			(*status_dump_cb)(struct bridge *br);
};

static void bridge_monitor_mdb_check(void);


typedef int (*rtnl_listen_filter_t)(struct rtnl_ctrl_data *,
				    struct nlmsghdr *n, void *);



struct rtnl_handle rth_mon = { .fd = -1 };
struct rtnl_handle rth_dump = { .fd = -1 };

int rcvbuf = 1024 * 1024;

static inline __u32 nl_mgrp(__u32 group)
{
	if (group > 31 ) {
		fprintf(stderr, "Use setsockopt for this group %d\n", group);
		exit(-1);
	}
	return group ? (1 << (group - 1)) : 0;
}

int rtnl_open_byproto(struct rtnl_handle *rth, unsigned int subscriptions,
		      int protocol)
{
	socklen_t addr_len;
	int sndbuf = 32768;
	int one = 1;

	memset(rth, 0, sizeof(*rth));

	rth->proto = protocol;
	rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (rth->fd < 0) {
		perror("Cannot open netlink socket");
		return -1;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF,
		       &sndbuf, sizeof(sndbuf)) < 0) {
		perror("SO_SNDBUF");
		return -1;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF,
		       &rcvbuf, sizeof(rcvbuf)) < 0) {
		perror("SO_RCVBUF");
		return -1;
	}

	/* Older kernels may no support extended ACK reporting */
	setsockopt(rth->fd, SOL_NETLINK, NETLINK_EXT_ACK,
		   &one, sizeof(one));

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr *)&rth->local,
		 sizeof(rth->local)) < 0) {
		perror("Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr *)&rth->local,
			&addr_len) < 0) {
		perror("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		fprintf(stderr, "Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		fprintf(stderr, "Wrong address family %d\n",
			rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);
	return 0;
}

int rtnl_open(struct rtnl_handle *rth, unsigned int subscriptions)
{
	return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}

/* Older kernels may not support strict dump and filtering */
void rtnl_set_strict_dump(struct rtnl_handle *rth)
{
	int one = 1;

	if (setsockopt(rth->fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
		       &one, sizeof(one)) < 0)
		return;

	rth->flags |= RTNL_HANDLE_F_STRICT_CHK;
}

int rtnl_listen(struct rtnl_handle *rtnl,
		rtnl_listen_filter_t handler,
		void *jarg)
{
	int status;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[16384];
	char   cmsgbuf[BUFSIZ];

	iov.iov_base = buf;
	while (running) {
		struct rtnl_ctrl_data ctrl;
		struct cmsghdr *cmsg;

		if (rtnl->flags & RTNL_HANDLE_F_LISTEN_ALL_NSID) {
			msg.msg_control = &cmsgbuf;
			msg.msg_controllen = sizeof(cmsgbuf);
		}

		bridge_monitor_mdb_check();

		iov.iov_len = sizeof(buf);
		status = recvmsg(rtnl->fd, &msg, 0);

		if (status_dump && rtnl->status_dump_cb) {
			rtnl->status_dump_cb(rtnl->bridge);
			status_dump = 0;
		}

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			fprintf(stderr, "netlink receive error %s (%d)\n",
				strerror(errno), errno);
			if (errno == ENOBUFS)
				continue;
			return -1;
		}
		if (status == 0) {
			fprintf(stderr, "EOF on netlink\n");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			fprintf(stderr,
				"Sender address length == %d\n",
				msg.msg_namelen);
			exit(1);
		}

		if (rtnl->flags & RTNL_HANDLE_F_LISTEN_ALL_NSID) {
			memset(&ctrl, 0, sizeof(ctrl));
			ctrl.nsid = -1;
			for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
			     cmsg = CMSG_NXTHDR(&msg, cmsg))
				if (cmsg->cmsg_level == SOL_NETLINK &&
				    cmsg->cmsg_type == NETLINK_LISTEN_ALL_NSID &&
				    cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
					int *data = (int *)CMSG_DATA(cmsg);

					ctrl.nsid = *data;
				}
		}

		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					fprintf(stderr, "Truncated message\n");
					return -1;
				}
				fprintf(stderr,
					"!!!malformed message: len=%d\n",
					len);
				exit(1);
			}

			err = handler(&ctrl, h, jarg);
			if (err < 0)
				return err;

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}
		if (status) {
			fprintf(stderr, "!!!Remnant of size %d\n", status);
			exit(1);
		}
	}

	return 0;
}

void rtnl_close(struct rtnl_handle *rth)
{
	if (rth->fd >= 0) {
		close(rth->fd);
		rth->fd = -1;
	}
}

int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n",
			len, rta->rta_len);
	return 0;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	return parse_rtattr_flags(tb, max, rta, len, 0);
}

static int __parse_mdb_nlmsg(struct nlmsghdr *n, struct rtattr **tb)
{
	struct br_port_msg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;

	if (n->nlmsg_type != RTM_GETMDB &&
	    n->nlmsg_type != RTM_NEWMDB &&
	    n->nlmsg_type != RTM_DELMDB) {
		fprintf(stderr,
			"Not RTM_GETMDB, RTM_NEWMDB or RTM_DELMDB: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);

		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

//	if (filter_index && filter_index != r->ifindex)
//		return 0;

	parse_rtattr(tb, MDBA_MAX, MDBA_RTA(r), n->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	return 1;
}

const char *rt_addr_n2a_r(int af, int len,
			  const void *addr, char *buf, int buflen)
{
	switch (af) {
	case AF_INET:
	case AF_INET6:
		return inet_ntop(af, addr, buf, buflen);
//	case AF_MPLS:
//		return mpls_ntop(af, addr, buf, buflen);
//	case AF_PACKET:
//		return ll_addr_n2a(addr, len, ARPHRD_VOID, buf, buflen);
	case AF_BRIDGE:
	{
		printf("~~~ %s:%i: AF_BRIDGE\n", __func__, __LINE__);
		const union {
			struct sockaddr sa;
			struct sockaddr_in sin;
			struct sockaddr_in6 sin6;
		} *sa = addr;

		switch (sa->sa.sa_family) {
		case AF_INET:
			return inet_ntop(AF_INET, &sa->sin.sin_addr,
					 buf, buflen);
		case AF_INET6:
			return inet_ntop(AF_INET6, &sa->sin6.sin6_addr,
					 buf, buflen);
		}

		// fallthrough
	}
	default:
		return "???";
	}
}

static inline __u8 rta_getattr_u8(const struct rtattr *rta)
{
        return *(__u8 *)RTA_DATA(rta);
}

static void print_mdb_entry(struct rtnl_handle *rth, int ifindex, const struct br_mdb_entry *e,
			    struct nlmsghdr *n, struct rtattr **tb)
{
//	const void *grp, *src;
	const void *grp;
	const char *addr;
//	SPRINT_BUF(abuf);
	char abuf[64];
	__u8 mode;
//	const char *dev;
	int af;

//	if (filter_vlan && e->vid != filter_vlan)
//		return;

	if (!e->addr.proto) {
		af = AF_PACKET;
		grp = &e->addr.u.mac_addr;
	} else if (e->addr.proto == htons(ETH_P_IP)) {
		af = AF_INET;
		grp = &e->addr.u.ip4;
	} else {
		af = AF_INET6;
		grp = &e->addr.u.ip6;
	}
//	dev = ll_index_to_name(ifindex);

/*	open_json_object(NULL);

	print_int(PRINT_JSON, "index", NULL, ifindex);
	print_color_string(PRINT_ANY, COLOR_IFNAME, "dev", "dev %s", dev);
	print_string(PRINT_ANY, "port", " port %s",
		     ll_index_to_name(e->ifindex));
*/
	/* The ETH_ALEN argument is ignored for all cases but AF_PACKET */
	addr = rt_addr_n2a_r(af, ETH_ALEN, grp, abuf, sizeof(abuf));
	if (!addr)
		return;

/*	if (tb && tb[MDBA_MDB_EATTR_SOURCE]) {
		src = (const void *)RTA_DATA(tb[MDBA_MDB_EATTR_SOURCE]);
		inet_ntop(af, src, abuf, sizeof(abuf));
	}*/

	if (tb && tb[MDBA_MDB_EATTR_GROUP_MODE]) {
		mode = rta_getattr_u8(tb[MDBA_MDB_EATTR_GROUP_MODE]);

		/* adding a MDB entry in include mode with no sources is a
		 * no-op (or delete).
		 * The bridge sends this when adding a new ASM listener
		 * to the MDB, before sending a second event here to
		 * switch it to exclude-mode.
		 * Ignore it to avoid duplicate additions.
		 */
		if (n->nlmsg_type == RTM_NEWMDB &&
		    mode == MCAST_INCLUDE &&
		    !tb[MDBA_MDB_EATTR_SOURCE] &&
		    !tb[MDBA_MDB_EATTR_SRC_LIST])
			return;
	}


	if (rth == &rth_dump && n->nlmsg_type != RTM_GETMDB) {
		//fprintf(stderr, "Warning: MDB dump with unexpected type, ignoring\n");
		fprintf(stderr, "Warning: MDB dump with unexpected type (%hu, ignoring\n", n->nlmsg_type);
		return;
	}

	if (rth->bridge->ifindex != ifindex)
		return;

	rth->update_cb(rth->bridge, e->ifindex, n->nlmsg_type, af, grp);

/*	print_color_string(PRINT_ANY, ifa_family_color(af),
			    "grp", " grp %s", addr);

	if (tb && tb[MDBA_MDB_EATTR_SOURCE]) {
		src = (const void *)RTA_DATA(tb[MDBA_MDB_EATTR_SOURCE]);
		print_color_string(PRINT_ANY, ifa_family_color(af),
				   "src", " src %s",
				   inet_ntop(af, src, abuf, sizeof(abuf)));
	}
	print_string(PRINT_ANY, "state", " %s",
			   (e->state & MDB_PERMANENT) ? "permanent" : "temp");
	if (show_details && tb) {
		if (tb[MDBA_MDB_EATTR_GROUP_MODE]) {
			__u8 mode = rta_getattr_u8(tb[MDBA_MDB_EATTR_GROUP_MODE]);

			print_string(PRINT_ANY, "filter_mode", " filter_mode %s",
				     mode == MCAST_INCLUDE ? "include" :
							     "exclude");
		}
		if (tb[MDBA_MDB_EATTR_SRC_LIST]) {
			struct rtattr *i, *attr = tb[MDBA_MDB_EATTR_SRC_LIST];
			const char *sep = " ";
			int rem;

			open_json_array(PRINT_ANY, is_json_context() ?
								"source_list" :
								" source_list");
			rem = RTA_PAYLOAD(attr);
			for (i = RTA_DATA(attr); RTA_OK(i, rem);
			     i = RTA_NEXT(i, rem)) {
				print_src_entry(i, af, sep);
				sep = ",";
			}
			close_json_array(PRINT_JSON, NULL);
		}
		if (tb[MDBA_MDB_EATTR_RTPROT]) {
			__u8 rtprot = rta_getattr_u8(tb[MDBA_MDB_EATTR_RTPROT]);
			SPRINT_BUF(rtb);

			print_string(PRINT_ANY, "protocol", " proto %s ",
				     rtnl_rtprot_n2a(rtprot, rtb, sizeof(rtb)));
		}
	}*/

/*	open_json_array(PRINT_JSON, "flags");
	if (e->flags & MDB_FLAGS_OFFLOAD)
		print_string(PRINT_ANY, NULL, " %s", "offload");
	if (e->flags & MDB_FLAGS_FAST_LEAVE)
		print_string(PRINT_ANY, NULL, " %s", "fast_leave");
	if (e->flags & MDB_FLAGS_STAR_EXCL)
		print_string(PRINT_ANY, NULL, " %s", "added_by_star_ex");
	if (e->flags & MDB_FLAGS_BLOCKED)
		print_string(PRINT_ANY, NULL, " %s", "blocked");
	close_json_array(PRINT_JSON, NULL);*/

/*	if (e->vid)
		print_uint(PRINT_ANY, "vid", " vid %u", e->vid);

	if (show_stats && tb && tb[MDBA_MDB_EATTR_TIMER]) {
		__u32 timer = rta_getattr_u32(tb[MDBA_MDB_EATTR_TIMER]);

		print_string(PRINT_ANY, "timer", " %s",
			     format_timer(timer, 1));
	}

	print_nl();
	close_json_object();*/
}

static void br_print_mdb_entry(struct rtnl_handle *rth, int ifindex, struct rtattr *attr,
			       struct nlmsghdr *n)
{
	struct rtattr *etb[MDBA_MDB_EATTR_MAX + 1];
	struct br_mdb_entry *e;
	struct rtattr *i;
	int rem;

	rem = RTA_PAYLOAD(attr);
	for (i = RTA_DATA(attr); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
		e = RTA_DATA(i);
		parse_rtattr_flags(etb, MDBA_MDB_EATTR_MAX, MDB_RTA(RTA_DATA(i)),
				   RTA_PAYLOAD(i) - RTA_ALIGN(sizeof(*e)),
				   NLA_F_NESTED);
		print_mdb_entry(rth, ifindex, e, n, etb);
	}
}

static void print_mdb_entries(struct rtnl_handle *rth, struct nlmsghdr *n,
			      int ifindex,  struct rtattr *mdb)
{
	int rem = RTA_PAYLOAD(mdb);
	struct rtattr *i;

	for (i = RTA_DATA(mdb); RTA_OK(i, rem); i = RTA_NEXT(i, rem))
		br_print_mdb_entry(rth, ifindex, i, n);
}

static int accept_msg(struct rtnl_ctrl_data *ctrl,
		      struct nlmsghdr *n, void *arg)
{
	struct br_port_msg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtnl_handle *rth = arg;
	int ret;
	struct rtattr *tb[NDA_MAX+1];

	printf("Got message\n");

//	printf("~~~ : &fp: %p\n", fp);

	switch (n->nlmsg_type) {
	case RTM_NEWMDB:
		printf("New MDB entry: ...\n");
		break;
	case RTM_DELMDB:
		printf("Deleted MDB entry: ...\n");
		break;
	default:
		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

//	if (r->ndm_family != AF_BRIDGE)
//		return 0;

//	if (filter_index && filter_index != r->ndm_ifindex)
//		return 0;

//	if (filter_state && !(r->ndm_state & filter_state))
//		return 0;

//	parse_rtattr(tb, NDA_MAX, NDA_RTA(r),
//		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	ret = __parse_mdb_nlmsg(n, tb);
	if (ret != 1)
		return ret;

	if (tb[MDBA_MDB])
		print_mdb_entries(rth, n, r->ifindex, tb[MDBA_MDB]);

//	if (tb[MDBA_ROUTER])
//		print_router_entries(fp, n, r->ifindex, tb[MDBA_ROUTER]);

//	if (tb[NDA_LLADDR]) {
//		const unsigned char *addr = RTA_DATA(tb[NDA_LLADDR]);
//		int alen = RTA_PAYLOAD(tb[NDA_LLADDR]);
//		char b1[strlen("00:11:22:33:44:55") + 1];
//		int i, l;
//
//		memset(b1, 0, sizeof(b1));
//
//		snprintf(b1, sizeof(b1), "%02x", addr[0]);
//		for (i = 1, l = 2; i < alen && l < sizeof(b1); i++, l += 3)
//			snprintf(b1 + l, sizeof(b1) - l, ":%02x", addr[i]);
//
//		printf("MAC: %s\n", b1);
//	}

	return 0;
}

int rtnl_mdbdump_req(struct rtnl_handle *rth, int family)
{
	struct {
		struct nlmsghdr nlh;
		struct br_port_msg bpm;
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct br_port_msg)),
		.nlh.nlmsg_type = RTM_GETMDB,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.bpm.family = family,
	};

	return send(rth->fd, &req, sizeof(req), 0);
}

static int print_mdbs(struct nlmsghdr *n, void *arg)
{
	struct br_port_msg *r = NLMSG_DATA(n);
	struct rtattr *tb[MDBA_MAX+1];
	struct rtnl_handle *rth = arg;
	int ret;

	ret = __parse_mdb_nlmsg(n, tb);
	if (ret != 1)
		return ret;

	if (tb[MDBA_MDB])
		print_mdb_entries(rth, n, r->ifindex, tb[MDBA_MDB]);

	return 0;
}

typedef int (*rtnl_filter_t)(struct nlmsghdr *n, void *);

typedef int (*rtnl_err_hndlr_t)(struct nlmsghdr *n, void *);

struct rtnl_dump_filter_arg {
	rtnl_filter_t filter;
	void *arg1;
	rtnl_err_hndlr_t errhndlr;
	void *arg2;
	__u16 nc_flags;
};

static int __rtnl_recvmsg(int fd, struct msghdr *msg, int flags)
{
	int len;

	do {
		len = recvmsg(fd, msg, flags);
	} while (len < 0 && (errno == EINTR || errno == EAGAIN));

	if (len < 0) {
		fprintf(stderr, "netlink receive error %s (%d)\n",
			strerror(errno), errno);
		return -errno;
	}

	if (len == 0) {
		fprintf(stderr, "EOF on netlink\n");
		return -ENODATA;
	}

	return len;
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
	struct iovec *iov = msg->msg_iov;
	char *buf;
	int len;

	iov->iov_base = NULL;
	iov->iov_len = 0;

	len = __rtnl_recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC);
	if (len < 0)
		return len;

	if (len < 32768)
		len = 32768;
	buf = malloc(len);
	if (!buf) {
		fprintf(stderr, "malloc error: not enough buffer\n");
		return -ENOMEM;
	}

	iov->iov_base = buf;
	iov->iov_len = len;

	len = __rtnl_recvmsg(fd, msg, 0);
	if (len < 0) {
		free(buf);
		return len;
	}

	if (answer)
		*answer = buf;
	else
		free(buf);

	return len;
}

static int rtnl_dump_done(struct nlmsghdr *h,
			  const struct rtnl_dump_filter_arg *a)
{
	int len = *(int *)NLMSG_DATA(h);

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof(int))) {
		fprintf(stderr, "DONE truncated\n");
		return -1;
	}

	if (len < 0) {
		errno = -len;

//		if (a->errhndlr && (a->errhndlr(h, a->arg2) & RTNL_SUPPRESS_NLMSG_DONE_NLERR))
//			return 0;

		/* check for any messages returned from kernel */
//		if (nl_dump_ext_ack_done(h, len))
//			return len;

		switch (errno) {
		case ENOENT:
		case EOPNOTSUPP:
			return -1;
		case EMSGSIZE:
			fprintf(stderr,
				"Error: Buffer too small for object.\n");
			break;
		default:
			perror("RTNETLINK answers");
		}
		return len;
	}

	/* check for any messages returned from kernel */
//	nl_dump_ext_ack(h, NULL);

	return 0;
}

static int rtnl_dump_filter_l(struct rtnl_handle *rth,
			      const struct rtnl_dump_filter_arg *arg)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char *buf;
	int dump_intr = 0;

	while (1) {
		int status;
		const struct rtnl_dump_filter_arg *a;
		int found_done = 0;
		int msglen = 0;

		status = rtnl_recvmsg(rth->fd, &msg, &buf);
		if (status < 0)
			return status;

//		if (rth->dump_fp)
//			fwrite(buf, 1, NLMSG_ALIGN(status), rth->dump_fp);

		for (a = arg; a->filter; a++) {
			struct nlmsghdr *h = (struct nlmsghdr *)buf;

			msglen = status;

			while (NLMSG_OK(h, msglen)) {
				int err = 0;

				h->nlmsg_flags &= ~a->nc_flags;

				if (nladdr.nl_pid != 0 ||
				    h->nlmsg_pid != rth->local.nl_pid ||
				    h->nlmsg_seq != rth->dump)
					goto skip_it;

				if (h->nlmsg_flags & NLM_F_DUMP_INTR)
					dump_intr = 1;

				if (h->nlmsg_type == NLMSG_DONE) {
					err = rtnl_dump_done(h, a);
					if (err < 0) {
						free(buf);
						return -1;
					}

					found_done = 1;
					break; /* process next filter */
				}

				if (h->nlmsg_type == NLMSG_ERROR) {
//					err = rtnl_dump_error(rth, h, a);
//					if (err < 0) {
//						free(buf);
//						return -1;
//					}

					goto skip_it;
				}

//				if (!rth->dump_fp) {
					err = a->filter(h, a->arg1);
					if (err < 0) {
						free(buf);
						return err;
					}
//				}

skip_it:
				h = NLMSG_NEXT(h, msglen);
			}
		}
		free(buf);

		if (found_done) {
			if (dump_intr)
				fprintf(stderr,
					"Dump was interrupted and may be inconsistent.\n");
			return 0;
		}

		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}
		if (msglen) {
			fprintf(stderr, "!!!Remnant of size %d\n", msglen);
			exit(1);
		}
	}
}

int rtnl_dump_filter_nc(struct rtnl_handle *rth,
			rtnl_filter_t filter,
			void *arg1, __u16 nc_flags)
{
	const struct rtnl_dump_filter_arg a[] = {
		{
			.filter = filter, .arg1 = arg1,
			.nc_flags = nc_flags,
		},
		{ },
	};

	return rtnl_dump_filter_l(rth, a);
}

#define rtnl_dump_filter(rth, filter, arg) \
	rtnl_dump_filter_nc(rth, filter, arg, 0)



//static void bridge_monitor_mdb_check(struct rtnl_handle *rth)
static void bridge_monitor_mdb_check(void)
{
	static struct timespec last_checked = { .tv_sec = 0, .tv_nsec = 0 };
	struct timespec cur_time;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &cur_time);
	if (ret < 0) {
		perror("clock_gettime()");
		exit(3);
	}

	/* not time to check yet */
	if (last_checked.tv_sec &&
	    last_checked.tv_sec + BRMMDB_CHECK_TIMEOUT >= cur_time.tv_sec)
		return;

	rth_dump.pre_dump_cb(rth_dump.bridge);

	if (rtnl_mdbdump_req(&rth_dump, PF_BRIDGE) < 0) {
		perror("Cannot send dump request");
		return;
	}

	if (rtnl_dump_filter(&rth_dump, print_mdbs, &rth_dump) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return;
	}

	ret = rth_dump.post_dump_cb(rth_dump.bridge);
	if (ret) {
		/* a listener was absent or deleted, early recheck */
		last_checked.tv_sec = 0;
		last_checked.tv_nsec = 0;
		return;
	}

	last_checked = cur_time;
}

static int
bridge_monitor_mdbdump_setup(struct rtnl_handle *rth,
			     struct bridge *br,
			     int (*update_cb)(struct bridge *br,
					      int port_ifindex,
					      __u16 nlmsg_type,
					      int addr_family,
					      const void *group),
			     void (*pre_dump_cb)(struct bridge *br),
			     int (*post_dump_cb)(struct bridge *br))
{
	int ret = rtnl_open(rth, 0);

	rth->bridge = br;
	rth->update_cb = update_cb;
	rth->pre_dump_cb = pre_dump_cb;
	rth->post_dump_cb = post_dump_cb;

	return ret;
}

static int
bridge_monitor_mdbmon_setup(struct rtnl_handle *rth,
			    struct bridge *br,
			    int (*update_cb)(struct bridge *br,
					     int port_ifindex,
					     __u16 nlmsg_type,
					     int addr_family,
					     const void *group),
			    void (*status_dump_cb)(struct bridge *br))
{
	struct timeval timeval = { .tv_sec = BRMMDB_CHECK_TIME, .tv_usec = 0 };
	unsigned int groups = nl_mgrp(RTNLGRP_MDB);
	int ret = rtnl_open(rth, groups);

	if (ret < 0)
		return ret;

	ret = setsockopt(rth->fd, SOL_SOCKET, SO_RCVTIMEO,
			 &timeval, sizeof(timeval));
	if (ret < 0) {
		perror("SO_RCVTIMEO");
		rtnl_close(rth);
		return ret;
	}

	rth->bridge = br;
	rth->update_cb = update_cb;
	rth->pre_dump_cb = NULL;
	rth->post_dump_cb = NULL;
	rth->status_dump_cb = status_dump_cb;

	return 0;
}

int bridge_monitor_mdb(int (*update_cb)(struct bridge *br,
					int port_ifindex,
					__u16 nlmsg_type,
					int addr_family,
					const void *group),
		       void (*pre_dump_cb)(struct bridge *br),
		       int (*post_dump_cb)(struct bridge *br),
		       void (*status_dump_cb)(struct bridge *br),
		       struct bridge *br)
{
	if (bridge_monitor_mdbdump_setup(&rth_dump, br, update_cb, pre_dump_cb, post_dump_cb) < 0)
		exit(1);

	if (bridge_monitor_mdbmon_setup(&rth_mon, br, update_cb, status_dump_cb) < 0) {
		rtnl_close(&rth_dump);
		exit(2);
	}

	if (rtnl_listen(&rth_mon, accept_msg, &rth_mon) < 0) {
		rtnl_close(&rth_mon);
		rtnl_close(&rth_dump);
		exit(3);
	}

	rtnl_close(&rth_mon);
	rtnl_close(&rth_dump);

	return 0;
}

void bridge_monitor_mdb_shutdown(void) {
	running = 0;
}

void bridge_monitor_mdb_status(void) {
	status_dump = 1;
}
