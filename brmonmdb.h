/* SPDX-FileCopyrightText: 2023 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __BRMONMDB_H__
#define __BRMONMDB_H__

#include <linux/types.h> // __u16

int bridge_monitor_mdb(int (*update_cb)(struct bridge *br,
					int port_ifindex,
					__u16 nlmsg_type,
					int addr_family,
					const void *group),
		       void (*pre_dump_cb)(struct bridge *br),
		       int (*post_dump_cb)(struct bridge *br),
		       struct bridge *br);

void bridge_monitor_mdb_shutdown(void);

#endif /* __BRMONMDB_H__ */
