/* SPDX-FileCopyrightText: 2023 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __BRMONMDB_H__
#define __BRMONMDB_H__

#include <linux/types.h> // __u16

int bridge_monitor_mdb(void (*callback)(struct bridge *br,
					int br_ifindex,
					int port_ifindex,
					__u16 nlmsg_type,
					int addr_family,
					const void *group),
		       struct bridge *br);

void bridge_monitor_mdb_shutdown(void);

#endif /* __BRMONMDB_H__ */
