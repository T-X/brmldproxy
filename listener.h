/* SPDX-FileCopyrightText: 2023 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __LISTENER_H__
#define __LISTENER_H__

#include <linux/types.h> // __u16

#include "brmldproxy.h"

int listener_update(struct bridge *br, int port_ifindex, __u16 nlmsg_type, int addr_family, const void *group);
void listener_reduce_lifes(struct bridge *br);
int listener_flush_dead(struct bridge *br);
void listener_flush(struct brport *port);
int listener_filter_add_group(struct bridge *br,
			      struct sockaddr_storage *group,
			      struct sockaddr_storage *mask,
			      int mode);
void listener_dump(struct bridge *br);

#endif /* __LISTENER_H__ */
