/* SPDX-FileCopyrightText: 2023 Linus Lüssing <linus.luessing@c0d3.blue> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __BRMLDPROXY_H__
#define __BRMLDPROXY_H__

#include <net/if.h> // IFNAMSIZ, if_nametoindex()

#include "list.h"

struct bridge {
	struct list_head included_ports_list;
	struct list_head excluded_ports_list;
	struct list_head proxied_ports_list;

	struct list_head group_filter_list_v4;
	struct list_head group_filter_list_v6;

	// IFNAMSIZ: typ. 16 on Linux?
	char name[IFNAMSIZ];
	int ifindex;
};

struct brport {
	struct list_head node;
	struct list_head listener_list_v4; // TODO: make this a hash table?
	struct list_head listener_list_v6; // TODO: make this a hash table?

	char name[IFNAMSIZ];
	int ifindex;

	char prname[IFNAMSIZ];
	int prifindex;

	char prbname[IFNAMSIZ];
	int prbifindex;
};

int setup_proxy_port_rx_dummy_query(struct brport *port);
void teardown_proxy_port_rx_dummy_query(struct brport *port);

#endif /* __BRMLDPROXY_H__ */
