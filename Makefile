# SPDX-FileCopyrightText: 2023 Linus Lüssing <linus.luessing@c0d3.blue>
# SPDX-License-Identifier: GPL-2.0-or-later

all: brmldproxy

CFLAGS += -Wall

brmldproxy: brmldproxy.c brmonmdb.c listener.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -fPIC -D_GNU_SOURCE -o $@ $^ $(LDLIBS)

clean:
	rm -f brmldproxy
