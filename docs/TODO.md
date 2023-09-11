# TODOs

[x] BUG: br0(i) { veth0(p) }, querier on br0
    -> once brmldproxy is started, the bridge
       loses MDB entries from veth0
    -> setup_proxy_port_tx() prevents
       MLD queries from appearing on veth1(<-veth0)
[ ] BUG: br0 as proxied port is not working
    -> listener from another proxied port
       appears directly br0 in bridge MDB
       (but not in "ip maddr show")
    -> does it need other tc rules?
    -> workaround: put br0 into include instead of
       proxied list by default, disallow using
       "-p br0"
[x] fixup brmldproxy's listeners via (netlink of)
    "bridge mdb show" (about every 30 seconds maybe?)
    -> we don't get full MDB state on startup and
       maybe "bridge monitor mdb" might sometimes be
       out of order?
       -> be conservative: before deleting a specific
          listener via full dump, check full dump 2 more times,
          with a little delay in between?
    -> current workaround (sort of) could be: start brmldproxy
       before setting br0 up (but this will miss the
       listeners on br0, too, somehow they are not cleaned
       from the MDB on interface down)
[ ] MLDv2 SSM listeners support
    (full MLDv2 support -> currently all treated like ASM)
[x] multicast address filters
[ ] IPv4 support
    (open question: which IPv4 address to pick from br0
     to add to a proxied port's dummy interface,
     which address would the Linux kernel choose for IGMP reports
     from br0?
     what to do if no IPv4 address is available on br0?
     or could we just use any IP address as an IGMP report's source
     and SNAT it to 0.0.0.0?)
[ ] add hash tables for faster lookups
[ ] bridge port hotplugging
[ ] use netlink for "tc" commands (avoid process spawning)
[ ] use netlink for "ip" commands (avoid process spawning)
[x] avoid forwarding MLD Reports to proxied ports
    (still needs to go through the bridge for mdb learning,
     filtering can only be done on outgoing port)
[ ] add a delay for forwarding MLD queries to proxied-dummy port,
    equal to MLD query's maximum response delay?
    (as we might transmit multiple, proxied MLD reports otherwise,
     when responses arrive one by one; or better alternative:
     proxy MLD queries, too, see below, but more work)
    and would likely also need to alter/reduce the MLD query's
    maximum response delay when forwarded to work properly...
[ ] multicast router
  [ ] MLD Querier
    [ ] avoid forwarding MLD Queries to proxied ports
    [ ] become a (potential) MLD querier on a proxied port if a
        querier is present on one of the other ports
    [ ] become a (potential) MLD querier on a non-proxied port if a
        querier is present on one of the other ports
  [ ] MRD
    [ ] avoid forwarding MRD to proxied ports
    [ ] respond to Multicast Router Discovery solicitations messages
        on proxied ports (if router present on other ports)
[ ] for batman-adv setups:
    to reduce mesh-wide report overhead,
    detect routers on proxied ports (MLD query + MRD) and send
    MLD report to them via individual unicasts instead of via
    multicast?
    -> simpler/better to do in batman-adv, but not sure if this
       would be accepted upstream, so maybe patch this in
       batman-adv's Gluon only and implement this as a fallback
       (config) option here?
[ ] avoid (reduce?) sending unsolicited MLD reports on proxied ports, if no MLD
    querier is present
[ ] write some tests
[x] add a SIGUSR1 handle which dumps current internal state
    (for debugging purposes, easier overview than looking at
     "ip maddr show" and "bridge -d mdb show"
