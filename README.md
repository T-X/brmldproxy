# brmldproxy

A userspace controlled MLD proxy implementation for a Linux bridge.

The bridge itself will appear as a single multicast listening host
to any MLD querier on a configured proxy port, acting in deputy
for any other multicast listener behind adjacent bridge ports.
This potentially reduces MLD report overhead.
brmldproxy further allows to filter out specific multicast groups
and bridge ports from its combined MLD report.

# Why

1) To reduce duplicate MLD reports: Multiple hosts might join
   the same group(s). Each would produce their own MLD report.
   Which would be passing redundant information to another
   bridge port. It is sufficient (in most cases) to just
   forward one bundled MLD report instead, without redundant
   group information, to reduce MLD overhead.

   Example illustrations (from other vendors):
   * https://techhub.hpe.com/eginfolib/networking/docs/switches/3100-48/5998-7635r_ip-multi_cg/content/442450483.htm
   * https://forum.huawei.com/enterprise/en/implementation-of-internet-group-management-protocol-igmp-proxy-steps-to-remember/thread/667220449806925824-667213871523442688

   (TODO: replace these links with our own pictures here)

2) Filtering support for specific ports and multicast groups.

   The main motivation for this tool is for mesh networks
   based on the batman-adv layer 2 mesh protocol and the Gluon
   mesh firmware framework. To filter out MLD for link-local
   multicast groups towards the mesh side (plus using manually
   configured bridge multicast router ports). And only
   forwarding MLD reports for the (currently) a lot less
   commonly used routable multicast groups to multicast routers.
   Again to overall reduce MLD overhead.

## How

1. For each proxied port a new Linux dummy interface named "brmldp0/1/..." is created.
2. Any multicast listener snooped by the bridge on adjacent ports
   gets installed as a new socket with an according multicast listener join
   on this dummy interface.
4. TC redirects MLD queries ingress on a proxied port to its assigned dummy interface.
5. The Linux IPv6 stack will respond on the dummy interface to the redirected MLD queries with MLD reports
6. TC will redirect MLD reports from the dummy interface to its according proxied port.

brmldproxy takes care of managing these TC redirections and dummy interface setups
in response to the provided configuration options on the one hand. And in
response to multicast listener state changes, which it got notified of via
Netlink from the Linux bridge, on the other.

## Usage

```
$ brmldproxy
Usage: brmldproxy -b <bridge> [<options> ...]

    -b <bridge>                         bridge interface brmldproxy will run on

Options:
    -i <bridge-port>                    bridge port to proxy (from)
    -e <bridge-port>                    bridge port to exclude from proxying
    -p <bridge-port>                    bridge port to proxy to
    -I <mcast-address>[/mask]           multicast IP address (range) to include in proxying
    -E <mcast-address>[/mask]           multicast IP address (range) to exclude from proxying
```

Most simple way to run: Only specify a bridge via "-b". Then each
port of this bridge will reply to external MLD queries with proxied
MLD reports. An MLD querier will then only see a single, reporting
host from each port.

---

More advanced options are supported as follows:

**-p / proxied-port:** bridge port to proxy to
**-i / included-port:** bridge port to proxy from

"-p" and "-i" allow to only select some ports for proxied MLD reports
(-p). While an MLD querier on an "-i" port still gets individual,
unproxied MLD reports. However listeners behind "-i" ports
are still included for proxied reports on "-p" ports.

So if you are mainly interested in proxying MLD on a specific port
("WAN" like, multicast router facing side?) then this can help to reduce
the number of created dummy interfaces and can reduce the "tc"
performance impact on such non-proxied, included "-i" ports.

**-e <bridge-port>:**  bridge port to exclude from proxying

Which is in contrast to "-e" excluded ports. Any listeners behind
such ports will be excluded / filtered from proxied MLD reports on
a "-p" proxied port.

**-I <mcast-address>[/mask]:** multicast IP address (range) to include in proxying
**-E <mcast-address>[/mask]:** multicast IP address (range) to exclude from proxying

Allows to further exclude / filter out specific multicast IP addresses
or ranges from MLD reports on "-p" proxied ports. Either via
"allow lists" if "-I" comes first or "deny lists" if "-E" comes first.
Multiple "-I" and "-E" options can be specified, options more to the
right override ones to the left when ranges overlap.
"/mask" may be either a bitmask length or a bitmask address.

Example: `-E ff02::/ff0f:: -I ff02:1111::/32 -E ff02:1111::1234`

Would by default allow all multicast addresses, but would
disallow link-local multicast, except addresses
in the ff02:1111::/32 range that are allowed, with the
more specific exeception to the exception that the address
ff02:1111::1234 is disallowed.

## Signals

* SIGINT/SIGHUP/SIGTERM: trigger a clean shutdown
* SIGUSR1: dumps listener status to stdout.
  This will list the listener groups which a proxied port will
  send (an) IGMP/MLD report(s) for.

Example output of SIGUSR1:

```
$ brmldproxy -6 -b br-client -p bat0 -e local-port -E ff05::abcd -E ff02::/ff0f:: -E ff00::/ff0e::
* included:
        br-client
        eth0
* excluded:
        local-port
* proxied:
        bat0
[SIGUSR1 here]
Proxied listeners for br-client:
        bat0:
                ff15::42 (eth0)
                ff15::123 (eth0)
                ff05::2:1001 (br-client)
                ff05::2:1001 (eth0)
```

## Limitations

* brmldproxy cannot fully filter out the IPv6 solicited-node multicast
  address from the bridge interface itself. As the Linux kernel
  currently needs an IPv6 address installed on the dummy interface
  (which is copied from the bridge interface) to be able to respond via MLD.
  And brmldproxy is not capable of modifying the MLD report which the
  Linux kernel has generated on this dummy interface.
* There is currently no IPv4/IGMP support yet.
* There is no support for a Linux bridge in MLDv2 mode yet.
  (However the proxied MLD report is independent of that, the
   Linux IPv6 stack will generate either an MLDv1 or MLDv2 report
   depending on if it received an MLDv1 or MLDv2 query on its proxided port.)

Also see:

## TODOs

See [TODO.md](./docs/TODO.md).
