# Included, proxied port (p-port) vs. included, non-proxied port (i-port)

## Scenario A.1: Querier behind p-port

* Query is forwarded from p-port to i-port (via bridge).
* Query is forwarded/copied from p-port to p-d-port (via tc).
* Reports from i-port are forwarded to p-port (via bridge),
  but are then filtered before going out on p-port (via tc / TODO).
* Reports from p-port are forwarded to i-port (via bridge),
  but bridge might avoid forwarding it if no router is behind
  the i-port (RFC4541, e.g. no MRD adv. from it and no
  manual router port config)
* Reports from p-d port are redirected to p-port (via tc).

```
       
         /--------/
        /        /  <-Q
   ---=/i     /p/=---
      /      d /
     /--------/

```


## Scenario A.2: Querier behind i-port

* Query is forwarded from i-port to p-port (via bridge).
* Reports from p-port are forwarded to i-port (via bridge),
* Reports from i-port are forwarded to p-port (via bridge),
  but bridge might avoid forwarding it if no router is behind
  the i-port (RFC4541, e.g. no MRD adv. from it and no
  manual router port config)

```
       
         /--------/
  Q->   /        /
   ---=/i     /p/=---
      /      d /
     /--------/

```

## More, miscellaneous examples

Examples for "-b" / "-i" / "-e" / "-p" interface handling

1) "brmldproxy -b br0", br0: eth0, eth1, eth2
-> generic, simple use-case

- replies to an MLD query on eth0 with a combined
  report of listeners from br0 + eth1 + eth2
- similarly for a query on eth1, eth2 or br0
  (combined listeners from br0 + eth0 + eth2, br0 + eth0 + eth1
   or eth0 + eth1 + eth2)

2) "brmldproxy -b br0 -e br0 -e eth2", br0: eth0, eth1, eth2

- replies to an MLD query on eth0 with a combined
  report of listeners from eth1 (and neither br0 nor eth2)
- replies to an MLD query on eth1 with a combined
  report of listeners from eth0 (and neither br0 nor eth2)

3) "brmldproxy -b br0 -e eth2 -p wan0", br0: eth0, eth1, eth2, wan0
-> Gluon use-case

- replies to an MLD query on wan0 with a combined
  report of listeners from br0 + eth0 + eth1 (and not eth2)

4) "brmldproxy -b br0 -i eth0 -i eth1", br0: eth0, eth1, eth2

- replies to an MLD query on eth0 (/eth1) with a combined
  report of listeners from eth1 (/eth0) (and neither br0 nor eth2)

5) "brmldproxy -b br0 -i eth0 -p wan0", br0: eth0, eth1, wan0

- replies to an MLD query on wan0 with a combined
  report of listeners from eth0 (and neither br0 nor eth1)

6) "brmldproxy -b br0 -e wan1@wan0 -p wan0 -p wan1", br0: eth0, eth1, wan0, wan1
("-e x@y" syntax to be implemented later)

- replies to an MLD query on wan0 with a combined
  report of listeners from br0 + eth0 + eth1 (and not wan1)
- replies to an MLD query on wan1 with a combined
  report of listeners from br0 + eth0 + eth1 + wan0

7) "brmldproxy -b br0 -i eth0@wan0 -i eth1@wan1 -p wan0 -p wan1", br0: eth0, eth1, wan0, wan1
("-i x@y" syntax to be implemented later)

- replies to an MLD query on wan0 with a combined
  report of listeners from eth0 (and neither eth1 nor wan1)
- replies to an MLD query on wan1 with a combined
  report of listeners from eth1 (and neither eth0 nor wan0)

