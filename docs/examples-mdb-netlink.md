1) `$ ./mcjoin -d -i veth0 "[ff12::125]"`

`$ bridge monitor mdb`

```
dev br0 port veth1 grp ff12::125 temp filter_mode include proto kernel
dev br0 port veth1 grp ff12::125 temp filter_mode exclude proto kernel
```

`$ bridge -d mdb show`

```
...
dev br0 port veth1 grp ff12::125 temp filter_mode exclude proto kernel
...
```

2) `$ killall mcjoin`

`$ bridge monitor mdb`

```
Deleted dev br0 port veth1 grp ff12::125 temp filter_mode include proto kernel
```

---


1) `./mcjoin -d -i veth0 "[fe80::130],[ff12::130]"`

```
dev br0 port veth1 grp ff12::130 temp filter_mode include proto kernel
dev br0 port veth1 grp ff12::130 src fe80::130 temp filter_mode include proto kernel
dev br0 port veth1 grp ff12::130 temp filter_mode include source_list fe80::130/260.00 proto kernel
```

```
...
dev br0 port veth1 grp ff12::130 src fe80::130 temp filter_mode include proto kernel
dev br0 port veth1 grp ff12::130 temp filter_mode include source_list fe80::130/241.31 proto kernel
...
```

2) `./mcjoin -d -i veth0 "[fe80::131],[ff12::130]"`

```
dev br0 port veth1 grp ff12::130 src fe80::131 temp filter_mode include proto kernel
dev br0 port veth1 grp ff12::130 temp filter_mode include source_list fe80::131/260.00,fe80::130/247.86 proto kernel
```

```
...
dev br0 port veth1 grp ff12::130 src fe80::131 temp filter_mode include proto kernel
dev br0 port veth1 grp ff12::130 src fe80::130 temp filter_mode include proto kernel
dev br0 port veth1 grp ff12::130 temp filter_mode include source_list fe80::131/251.79,fe80::130/206.32 proto kernel
...
```

3) `kill (1)`

```
Deleted dev br0 port veth1 grp ff12::130 src fe80::131 temp filter_mode include proto kernel
```

```
...
dev br0 port veth1 grp ff12::130 src fe80::130 temp filter_mode include proto kernel
dev br0 port veth1 grp ff12::130 temp filter_mode include source_list fe80::130/250.50 proto kernel
...
```

4) `kill (2)`

```
Deleted dev br0 port veth1 grp ff12::130 src fe80::130 temp filter_mode include proto kernel
Deleted dev br0 port veth1 grp ff12::130 temp filter_mode include proto kernel
```
