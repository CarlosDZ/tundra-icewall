# tundra-icewall

Firewall of Tundra OS, works on any Linux with `nf_tables`. It reads rules from
text files with a closed vocabulary and loads them into the kernel over
netlink, by itself: no `nft`, libnftnl or libmnl.

It is a mechanism, not a guardian: it loads what the files say and exits.

## Requirements

- Linux with `nf_tables`, conntrack and the `fib` expression
  (`CONFIG_NF_TABLES_INET`, `CONFIG_NFT_CT`, `CONFIG_NFT_FIB_INET`).
- libseccomp and tundra-libconf. A checkout of tundra-libconf next to this one,
  built, is used instead of an installed one.
- `CAP_NET_ADMIN` for every command but `check`.

## Usage

```
tundra-icewall check [directory]
tundra-icewall load [directory]
tundra-icewall boot [directory]
tundra-icewall lockdown
tundra-icewall status
tundra-icewall --version
```

| Command | What it does |
|---------|--------------|
| `check` | Validates the rule files without touching the kernel. Needs no privileges |
| `load` | Validates everything and, only if it is right, replaces the policy in one transaction. On any failure the policy in the kernel stays as it was |
| `boot` | As `load`, but a failure loads the lockdown: at boot there is no earlier policy to keep |
| `lockdown` | Loads the lockdown: only local traffic, in and out |
| `status` | Prints `policy`, `lockdown` or `none`, read from the kernel |

The directory is `/etc/tundra/icewall` unless one is given. There is no command
that takes the firewall away.

## Rule files

`/etc/tundra/icewall/*.rules`, read in lexicographic order, in the configuration
grammar of Tundra (tundra-libconf). `500-base.rules` is the stock policy;
`000-template.rules` documents every key and is never loaded.

```
default {
	out = allow
}

allow {
	direction = in
	interface = enp0s31f6
	protocol = tcp
	port = 22, 8000-8100
	from = 192.168.1.0/24
}
```

| Block | |
|-------|-|
| `default` | Once at most, in any file: `out = allow` or `out = deny`. Without it the output is denied. The input is not configurable |
| `allow`, `deny` | A rule. The first one that matches wins, in the order of the files |

| Key | Value | |
|-----|-------|-|
| `direction` | `in` or `out` | Required |
| `interface` | An interface name | Any, without it |
| `protocol` | `tcp`, `udp`, `icmp` or a list | Any, without it |
| `port` | Destination port: a number, a list, a range, or a mix (`22, 8000-8100`) | Only with `tcp` and `udp`; up to 16 |
| `from` | Source: an IPv4 address or network | An address with bits outside its prefix is refused |
| `to` | Destination: an IPv4 address or network | |

Any other block, key or value is an error of the whole load, reported with its
file and line. Limits: 128 files, 256 rules, 1024 kernel rules (a rule becomes
one per protocol and port range).

## Fixed rules

Always loaded before the rules of the files, which cannot change them:

| Chain | In order |
|-------|----------|
| Input | Local traffic accepted · IPv6 dropped · invalid connections dropped · replies to connections of this host accepted · a packet for the address of another interface dropped (strong host model) · rules · drop |
| Output | Local traffic accepted · IPv6 dropped · established connections accepted · rules · `default out` |
| Forward | Drop |

Everything lives in one table, `inet tundra-icewall`, destroyed and created in
the same transaction: no packet sees half a policy.

With the stock policy the host does not answer to ping. With `out = deny`, DHCP
still gets its first lease (tundra-dhcpc uses a packet socket, below the
firewall) but needs a rule to renew it: the template has it.

## Exit status

| Code | Meaning |
|------|---------|
| `0` | Done |
| `1` | The kernel or the system failed: no privileges, a directory that cannot be read, a transaction refused |
| `2` | Invalid usage or rule files |

After a `boot` that exits with `1` or `2`, the lockdown is loaded.

## Service

`tundra-icewall.service` runs `boot` before `network-pre.target` and `load` on
reload. A unit that requires it, as tundra-networkd does, does not start when
`boot` fails.

## Privileges

It reads the files, opens its netlink socket, keeps only `CAP_NET_ADMIN` and
loads a seccomp filter that leaves that socket and the two output streams;
only then it sends anything to the kernel.

## Building

```
make
make install
```

| Variable | Default |
|----------|---------|
| `TUNDRA_ICEWALL_DIR` | `/etc/tundra/icewall` |
| `PREFIX` | `/usr` |
| `SYSCONFDIR` | `/etc` |

## Tests

```
make check-unit
make check
```

`check-unit` runs the unit tests with ASan and UBSan. `check` adds the
integration tests: each one gets its own network namespaces, loads policies
into the kernel and sends real TCP, UDP and ICMP traffic between two of them.
As root they use plain namespaces; as a user, a user namespace. Where `nft` is
installed, one test reads the kernel back with it and compares, as an
independent check of what was written.

## Currently unsupported

- IPv6 rules: IPv6 is dropped whole.
- ICMP types, source ports, logging and counters.
- Rules added at runtime: the policy is replaced whole.

## License

GPL-3.0-or-later.
