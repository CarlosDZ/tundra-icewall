. "$(dirname "$0")/lib.sh"

setup
# The peer reaches the address of h1 through the link of h0.
in_peer ip route add 10.98.0.1/32 via 10.99.0.1 dev p0
check "without a policy an address is reachable through the other link" peer_tcp 10.98.0.1 22

ipv6=0
if [ -e /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
	echo 0 >/proc/sys/net/ipv6/conf/all/disable_ipv6
	in_peer sh -c 'echo 0 >/proc/sys/net/ipv6/conf/all/disable_ipv6'
	ip -6 addr add fd99::1/64 dev h0 nodad
	in_peer ip -6 addr add fd99::2/64 dev p0 nodad
	sleep 0.5
	if ping -6 -c 1 -W 1 fd99::2 >/dev/null 2>&1; then
		ipv6=1
		ok "without a policy IPv6 works between them"
	fi
fi

rules 500-base <<END
default {
	out = allow
}
allow {
	direction = in
	protocol = tcp
	port = 22
}
allow {
	direction = in
	protocol = icmp
}
END
check "a policy that opens a port and ping everywhere" load
check "the address of an interface, through that interface" peer_tcp 10.99.0.1 22
refuse "the address of another interface is dropped (ADR-021)" peer_tcp 10.98.0.1 22
in_peer ip route del 10.98.0.1/32
check "through its own link it answers" peer_tcp 10.98.0.1 22

if [ "$ipv6" -eq 1 ]; then
	check "IPv4 ping gets in" in_peer ping -c 1 -W 1 10.99.0.1
	refuse "IPv6 does not come in, whatever the rules say" in_peer ping -6 -c 1 -W 1 fd99::1
	refuse "nor go out with the output open" ping -6 -c 1 -W 1 fd99::2
else
	echo "# skip: no IPv6 here"
fi
summary
