. "$(dirname "$0")/lib.sh"

setup
check "without a table the state is none" state_is none
check "and everything gets through" peer_tcp 10.99.0.1 22

rules 500-base <<END
default {
	out = allow
}
END
check "the base policy loads" load
check "the state is policy" state_is policy
refuse "the input is closed" peer_tcp 10.99.0.1 22
refuse "also for udp" peer_udp 10.99.0.1 5000
refuse "and for ping" in_peer ping -c 1 -W 1 10.99.0.1
check "the output is open" host_tcp 10.99.0.2 80
check "its replies come back over udp too" host_udp 10.99.0.2 53
check "and ping out is answered" ping -c 1 -W 1 10.99.0.2
check "local traffic is untouched" host_tcp 127.0.0.1 22

rules 600-ssh <<END
allow {
	direction = in
	protocol = tcp
	port = 22
	from = 10.99.0.0/24
}
END
check "a rule is added" load
check "the allowed port is open for that network" peer_tcp 10.99.0.1 22
refuse "another port is not" peer_tcp 10.99.0.1 23
refuse "nor that port for another network" peer_tcp 10.98.0.1 22

rules 600-ssh <<END
allow {
	direction = in
	interface = h1
	protocol = tcp
	port = 22, 23
}
END
check "a rule for one interface, with a list of ports" load
check "the first port, on that interface" peer_tcp 10.98.0.1 22
check "the second port" peer_tcp 10.98.0.1 23
refuse "a port outside the list" peer_tcp 10.98.0.1 80
refuse "the same port on the other interface" peer_tcp 10.99.0.1 22

rules 600-ssh <<END
allow {
	direction = in
	protocol = udp
	port = 5000-5010, 6000
}
END
check "a range and a single port, over udp" load
check "the start of the range" peer_udp 10.99.0.1 5000
check "the middle" peer_udp 10.99.0.1 5005
check "the end" peer_udp 10.99.0.1 5010
refuse "one past the end" peer_udp 10.99.0.1 5011
check "the single port" peer_udp 10.99.0.1 6000
refuse "tcp on a udp rule" peer_tcp 10.99.0.1 22

rules 600-ssh <<END
allow {
	direction = in
	protocol = tcp, udp
	port = 22, 5000
}
END
check "two protocols in one rule" load
check "tcp" peer_tcp 10.99.0.1 22
check "udp" peer_udp 10.99.0.1 5000
refuse "the port of one is not open on the other without being listed" peer_udp 10.99.0.1 5005

rules 600-ssh <<END
deny {
	direction = in
	protocol = tcp
	port = 22
	from = 10.99.0.2
}
allow {
	direction = in
	protocol = tcp
	port = 22
}
END
check "a deny before an allow" load
refuse "the first rule that matches wins" peer_tcp 10.99.0.1 22
check "the allow still serves the rest" peer_tcp 10.98.0.1 22

rules 600-ssh <<END
allow {
	direction = in
	protocol = icmp
}
END
check "icmp allowed in" load
check "ping is answered" in_peer ping -c 1 -W 1 10.99.0.1
refuse "tcp is still closed" peer_tcp 10.99.0.1 22

rm -f "$RULES/600-ssh.rules"
rules 500-base <<END
default {
	out = deny
}
allow {
	direction = out
	protocol = tcp
	port = 80
	to = 10.99.0.2
}
END
check "the output closed, with one way out" load
check "the allowed destination and port" host_tcp 10.99.0.2 80
refuse "another port" host_tcp 10.99.0.2 81
refuse "another destination" host_tcp 10.98.0.2 80
refuse "udp" host_udp 10.99.0.2 53
refuse "ping" ping -c 1 -W 1 10.99.0.2
check "local traffic is still untouched" host_tcp 127.0.0.1 22

no_rules
check "without any file the policy still loads" load
refuse "and with no default the output is closed" host_tcp 10.99.0.2 80
refuse "like the input" peer_tcp 10.99.0.1 22
summary
