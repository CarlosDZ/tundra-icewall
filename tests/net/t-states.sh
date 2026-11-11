. "$(dirname "$0")/lib.sh"

setup
rules 500-base <<END
default {
	out = allow
}
allow {
	direction = in
	protocol = tcp
	port = 22
}
END
check "check accepts valid files" "$ICEWALL" check "$RULES"
check "check does not touch the kernel" state_is none
check "load" load
check "the policy works" peer_tcp 10.99.0.1 22

rules 900-broken <<END
allow {
	direction = sideways
}
END
"$ICEWALL" check "$RULES" >/dev/null 2>"$WORK/err"
check "check exits with 2 on a wrong file" [ $? -eq 2 ]
check "and names the file and the line" grep -q "900-broken.rules: line 2: direction must be in or out" "$WORK/err"
"$ICEWALL" load "$RULES" >/dev/null 2>"$WORK/err"
check "load exits with 2 too" [ $? -eq 2 ]
check "and says the policy stays" grep -q "the policy in the kernel is left as it was" "$WORK/err"
check "the state is still policy" state_is policy
check "and the old policy still works" peer_tcp 10.99.0.1 22

"$ICEWALL" boot "$RULES" >/dev/null 2>"$WORK/err"
check "boot exits with 2 on a wrong file" [ $? -eq 2 ]
check "and loads the lockdown" state_is lockdown
check "which it says" grep -q "lockdown loaded: only local traffic" "$WORK/err"
refuse "nothing comes in" peer_tcp 10.99.0.1 22
refuse "nothing goes out" host_tcp 10.99.0.2 80
refuse "not even a ping" ping -c 1 -W 1 10.99.0.2
check "local traffic survives the lockdown" host_tcp 127.0.0.1 22

rm -f "$RULES/900-broken.rules"
check "boot with valid files" "$ICEWALL" boot "$RULES"
check "leaves the policy" state_is policy
check "and it works" peer_tcp 10.99.0.1 22

check "lockdown by hand" "$ICEWALL" lockdown
check "state lockdown" state_is lockdown
refuse "closes what was open" peer_tcp 10.99.0.1 22
check "load brings the policy back" load
check "open again" peer_tcp 10.99.0.1 22

"$ICEWALL" load "$WORK/missing" >/dev/null 2>&1
check "a directory that cannot be read exits with 1" [ $? -eq 1 ]
check "and leaves the policy" state_is policy
"$ICEWALL" boot "$WORK/missing" >/dev/null 2>&1
check "at boot it is a lockdown" state_is lockdown

"$ICEWALL" >/dev/null 2>&1
check "no command is a usage error" [ $? -eq 2 ]
"$ICEWALL" unload >/dev/null 2>&1
check "there is no command to take the firewall away" [ $? -eq 2 ]
"$ICEWALL" status extra >/dev/null 2>&1
check "an extra argument is a usage error" [ $? -eq 2 ]
check "--version" sh -c "$ICEWALL --version | grep -q '^tundra-icewall '"

no_rules
cp "$ROOT/data/500-base.rules" "$RULES/"
check "the stock policy is valid" "$ICEWALL" check "$RULES"
sed -n 's/^# \{0,1\}//p' "$ROOT/data/000-template.rules" |
	awk '/^(allow|deny|default) \{$/,/^\}$/' >"$RULES/600-examples.rules"
check "and so is every example of the template" sh -c "$ICEWALL check '$RULES' | grep -q ': 5 rules, out allowed'"
cp "$ROOT/data/000-template.rules" "$RULES/"
check "the template itself is never loaded" sh -c "$ICEWALL check '$RULES' | grep -q ': 5 rules, out allowed'"
no_rules

if command -v nft >/dev/null; then
	rules 500-base <<END
default {
	out = deny
}
allow {
	direction = in
	interface = h0
	protocol = tcp, udp
	port = 22, 8000-8100
	from = 192.168.1.0/24
}
deny {
	direction = out
	protocol = icmp
	to = 10.0.0.5
}
END
	load >/dev/null
	nft list table inet tundra-icewall >"$WORK/got"
	cat >"$WORK/want" <<END
table inet tundra-icewall {
	chain forward {
		type filter hook forward priority filter; policy drop;
	}

	chain strong {
		fib daddr . iif type local return
		fib daddr . iif type broadcast return
		fib daddr . iif type multicast return
		drop
	}

	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		meta nfproto ipv6 drop
		ct state invalid drop
		ct state established,related accept
		jump strong
		iifname "h0" ip saddr 192.168.1.0/24 tcp dport 22 accept
		iifname "h0" ip saddr 192.168.1.0/24 tcp dport 8000-8100 accept
		iifname "h0" ip saddr 192.168.1.0/24 udp dport 22 accept
		iifname "h0" ip saddr 192.168.1.0/24 udp dport 8000-8100 accept
	}

	chain output {
		type filter hook output priority filter; policy drop;
		oifname "lo" accept
		meta nfproto ipv6 drop
		ct state established,related accept
		meta l4proto icmp ip daddr 10.0.0.5 drop
		drop
	}
}
END
	if diff -u "$WORK/want" "$WORK/got" >"$WORK/diff"; then
		ok "nft reads from the kernel the policy that was written"
	else
		not_ok "nft reads from the kernel the policy that was written"
		sed 's/^/#   /' "$WORK/diff"
	fi
else
	echo "# skip: no nft here to read the kernel back"
fi
summary
