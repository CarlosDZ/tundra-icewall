# Sourced by every test. The host side is this namespace, where tundra-icewall
# loads its policy; the peer is another one, reached over two veth links:
#
#   host h0 10.99.0.1 ---- p0 10.99.0.2 peer
#   host h1 10.98.0.1 ---- p1 10.98.0.2 peer

ROOT=$(pwd)
ICEWALL=$ROOT/build/test/tundra-icewall
TALK=$ROOT/build/test/tools/talk
WORK=$(mktemp -d /run/icewall-test.XXXXXX)
RULES=$WORK/rules
PEER=peer
PASS=0
FAIL=0
BG=

ok() {
	PASS=$((PASS + 1))
	printf 'ok - %s\n' "$1"
}

not_ok() {
	FAIL=$((FAIL + 1))
	printf 'not ok - %s\n' "$1"
}

check() {
	desc=$1
	shift
	if "$@" >/dev/null 2>&1; then
		ok "$desc"
	else
		not_ok "$desc"
	fi
}

# The opposite: the command has to fail.
refuse() {
	desc=$1
	shift
	if "$@" >/dev/null 2>&1; then
		not_ok "$desc"
	else
		ok "$desc"
	fi
}

in_peer() {
	ip netns exec "$PEER" "$@"
}

background() {
	"$@" >/dev/null 2>&1 &
	BG="$BG $!"
}

setup() {
	ip link set lo up
	ip netns add "$PEER"
	ip -n "$PEER" link set lo up
	for n in 0 1; do
		ip link add "h$n" type veth peer name "p$n" netns "$PEER"
		ip addr add "10.9$((9 - n)).0.1/24" dev "h$n"
		ip link set "h$n" up
		ip -n "$PEER" addr add "10.9$((9 - n)).0.2/24" dev "p$n"
		ip -n "$PEER" link set "p$n" up
	done
	for f in all default h0 h1; do
		echo 0 >"/proc/sys/net/ipv4/conf/$f/rp_filter"
	done
	mkdir -p "$RULES"
	# What the peer offers and what the host offers.
	for port in 22 23 80 81; do
		background "$TALK" listen tcp "$port"
		background in_peer "$TALK" listen tcp "$port"
	done
	for port in 5000 5005 5010 5011 6000; do
		background "$TALK" listen udp "$port"
	done
	background in_peer "$TALK" listen udp 53
	sleep 0.3
}

teardown() {
	for p in $BG; do
		kill "$p" 2>/dev/null
	done
	ip netns del "$PEER" 2>/dev/null
	rm -rf "$WORK"
}

# rules <name> : writes stdin as a rule file.
rules() {
	cat >"$RULES/$1.rules"
}

no_rules() {
	rm -f "$RULES"/*.rules
}

load() {
	"$ICEWALL" load "$RULES"
}

state_is() {
	[ "$("$ICEWALL" status)" = "$1" ]
}

# From the peer to the host, and back.
peer_tcp() {
	in_peer "$TALK" tcp "$1" "$2"
}

peer_udp() {
	in_peer "$TALK" udp "$1" "$2"
}

host_tcp() {
	"$TALK" tcp "$1" "$2"
}

host_udp() {
	"$TALK" udp "$1" "$2"
}

summary() {
	teardown
	printf '# %d passed, %d failed\n' "$PASS" "$FAIL"
	[ "$FAIL" -eq 0 ]
}
