#!/bin/sh
# Every test gets its own network and mount namespaces: as root, plain ones;
# as a user, inside a user namespace, where nf_tables works just the same.
cd "$(dirname "$0")/../.." || exit 1

for dep in ip unshare ping; do
	command -v "$dep" >/dev/null || {
		echo "missing dependency: $dep" >&2
		exit 1
	}
done

if [ "$(id -u)" -eq 0 ]; then
	apart="unshare -nm"
else
	apart="unshare -Urnm"
fi

rc=0
for t in tests/net/t-*.sh; do
	[ -e "$t" ] || continue
	printf '# %s\n' "$t"
	$apart sh -c 'mount -t tmpfs tmpfs /run && exec sh "$1"' sh "$t" || rc=1
done
exit $rc
