#include "rules.c"
#include "test.h"

#include <arpa/inet.h>
#include <tundra/conf.h>

static struct tconf g;
static struct ruleset rs;
static char err[RULES_ERR_MAX];

static int add(const char *text) {
	err[0] = '\0';
	if (tconf_parse(text, strlen(text), &g) < 0)
		return -9;
	return rules_add(&rs, &g, err);
}

static int fresh(const char *text) {
	rules_init(&rs);
	return add(text);
}

static int says(const char *text) { return strstr(err, text) != NULL; }

#define IN " direction = in\n"

static void test_default(void) {
	CHECK(fresh("") == 0 && rs.n == 0 && !rs.has_default && !rs.out_allow,
	      "an empty file: no rules, and out stays denied");
	CHECK(fresh("default {\n out = allow\n}\n") == 0 && rs.has_default &&
	          rs.out_allow,
	      "out = allow");
	CHECK(fresh("default {\n out = deny\n}\n") == 0 && rs.has_default &&
	          !rs.out_allow,
	      "out = deny");
	CHECK(fresh("default {\n out = maybe\n}\n") < 0 &&
	          says("line 2: out must be allow or deny"),
	      "another value");
	CHECK(fresh("default {\n}\n") < 0 && says("line 1: default without out"),
	      "a default block without out");
	CHECK(fresh("default {\n in = allow\n}\n") < 0 &&
	          says("unknown key in in default"),
	      "the input is not configurable");
	CHECK(fresh("default {\n out = allow\n out = deny\n}\n") < 0 &&
	          says("repeated key out"),
	      "out twice");
	CHECK(fresh("default {\n out = \"allow\"\n}\n") < 0 &&
	          says("must not be quoted"),
	      "a quoted value");
	fresh("default {\n out = allow\n}\n");
	CHECK(add("default {\n out = deny\n}\n") < 0 &&
	          says("line 1: a second default block") && rs.out_allow,
	      "a second default block, even in another file");
}

static void test_structure(void) {
	CHECK(fresh("out = allow\n") < 0 && says("line 1: out outside a block"),
	      "a key outside a block");
	CHECK(fresh("reject {\n" IN "}\n") < 0 &&
	          says("line 1: unknown block reject"),
	      "an unknown block");
	CHECK(fresh("allow {\n}\n") < 0 && says("line 1: missing direction"),
	      "a rule without direction");
	CHECK(fresh("allow {\n" IN " colour = red\n}\n") < 0 &&
	          says("line 3: unknown key colour"),
	      "an unknown key");
	CHECK(fresh("allow {\n" IN IN "}\n") < 0 &&
	          says("line 3: repeated key direction"),
	      "a repeated key");
	CHECK(fresh("allow {\n direction = both\n}\n") < 0 &&
	          says("direction must be in or out"),
	      "another direction");
	CHECK(fresh("allow {\n" IN "}\ndeny {\n direction = out\n}\n") == 0 &&
	          rs.n == 2 && rs.r[0].allow && rs.r[0].dir == DIR_IN &&
	          !rs.r[1].allow && rs.r[1].dir == DIR_OUT,
	      "rules keep their order, action and direction");
	CHECK(rs.r[0].protos == 0 && rs.r[0].nports == 0 && !rs.r[0].from.set &&
	          !rs.r[0].to.set && rs.r[0].iface[0] == '\0',
	      "a rule with only a direction matches everything");

	static char many[RULES_MAX * 40 + 64];
	size_t len = 0;
	for (int i = 0; i < 100; i++)
		len += (size_t)snprintf(many + len, sizeof(many) - len,
		                        "allow {\n" IN "}\n");
	rules_init(&rs);
	CHECK(add(many) == 0 && add(many) == 0 && rs.n == 200 && add(many) < 0 &&
	          says("more than 256 rules"),
	      "the limit of rules counts every file");
}

static void test_interface(void) {
	CHECK(fresh("allow {\n" IN " interface = enp0s31f6\n}\n") == 0 &&
	          strcmp(rs.r[0].iface, "enp0s31f6") == 0,
	      "an interface");
	CHECK(fresh("allow {\n" IN " interface = abcdefghijklmnop\n}\n") < 0 &&
	          says("invalid interface"),
	      "a name of 16 bytes");
	CHECK(fresh("allow {\n" IN " interface = a/b\n}\n") < 0 &&
	          fresh("allow {\n" IN " interface = a b\n}\n") < 0 &&
	          fresh("allow {\n" IN " interface = ..\n}\n") < 0,
	      "a slash, a space and ..");
}

static void test_protocol(void) {
	CHECK(fresh("allow {\n" IN " protocol = tcp\n}\n") == 0 &&
	          rs.r[0].protos == PROTO_TCP,
	      "one protocol");
	CHECK(fresh("allow {\n" IN " protocol = tcp, udp,icmp\n}\n") == 0 &&
	          rs.r[0].protos == (PROTO_TCP | PROTO_UDP | PROTO_ICMP),
	      "a list, with or without spaces");
	CHECK(fresh("allow {\n" IN " protocol = sctp\n}\n") < 0 &&
	          says("invalid protocol: sctp"),
	      "an unknown protocol");
	CHECK(fresh("allow {\n" IN " protocol = tcp, tcp\n}\n") < 0 &&
	          says("repeated protocol: tcp"),
	      "a repeated protocol");
	CHECK(fresh("allow {\n" IN " protocol = tcp,\n}\n") < 0 &&
	          fresh("allow {\n" IN " protocol = ,tcp\n}\n") < 0 &&
	          says("invalid protocol: (empty)"),
	      "an empty element");
	CHECK(fresh("allow {\n" IN " protocol = TCP\n}\n") < 0,
	      "protocols are lower case");
}

static void test_port(void) {
	CHECK(fresh("allow {\n" IN " protocol = tcp\n port = 22\n}\n") == 0 &&
	          rs.r[0].nports == 1 && rs.r[0].ports[0].lo == 22 &&
	          rs.r[0].ports[0].hi == 22,
	      "a single port");
	CHECK(fresh("allow {\n" IN " protocol = tcp\n port = 80, 443\n}\n") == 0 &&
	          rs.r[0].nports == 2 && rs.r[0].ports[1].lo == 443,
	      "a list");
	CHECK(fresh("allow {\n" IN " protocol = udp\n port = 8000-8100\n}\n") ==
	              0 &&
	          rs.r[0].ports[0].lo == 8000 && rs.r[0].ports[0].hi == 8100,
	      "a range");
	CHECK(fresh("allow {\n" IN
	            " protocol = tcp\n port = 22, 8000-8100,65535\n}\n") == 0 &&
	          rs.r[0].nports == 3 && rs.r[0].ports[2].hi == 65535,
	      "ports and ranges together");
	CHECK(fresh("allow {\n" IN " port = 22\n}\n") < 0 &&
	          says("port requires protocol tcp or udp"),
	      "a port without protocol");
	CHECK(fresh("allow {\n" IN " protocol = tcp, icmp\n port = 22\n}\n") < 0 &&
	          says("port requires protocol tcp or udp"),
	      "a port with icmp among the protocols");
	CHECK(fresh("allow {\n" IN " protocol = tcp\n port = 0\n}\n") < 0 &&
	          fresh("allow {\n" IN " protocol = tcp\n port = 65536\n}\n") < 0 &&
	          says("invalid port: 65536"),
	      "ports 0 and 65536");
	CHECK(fresh("allow {\n" IN " protocol = tcp\n port = 100-99\n}\n") < 0 &&
	          says("invalid port range: 100-99"),
	      "a range that goes backwards");
	CHECK(fresh("allow {\n" IN " protocol = tcp\n port = 1-2-3\n}\n") < 0 &&
	          fresh("allow {\n" IN " protocol = tcp\n port = 1-\n}\n") < 0 &&
	          fresh("allow {\n" IN " protocol = tcp\n port = -5\n}\n") < 0 &&
	          fresh("allow {\n" IN " protocol = tcp\n port = ssh\n}\n") < 0 &&
	          fresh("allow {\n" IN " protocol = tcp\n port = 22,\n}\n") < 0 &&
	          fresh("allow {\n" IN " protocol = tcp\n port = +22\n}\n") < 0,
	      "broken ranges, names, empty elements and signs");
	CHECK(fresh("allow {\n" IN " protocol = tcp\n"
	            " port = 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16\n}\n") == 0 &&
	          fresh("allow {\n" IN " protocol = tcp\n"
	                " port = 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17\n}\n") <
	              0 &&
	          says("more than 16 ports or ranges"),
	      "sixteen ports fit, seventeen do not");
}

static void test_net(void) {
	CHECK(
	    fresh("allow {\n" IN " from = 192.168.1.0/24\n}\n") == 0 &&
	        rs.r[0].from.set && rs.r[0].from.addr == inet_addr("192.168.1.0") &&
	        rs.r[0].from.mask == inet_addr("255.255.255.0") && !rs.r[0].to.set,
	    "a network in from");
	CHECK(fresh("allow {\n direction = out\n to = 10.0.0.5\n}\n") == 0 &&
	          rs.r[0].to.addr == inet_addr("10.0.0.5") &&
	          rs.r[0].to.mask == 0xffffffffu,
	      "an address without prefix is a /32");
	CHECK(fresh("allow {\n" IN " from = 0.0.0.0/0\n}\n") == 0 &&
	          rs.r[0].from.set && rs.r[0].from.mask == 0,
	      "the whole of IPv4");
	CHECK(fresh("allow {\n" IN " from = 192.168.1.5/24\n}\n") < 0 &&
	          says("from has bits outside its prefix"),
	      "an address with bits outside its prefix");
	CHECK(fresh("allow {\n" IN " from = 192.168.1.0/33\n}\n") < 0 &&
	          says("invalid prefix in from"),
	      "a prefix of 33");
	CHECK(fresh("allow {\n" IN " from = 192.168.1/24\n}\n") < 0 &&
	          fresh("allow {\n" IN " from = fd00::1\n}\n") < 0 &&
	          fresh("allow {\n" IN " from = host.example\n}\n") < 0 &&
	          says("invalid address in from"),
	      "a short address, IPv6 and a name");
	CHECK(fresh("allow {\n" IN " from = 10.0.0.0/8\n to = 10.1.0.0/16\n}\n") ==
	              0 &&
	          rs.r[0].from.set && rs.r[0].to.set,
	      "from and to together");
}

static void test_expanded(void) {
	fresh("allow {\n" IN "}\n"
	      "allow {\n" IN " protocol = tcp, udp\n port = 1, 2, 3-4\n}\n"
	      "allow {\n" IN " protocol = tcp, udp, icmp\n}\n");
	CHECK(rules_expanded(&rs.r[0]) == 1 && rules_expanded(&rs.r[1]) == 6 &&
	          rules_expanded(&rs.r[2]) == 3,
	      "one kernel rule per protocol and port range");
}

int main(void) {
	test_default();
	test_structure();
	test_interface();
	test_protocol();
	test_port();
	test_net();
	test_expanded();
	return test_summary();
}
