/*
 * iplink_vpls.c	VPLS device support
 *
 *              Author:	Amine Kherbouche <amine.kherbouche@6wind.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_link.h>
#include <arpa/inet.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"

static void print_explain(FILE *f)
{
	fprintf(f, "Usage: ... vpls id ID [ output LABEL ] [ input LABEL ]\n");
	fprintf(f, "                 [ ttl TTL ] [ via ADDR ][ dev PHYS_DEV ]\n");
	fprintf(f, "                 [ vlan ID ]\n");
	fprintf(f, "\n");
	fprintf(f, "Where: ID    := 0-16777215\n");
	fprintf(f, "       TTL   := { 1..255 | inherit }\n");
	fprintf(f, "       LABEL := 0-1048575\n");
}

static int vpls_parse_opt(struct link_util *lu, int argc, char **argv,
			  struct nlmsghdr *n)
{
	struct in6_addr via_addr6 = IN6ADDR_ANY_INIT;
	__u32 via_addr = 0;
	__u32 in_label = 0;
	__u32 out_label = 0;
	__u32 link = 0;
	__u32 id = 0;
	__u8 ttl = 0;
	__u8 vlanid = 0;

	while (argc > 0) {
		if (!matches(*argv, "id")) {
			NEXT_ARG();
			if (get_u32(&id, *argv, 0))
				invarg("invalid id", *argv);
			addattr32(n, 1024, IFLA_VPLS_ID, id);
		} else if (!matches(*argv, "via")) {
			NEXT_ARG();
			if (!inet_get_addr(*argv, &via_addr, &via_addr6)) {
				invarg("invalid address", *argv);
			}
		} else if (!matches(*argv, "vlan")) {
			NEXT_ARG();
			if (get_u8(&vlanid, *argv, 0))
				invarg("invalid vlan id", *argv);
			addattr8(n, 1024, IFLA_VPLS_VLANID, vlanid);
		} else if (!matches(*argv, "dev")) {
			NEXT_ARG();
			link = if_nametoindex(*argv);
			if (link == 0)
				invarg("invalid device", *argv);
			addattr32(n, 1024, IFLA_VPLS_OIF, link);
		} else if (!matches(*argv, "ttl") ||
			   !matches(*argv, "hoplimit")) {
			__u32 uval;

			NEXT_ARG();
			if (strcmp(*argv, "inherit") != 0) {
				if (get_unsigned(&uval, *argv, 0))
					invarg("invalid TTL", *argv);
				if (uval > 255)
					invarg("TTL must be <= 255", *argv);
				ttl = uval;
				addattr8(n, 1024, IFLA_VPLS_TTL, ttl);
			}
		} else if (!matches(*argv, "input")) {
			__u32 uval;

			NEXT_ARG();
			if (get_u32(&uval, *argv, 0) ||
			    (uval & ~LABEL_MAX_MASK))
				invarg("invalid input label", *argv);
			in_label = uval;
			addattr32(n, 1024, IFLA_VPLS_IN_LABEL, in_label);
		} else if (!matches(*argv, "output")) {
			__u32 uval;

			NEXT_ARG();
			if (get_u32(&uval, *argv, 0) ||
			    (uval & ~LABEL_MAX_MASK))
				invarg("invalid output label", *argv);
			out_label = uval;
			addattr32(n, 1024, IFLA_VPLS_OUT_LABEL, out_label);
		} else if (matches(*argv, "help") == 0) {
			print_explain(stderr);
			return -1;
		} else {
			fprintf(stderr, "vpls: unknown command \"%s\"?\n", *argv);
			print_explain(stderr);
			return -1;
		}
		argc--, argv++;
	}

	if (via_addr)
		addattr_l(n, 1024, IFLA_VPLS_NH, &via_addr, 4);
	else if (!IN6_IS_ADDR_UNSPECIFIED(&via_addr6))
		addattr_l(n, 1024, IFLA_VPLS_NH6, &via_addr6,
			  sizeof(struct in6_addr));

	return 0;
}

static void vpls_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	__u8 vlanid = 0;
	__u32 val = 0;
	__u32 id = 0;

	if (!tb)
		return;

	if (!tb[IFLA_VPLS_ID] ||
	    RTA_PAYLOAD(tb[IFLA_VPLS_ID]) < sizeof(__u32))
		return;
	id = rta_getattr_u32(tb[IFLA_VPLS_ID]);
	fprintf(f, "id %u ", id);


	if (tb[IFLA_VPLS_IN_LABEL]) {
		val = rta_getattr_u32(tb[IFLA_VPLS_IN_LABEL]);
		if (val)
			fprintf(f, "label in %u ", val);
	}

	if (tb[IFLA_VPLS_OUT_LABEL]) {
		val = rta_getattr_u32(tb[IFLA_VPLS_OUT_LABEL]);
		if (val)
			fprintf(f, "out %u ", val);
	}

	if (tb[IFLA_VPLS_VLANID]) {
		vlanid = rta_getattr_u8(tb[IFLA_VPLS_VLANID]);
		if (vlanid)
			fprintf(f, "vlan %u ", vlanid);
	}

	if (tb[IFLA_VPLS_NH]) {
		__be32 addr = rta_getattr_u32(tb[IFLA_VPLS_NH]);

		if (addr)
			fprintf(f, "via inet %s ",
				format_host(AF_INET, 4, &addr));
	} else if (tb[IFLA_VPLS_NH6]) {
		struct in6_addr addr;

		memcpy(&addr, RTA_DATA(tb[IFLA_VPLS_NH6]),
		       sizeof(struct in6_addr));
		if (!IN6_IS_ADDR_UNSPECIFIED(&addr))
			fprintf(f, "via inet6 %s ",
				format_host(AF_INET6, sizeof(struct in6_addr),
					    &addr));
	}

	if (tb[IFLA_VPLS_OIF]) {
		const char *n;
		__u32 link;
		char s[64];

		link = rta_getattr_u32(tb[IFLA_VPLS_OIF]);
		n = if_indextoname(link, s);

		if (n)
			fprintf(f, "dev %s ", n);
		else
			fprintf(f, "dev %u ", link);
	}

	if (tb[IFLA_VPLS_TTL]) {
		__u8 ttl = rta_getattr_u8(tb[IFLA_VPLS_TTL]);

		if (ttl)
			fprintf(f, "ttl %u ", ttl);
	}

}

static void vpls_print_help(struct link_util *lu, int argc, char **argv,
			    FILE *f)
{
	print_explain(f);
}

struct link_util vpls_link_util = {
	.id		= "vpls",
	.maxattr	= IFLA_VPLS_MAX,
	.parse_opt	= vpls_parse_opt,
	.print_opt	= vpls_print_opt,
	.print_help	= vpls_print_help,
};
