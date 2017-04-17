#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>

#include "fakert_info.h"

enum {
	O_ROUTER_COUNT
};

static struct xt_option_entry opts[] = {
	{ .name = "router-count", .id = O_ROUTER_COUNT, .type = XTTYPE_UINT8, .flags = XTOPT_PUT, XTOPT_POINTER(struct xt_fakert_info, router_count) },
	XTOPT_TABLEEND
};

static void help(void) {
	printf(
"FAKEROUTER target options:\n"
"--router-count N                specifies router count\n"
);
}

static void init(struct xt_entry_target *target) {
	struct xt_fakert_info *info = (struct xt_fakert_info *) target->data;
	info->router_count = 1;
}

static void parse(struct xt_option_call *cb) {
	struct xt_fakert_info *info = (struct xt_fakert_info *) cb->data;
	xtables_option_parse(cb);
}

static void print(const void *ip, const struct xt_entry_target *target, int numeric) {
	struct xt_fakert_info *info = (struct xt_fakert_info *) target->data;
	printf("router count: %d ", info->router_count);
}

static void save(const void *ip, const struct ipt_entry_target *target) {
	struct xt_fakert_info *info = (struct xt_fakert_info *) target->data;
	printf(" --router-count %d", info->router_count);
}

static
struct xtables_target fakerouter = {
	.next			= NULL,
	.name			= "FAKEROUTER",
	.version		= XTABLES_VERSION,
	.size			= XT_ALIGN(sizeof(struct xt_fakert_info)),
	.userspacesize	= sizeof(struct xt_fakert_info),
	.help			= help,
	.init			= init,
	.print			= print,
	.save			= save,
	.x6_parse		= parse,
	.x6_options		= opts,
};

void _init(void)
{
	xtables_register_target(&fakerouter);
}
