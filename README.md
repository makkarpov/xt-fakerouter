xt_FAKEROUTER
=============

Kernel module and xtables add-on to emulate fake routers between your host and internet.

Usage: `ip6tables -I INPUT -d <addr> -j FAKEROUTER --router-count N`

N additional hops will be added. These hops will have address `addr` with least significant word replaced with hop index.
