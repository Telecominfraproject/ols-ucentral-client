all: netlink.a

%.o: %.c
	gcc -c -o $@ ${CFLAGS} -I ./ -I/usr/include/libnl3 -lnl-3 -lnl-route-3 $<

netlink.a: netlink_common.o
	ar crs $@ $^

netlink.full.a: netlink.a
	ar crsT $@ $^
