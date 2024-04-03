plat.a: plat.o
	ar crs $@ $^

plat.o: plat-gnma.o gnma/gnma.full.a netlink/netlink.full.a
	# TODO(vb) get back to this
	gcc -r -nostdlib -o $@ $^

gnma/gnma.full.a:
	$(MAKE) -C $(dir $@) $(notdir $@)

netlink/netlink.full.a:
	$(MAKE) -C $(dir $@) $(notdir $@)

%.o: %.c
ifdef PLATFORM_REVISION
	gcc -c -g -o $@ ${CFLAGS} -I ./ -I ../../include -D PLATFORM_REVISION='"$(PLATFORM_REVISION)"' $^
else
	gcc -c -g -o $@ ${CFLAGS} -I ./ -I ../../include $^
endif
