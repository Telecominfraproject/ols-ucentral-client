all: gnma.a

%.o: %.c
	gcc -c -o $@ ${CFLAGS} -I ./ -I../../../include -I../netlink $<

gnma.a: gnma_common.o
	ar crs $@ $^

gnmi/gnmi_c_connector.full.a:
	$(MAKE) -C $(dir $@) $(notdir $@)

gnma.full.a: gnma.a gnmi/gnmi_c_connector.full.a
	ar crsT $@ $^
