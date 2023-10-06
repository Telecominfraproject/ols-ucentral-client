plat.a: plat.o
	ar crs $@ $^

plat.o: plat-gnma.o gnma/gnma.full.a
	# TODO(vb) get back to this
	gcc -r -nostdlib -o $@ $^

gnma/gnma.full.a:
	$(MAKE) -C $(dir $@) $(notdir $@)

%.o: %.c
	gcc -c -o $@ ${CFLAGS} -I ./ -I ../../include $^
