plat.a: plat-example.o
	ar crs $@ $^

%.o: %.c
ifdef PLATFORM_REVISION
	gcc -c -o $@ ${CFLAGS} -I ./ -I ../../include -D PLATFORM_REVISION='"$(PLATFORM_REVISION)"' $^
else
	gcc -c -o $@ ${CFLAGS} -I ./ -I ../../include $^
endif
