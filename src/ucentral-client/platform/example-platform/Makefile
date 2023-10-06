plat.a: plat-example.o
	ar crs $@ $^

%.o: %.c
	gcc -c -o $@ ${CFLAGS} -I ./ -I ../../include $^
