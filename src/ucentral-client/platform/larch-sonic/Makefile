plat.a: plat-larch.o
	ar crs $@ $^

%.o: %.cpp
	g++ -c -o $@ ${CFLAGS} -I ./ -I ../../include $^
