
all:libtest.so runso

runso:
	gcc runso.c -ldl -o runso
libtest.so:lib.o
	gcc --shared lib.o -o libtest.so
lib.o:lib.c
	gcc -c -fPIC lib.c -o lib.o
test:
	./runso ./libtest.so tfunction
clean:
	rm -rf *.o runso libtest.so
