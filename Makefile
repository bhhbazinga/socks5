cc = gcc
flag = -Wall -g -std=c99
target = socks5
object = socks5.o buff.o
src = socks5.c buff.c

all : $(object)
	$(cc) $(flag) -o $(target) $(object)

socks5.o : socks5.c
	$(cc) $(flag) -c -o socks5.o socks5.c

buff.o : buff.c
	$(cc) $(flag) -c -o buff.o buff.c

.PHONY:	clean

clean:
	rm *.o $(target) core.* vgcore.*
