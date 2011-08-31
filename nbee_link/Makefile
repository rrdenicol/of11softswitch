all:
	g++ -Wall -fPIC -c nbee_link.cpp
	g++ -shared -Wl,-soname,libnbeelink.so -Wl,--no-undefined -lnbee nbee_link.o ../lib/list_t.o -o libnbeelink.so     

clean:
	rm -f *.so
	rm -f *.o

rebuild: clean all
	
