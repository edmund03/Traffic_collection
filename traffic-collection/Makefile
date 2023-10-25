all:config.o packet.o log.o util.o
	cp --path traffic/category.conf /etc/
	cp --path traffic/default.conf /etc/
	gcc -g -o packet_capture main.c config.o packet.o log.o util.o -lpcap
config.o:
	gcc -g -c config.c -o config.o  -lpcap
packet.o:
	gcc -g -c packet.c -o packet.o  -lpcap
log.o:
	gcc -g -c log.c -o log.o  -lpcap
util.o:
	gcc -g -c util.c -o util.o  -lpcap
clean:
	rm *.o packet_capture
install:
	cp packet_capture /usr/local/bin/
	chmod +x packet_capture
	cp packet-capture.service /usr/lib/systemd/system/
uninstall:
	rm /usr/local/bin/packet_capture
	rm /usr/lib/systemd/system/packet-capture.service