all: send_arp
send_arp: main.c
	gcc -o send_arp main.c -lpcap
clean:
	rm send_arp