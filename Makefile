CC=gcc
CFLAGS=-Wall -Wextra -g

.PHONY: clean

ipk_sniffer : ipk_sniffer.c ipk_sniffer.h
	$(CC) $(CFLAGS) $^ -o $@ -lpcap


clean:
	rm ipk_sniffer