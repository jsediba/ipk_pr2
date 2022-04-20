#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#define FILTER_BUFFER_SIZE 512 
#define TMP_BUFFER_SIZE 64

typedef struct{
    bool all;
    bool tcp;
    bool udp;
    bool icmp;
    bool arp;
    long port;
    long num;
    char* interface;
} sniffer_settings_t;

void print_interfaces();
void print_settings(sniffer_settings_t *settings);
void generate_filter_string(char* buffer, sniffer_settings_t* settings);
long check_if_valid_number(int argc, char **argv, int pos);
bool check_if_valid_interface(char *interface);
void setup_sniffer_settings(sniffer_settings_t *settings);
int parse_args(int argc, char** argv, sniffer_settings_t *settings);

#endif