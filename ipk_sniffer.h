#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>
#include <ctype.h>


#define FILTER_BUFFER_SIZE 512 
#define BUFFER_SIZE 128
#define TMP_BUFFER_SIZE 64
#define PACKET_PRINT_ROW 16


// Struct for storing settings
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

void sigint_handler();

void print_interfaces();

void print_settings(sniffer_settings_t *settings);
void setup_sniffer_settings(sniffer_settings_t *settings);

long check_if_valid_number(int argc, char **argv, int pos);

void generate_filter_string(char* buffer, sniffer_settings_t* settings);

int parse_args(int argc, char** argv, sniffer_settings_t *settings);

void print_timestamp(struct pcap_pkthdr *header);
void print_macs(struct ether_header *eth_hdr);
void print_ipv4s(struct iphdr *ip_hdr);
void print_ipv6s(struct ip6_hdr *ip6_hdr);
void print_arp_ips(struct ether_arp *arp_hdr);

void print_packet(const unsigned char *packet, struct pcap_pkthdr *pkt_hdr);

void handle_ipv4(const unsigned char* packet);
void handle_ipv6(const unsigned char* packet);
void handle_arp(const unsigned char* packet);
void handle_tcp(struct tcphdr *tcp_hdr);
void handle_udp(struct udphdr *udp_hdr);
void handle_icmp(struct icmphdr *icmp_hdr);

int setup_pcap_handle(sniffer_settings_t *settings, char *filter);
int sniff_packets(sniffer_settings_t *settings, char *filter);

#endif