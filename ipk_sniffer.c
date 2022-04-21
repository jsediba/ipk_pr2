#include "ipk_sniffer.h"

void print_interfaces()
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs = NULL;
    if (pcap_findalldevs(&devs, NULL) != 0)
    {
        fprintf(stderr, "%s\n", pcap_errbuf);
        exit(1);
    }

    pcap_if_t *tmp = devs;
    printf("Available devices:\n");
    while (tmp != NULL)
    {
        if (tmp->flags & PCAP_IF_RUNNING)
        {
            printf("\t%s\n", tmp->name);
        }
        tmp = tmp->next;
    }
    pcap_freealldevs(devs);
}

bool check_if_valid_interface(char *interface)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs = NULL;
    if (pcap_findalldevs(&devs, NULL) != 0)
    {
        fprintf(stderr, "%s\n", pcap_errbuf);
        exit(1);
    }

    bool found_matching = false;
    pcap_if_t *tmp = devs;
    while (tmp != NULL)
    {
        if (tmp->flags & PCAP_IF_RUNNING)
        {
            if (strcmp(tmp->name, interface) == 0)
            {
                found_matching = true;
                break;
            }
        }
        tmp = tmp->next;
    }
    pcap_freealldevs(devs);

    return found_matching;
}

void print_settings(sniffer_settings_t *settings)
{
    printf("all:\t%d\n", settings->all);
    printf("tcp:\t%d\n", settings->tcp);
    printf("udp:\t%d\n", settings->udp);
    printf("icmp:\t%d\n", settings->icmp);
    printf("arp:\t%d\n", settings->arp);
    printf("port:\t%ld\n", settings->port);
    printf("num:\t%ld\n", settings->num);
    printf("interface:\t%s\n", settings->interface);
}

void setup_sniffer_settings(sniffer_settings_t *settings)
{
    settings->all = true;
    settings->tcp = false;
    settings->udp = false;
    settings->icmp = false;
    settings->arp = false;
    settings->port = -1;
    settings->num = 1;
    settings->interface = NULL;
}

long check_if_valid_number(int argc, char **argv, int pos)
{
    if (pos >= argc - 1)
    {
        return -1;
    }

    char *endptr = NULL;
    long res = strtol(argv[pos + 1], &endptr, 10);
    if (*endptr != 0)
    {
        return -1;
    }

    return res;
}

void generate_filter_string(char *buffer, sniffer_settings_t *settings)
{
    char port_buffer[TMP_BUFFER_SIZE] = {0};

    if (settings->port != -1)
    {
        snprintf(port_buffer, TMP_BUFFER_SIZE, " and port %ld", settings->port);
    }

    if (!settings->all)
    {
        if (settings->tcp)
        {
            if (strlen(buffer) != 0)
            {
                strncat(buffer, " or ", FILTER_BUFFER_SIZE - strlen(buffer) - 1);
            }
            strncat(buffer, "(tcp", FILTER_BUFFER_SIZE - strlen(buffer) - 1);
            if (settings->port != -1)
            {
                strncat(buffer, port_buffer, FILTER_BUFFER_SIZE - strlen(buffer) - 1);
            }
            strncat(buffer, ")", FILTER_BUFFER_SIZE - strlen(buffer) - 1);
        }

        if (settings->udp)
        {
            if (strlen(buffer) != 0)
            {
                strncat(buffer, " or ", FILTER_BUFFER_SIZE - strlen(buffer) - 1);
            }
            strncat(buffer, "(udp", FILTER_BUFFER_SIZE - strlen(buffer) - 1);
            if (settings->port != -1)
            {
                strncat(buffer, port_buffer, FILTER_BUFFER_SIZE - strlen(buffer) - 1);
            }
            strncat(buffer, ")", FILTER_BUFFER_SIZE - strlen(buffer) - 1);
        }

        if (settings->icmp)
        {
            if (strlen(buffer) != 0)
            {
                strncat(buffer, " or ", FILTER_BUFFER_SIZE - strlen(buffer) - 1);
            }
            strncat(buffer, "icmp or icmp6", FILTER_BUFFER_SIZE - strlen(buffer) - 1);
        }

        if (settings->arp)
        {
            if (strlen(buffer) != 0)
            {
                strncat(buffer, " or ", FILTER_BUFFER_SIZE - strlen(buffer) - 1);
            }
            strncat(buffer, "arp", FILTER_BUFFER_SIZE - strlen(buffer) - 1);
        }
    }
    else
    {
        if (settings->port != -1)
        {
            snprintf(port_buffer, TMP_BUFFER_SIZE, "port %ld", settings->port);
            strncat(buffer, port_buffer, FILTER_BUFFER_SIZE - strlen(buffer) - 1);
        }
    }
}

int parse_args(int argc, char **argv, sniffer_settings_t *settings)
{
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0)
        {
            settings->all = false;
            settings->tcp = true;
        }
        else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0)
        {
            settings->all = false;
            settings->udp = true;
        }
        else if (strcmp(argv[i], "--icmp") == 0)
        {
            settings->all = false;
            settings->icmp = true;
        }
        else if (strcmp(argv[i], "--arp") == 0)
        {
            settings->all = false;
            settings->arp = true;
        }
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0)
        {
            if (i == argc - 1)
            {
                print_interfaces();
                return -2;
            }

            settings->interface = argv[i + 1];
            i++;

            if (!check_if_valid_interface(settings->interface))
            {
                fprintf(stderr, "Incorrect interface selected.\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "-p") == 0)
        {
            long res = check_if_valid_number(argc, argv, i);
            if (res < 0 || res > 65535)
            {
                fprintf(stderr, "Invalid port number, the number has to be in range 0 to 65535.\n");
                return -1;
            }
            settings->port = res;
            i++;
        }
        else if (strcmp(argv[i], "-n") == 0)
        {
            long res = check_if_valid_number(argc, argv, i);
            if (res < 0)
            {
                fprintf(stderr, "Invalid number of packets selected.\n");
                return -1;
            }
            settings->num = res;
            i++;
        }
        else
        {
            fprintf(stderr, "Unknown argument %s\n", argv[i]);
            return -1;
        }
    }

    if (settings->interface == NULL)
    {
        print_interfaces();
        return -2;
    }
    return 0;
}

void print_timestamp(struct pcap_pkthdr *header)
{
    char timestamp_1[2 * TMP_BUFFER_SIZE] = {0};
    char timestamp_2[TMP_BUFFER_SIZE] = {0};
    char timestamp_2_str[TMP_BUFFER_SIZE] = {0};
    char timestamp_3[TMP_BUFFER_SIZE] = {0};

    struct tm *packet_time;

    packet_time = localtime(&(header->ts.tv_sec));
    strftime(timestamp_1, TMP_BUFFER_SIZE - 1, "%FT%T", packet_time);
    snprintf(timestamp_2, TMP_BUFFER_SIZE - 1, ".%.3ld", header->ts.tv_usec);
    snprintf(timestamp_2_str, TMP_BUFFER_SIZE - 1, "%.4s", timestamp_2);
    strftime(timestamp_3, TMP_BUFFER_SIZE - 1, "%z", packet_time);

    strncat(timestamp_1, timestamp_2_str, TMP_BUFFER_SIZE - strlen(timestamp_1) - 1);
    strncat(timestamp_1, timestamp_3, TMP_BUFFER_SIZE - strlen(timestamp_1) - 1);
    printf("timestamp: %s\n", timestamp_1);
}

void print_macs(struct ether_header *eth_hdr)
{
    printf("src MAC: ");
    for (int i = 0; i <= 5; i++)
    {
        printf("%02x", eth_hdr->ether_shost[i]);
        if (i != 5)
        {
            printf(":");
        }
    }
    printf("\n");

    printf("dst MAC: ");
    for (int i = 0; i <= 5; i++)
    {
        printf("%02x", eth_hdr->ether_dhost[i]);
        if (i != 5)
        {
            printf(":");
        }
    }
    printf("\n");
}

void print_packet(const unsigned char *packet, struct pcap_pkthdr *pkt_hdr)
{
    char buffer[TMP_BUFFER_SIZE] = {0};
    for (bpf_u_int32 i = 0; i < pkt_hdr->caplen; i++)
    {
        printf("%02x ", packet[i]);

        if (!isprint(packet[i]))
        {
            buffer[i % 8] = '.';
        }
        else
        {
            buffer[i % 8] = packet[i];
        }

        if (i % 8 == 7)
        {
            printf("\t%s\n", buffer);
        }
    }
    if(pkt_hdr->caplen%8 != 0){
        buffer[pkt_hdr->caplen%8] = 0;
        for(bpf_u_int32 i = 0; i< 8 - pkt_hdr->caplen%8; i++){
            printf("   ");
        }
        printf("\t%s\n", buffer);
    }}

int handle_ipv6(const unsigned char *packet)
{
    struct ip6_hdr *ipv6_hdr;
    ipv6_hdr = (struct ip6_hdr *)packet + sizeof(struct ether_header);

    switch (ipv6_hdr->ip6_nxt)
    {
    case IPPROTO_TCP:
        struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        handle_tcp(packet, tcp_hdr);
        break;
    case IPPROTO_UDP:
        struct udphdr *udp_hdr;
        udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        handle_udp(packet, udp_hdr);
        break;
    case IPPROTO_ICMPV6:
        handle_icmpv6(packet, ipv6_hdr);
        break;
    default:
        printf("Unsupported IPv6 protocol: %d\n", ipv6_hdr->ip6_nxt);
    }
    return 0;
}

int handle_ipv4(const unsigned char *packet)
{
    struct iphdr *ip_hdr;
    ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

    switch (ip_hdr->protocol)
    {
    case IPPROTO_TCP:
        struct tcphdr *tcp_hdr;
        tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        handle_tcp(packet, tcp_hdr);
        break;
    case IPPROTO_UDP:
        struct udphdr *udp_hdr;
        udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        handle_udp(packet, udp_hdr);
        break;
    case IPPROTO_ICMP:
        handle_icmpv4(packet, ip_hdr);
        break;
    default:
        printf("Unsupported IPv4 protocol: %d\n", ip_hdr->protocol);
    }
    return 0;
}

int handle_arp(const unsigned char *packet, struct ether_header *eth_hdr)
{
    (void)packet;
    (void)eth_hdr;
    printf("ARP\n");
    return 0;
}

int handle_tcp(const unsigned char *packet, struct tcphdr *tcp_hdr)
{
    (void)packet;
    (void)tcp_hdr;
    printf("TCP\n");
    return 0;
}
int handle_udp(const unsigned char *packet, struct udphdr *udp_hdr)
{
    (void)packet;
    (void)udp_hdr;
    printf("UDP\n");
    return 0;
}

int handle_icmpv4(const unsigned char *packet, struct iphdr *ip_hdr)
{
    (void)packet;
    (void)ip_hdr;
    printf("ICMPv4\n");
    return 0;
}

int handle_icmpv6(const unsigned char *packet, struct ip6_hdr *ip6_hdr)
{
    (void)packet;
    (void)ip6_hdr;
    printf("ICMPv6\n");
    return 0;
}

int sniff_packets(sniffer_settings_t *settings, char *filter)
{
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program compiled_filter;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(settings->interface, &net, &mask, pcap_error_buffer) == -1)
    {
        fprintf(stderr, "Cannot get net-mask for device %s\n", settings->interface);
        net = 0;
        mask = 0;
    }

    pcap_t *pcap_handle = pcap_open_live(settings->interface, BUFSIZ, 1, 1000, pcap_error_buffer);
    if (pcap_handle == NULL)
    {
        fprintf(stderr, "Error while opening device %s for sniffing: %s\n", settings->interface, pcap_error_buffer);
        return -1;
    }

    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s does not provide Ethernet headers.\n", settings->interface);
        pcap_close(pcap_handle);
        return -1;
    }

    if (pcap_compile(pcap_handle, &compiled_filter, filter, 0, net) == -1)
    {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter, pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return -1;
    }

    if (pcap_setfilter(pcap_handle, &compiled_filter) == -1)
    {
        fprintf(stderr, "Could not set filter %s: %s\n", filter, pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return (2);
    }

    long counter = 0;
    while (counter < settings->num)
    {

        counter++;
        const unsigned char *packet;
        struct pcap_pkthdr header;

        packet = pcap_next(pcap_handle, &header);

        print_timestamp(&header);

        struct ether_header *eth_hdr;
        eth_hdr = (struct ether_header *)packet;

        print_macs(eth_hdr);
        printf("frame length: %d bytes\n", header.len);
        switch (ntohs(eth_hdr->ether_type))
        {
        case ETHERTYPE_IPV6:
            handle_ipv6(packet);
            break;
        case ETHERTYPE_IP:
            handle_ipv4(packet);
            break;
        case ETHERTYPE_ARP:
            handle_arp(packet, eth_hdr);
            break;
        default:
            printf("Unsupported ether type: %d\n", ntohs(eth_hdr->ether_type));
        }

        /*
        switch (ntohs(eth_hdr->ether_type))
        {
        case ETHERTYPE_IPV6:
            struct ip6_hdr *ipv6_hdr;
            ipv6_hdr = (struct ip6_hdr *)packet+sizeof(struct ether_header);
            printf("ipv4\n");

            switch(ipv6_hdr->ip6_nxt){
                case IPPROTO_TCP:
                    //ipv6_hdr->ip6_dst

                    struct tcphdr *ipv6_tcphdr;
                    ipv6_tcphdr = (struct tcphdr *)packet+sizeof(struct ether_header)+sizeof(struct ip6_hdr)
                    break;
                default:
            }
            printf("ipv6\n");
            break;
        case ETHERTYPE_IP:
            struct iphdr *ip_hdr;
            ip_hdr = (struct iphdr *)packet+sizeof(struct ether_header);
            printf("ipv4\n");

            switch(ip_hdr->protocol){
                case IPPROTO_TCP:
                    break;
                default:
            }
            break;
        case ETHERTYPE_ARP:
            printf("arp\n");
            break;
        default:
            printf("trash\n");
        }
    */
        print_packet(packet, &header);
    }
    pcap_close(pcap_handle);
    return 0;
}

int main(int argc, char **argv)
{
    sniffer_settings_t settings;
    setup_sniffer_settings(&settings);
    int res = parse_args(argc, argv, &settings);
    if (res == -1)
    {
        return 1;
    }
    else if (res == -2)
    {
        return 0;
    }
    // print_settings(&settings);
    char filter[FILTER_BUFFER_SIZE] = {0};
    generate_filter_string(filter, &settings);
    // printf("%s\n", filter);

    res = sniff_packets(&settings, filter);

    return res;
}