/*
 * @Author: Jakub Šediba
 * @Date: 2022-04-12 13:42:49
 * @Last Modified by: Jakub Šediba
 * @Last Modified time: 2022-04-24 09:24:30
 */
#include "ipk_sniffer.h"

// pcap_handle and compiled filter need to be global for signal handling
pcap_t *pcap_handle = NULL;
struct bpf_program compiled_filter;

/**
 * @brief Function that handles SIGINT
 *
 */
void sigint_handler()
{
    if (pcap_handle != NULL)
    {
        pcap_close(pcap_handle);
    }

    pcap_freecode(&compiled_filter);
    fprintf(stderr, "Closing program after SIGINT.\n");
    exit(0);
}

/**
 * @brief Function that prints available running interfaces (devices)
 *
 */
void print_interfaces()
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs = NULL;

    // Get all devices
    if (pcap_findalldevs(&devs, NULL) != 0)
    {
        fprintf(stderr, "%s\n", pcap_errbuf);
        exit(1);
    }

    // Loop through the list of devices, printing them
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

/**
 * @brief Function for debugging, prints settings from arguments
 *
 * @param settings
 */
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

/**
 * @brief Function that sets up sniffer to default settings
 *
 * @param settings
 */
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

/**
 * @brief Function that checks if specified argument is long integer and returns it
 *
 * @param argc argument count
 * @param argv array of arguments
 * @param pos id if arguments that needs to be checked
 * @return long representation of the string in argument. -1 on error, non-negative on success.
 */
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

/**
 * @brief Function that generates the filter string
 *
 * @param buffer buffer in which the result will be stored
 * @param settings pointer to the settings structure
 */
void generate_filter_string(char *buffer, sniffer_settings_t *settings)
{
    // Temp buffer for adding specified port to UDP and TCP
    char port_buffer[TMP_BUFFER_SIZE] = {0};
    if (settings->port != -1)
    {
        snprintf(port_buffer, TMP_BUFFER_SIZE, " and port %ld", settings->port);
    }

    // Setup if at least one specific protocol was selected
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
    // If no specific protocol was selected
    else
    {
        // Add port to the filter string if it was set
        if (settings->port != -1)
        {
            snprintf(port_buffer, TMP_BUFFER_SIZE, "port %ld", settings->port);
            strncat(buffer, port_buffer, FILTER_BUFFER_SIZE - strlen(buffer) - 1);
        }
    }
}

/**
 * @brief Function that parses the arguments and fills settings struct
 *
 * @param argc argument count
 * @param argv array of arguments
 * @param settings pointer to the settings struct that should be filled
 * @return int 0 on success, -1 on error that should end the program with an error message, -2 when interface list should be printed.
 */
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

/**
 * @brief Function that prints a timestamp
 *
 * @param header pointer to a pcap packet header which contains the timestamp
 */
void print_timestamp(struct pcap_pkthdr *header)
{
    // Setup for buffers
    char timestamp_1[2 * TMP_BUFFER_SIZE] = {0};
    char timestamp_2[TMP_BUFFER_SIZE] = {0};
    char timestamp_2_str[TMP_BUFFER_SIZE] = {0};
    char timestamp_3[TMP_BUFFER_SIZE] = {0};

    // Converting timestamp to time struct
    struct tm *packet_time;
    packet_time = localtime(&(header->ts.tv_sec));

    // Fill in tmp buffers
    strftime(timestamp_1, TMP_BUFFER_SIZE - 1, "%FT%T", packet_time);
    snprintf(timestamp_2, TMP_BUFFER_SIZE - 1, ".%03ld", header->ts.tv_usec);
    strftime(timestamp_3, TMP_BUFFER_SIZE - 1, "%z", packet_time);

    // Turncate microseconds to 3 places
    snprintf(timestamp_2_str, TMP_BUFFER_SIZE - 1, "%.4s", timestamp_2);

    // Separate minutes from hours in offset by colon.
    int len = strlen(timestamp_3);
    timestamp_3[len] = timestamp_3[len - 1];
    timestamp_3[len - 1] = timestamp_3[len - 2];
    timestamp_3[len - 2] = ':';

    // Concat the strings and print the timestamp
    strncat(timestamp_1, timestamp_2_str, TMP_BUFFER_SIZE - strlen(timestamp_1) - 1);
    strncat(timestamp_1, timestamp_3, TMP_BUFFER_SIZE - strlen(timestamp_1) - 1);
    printf("timestamp: %s\n", timestamp_1);
}

/**
 * @brief Function that prints source and destination MAC addresses
 *
 * @param eth_hdr pointer to the ethernet header which contains the MAC addresses
 */
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

/**
 * @brief Function that prints source and destination IPv4 addresses
 *
 * @param ip_hdr pointer to the IP header which contains the IPv6 addresses
 */
void print_ipv4s(struct iphdr *ip_hdr)
{
    char buffer[BUFFER_SIZE] = {0};

    struct sockaddr_in source;
    source.sin_addr.s_addr = ip_hdr->saddr;

    struct sockaddr_in destination;
    destination.sin_addr.s_addr = ip_hdr->daddr;

    if (inet_ntop(AF_INET, &(source.sin_addr), buffer, sizeof(buffer)))
    {
        printf("src IP: %s\n", buffer);
    }
    else
    {
        printf("src IP: Error while parsing");
    }

    if (inet_ntop(AF_INET, &(destination.sin_addr), buffer, sizeof(buffer)))
    {
        printf("dst IP: %s\n", buffer);
    }
    else
    {
        printf("dst IP: Error while parsing");
    }
}

/**
 * @brief Function that prints the source and destination IPv6 addresses
 *
 * @param ip6_hdr pointer to the IPv6 header which contains the IPv6 addresses
 */
void print_ipv6s(struct ip6_hdr *ip6_hdr)
{
    char buffer[BUFFER_SIZE] = {0};
    struct sockaddr_in6 source;
    source.sin6_addr = ip6_hdr->ip6_src;
    if (inet_ntop(AF_INET6, &(source.sin6_addr), buffer, sizeof(buffer)))
    {
        printf("src IP: %s\n", buffer);
    }
    else
    {
        printf("src IP: Error while parsing");
    }

    struct sockaddr_in6 destination;
    destination.sin6_addr = ip6_hdr->ip6_dst;
    if (inet_ntop(AF_INET6, &(destination.sin6_addr), buffer, sizeof(buffer)))
    {
        printf("dst IP: %s\n", buffer);
    }
    else
    {
        printf("dst IP: Error while parsing");
    }
}

/**
 * @brief Function that prints IPv4 addresses from ARP header
 *
 * @param arp_hdr pointer to the ARP header
 */
void print_arp_ips(struct ether_arp *arp_hdr)
{
    char buffer[BUFFER_SIZE] = {0};
    if (inet_ntop(AF_INET, &(arp_hdr->arp_spa), buffer, sizeof(buffer)))
    {
        printf("src IP: %s\n", buffer);
    }
    else
    {
        printf("src IP: Error while parsing");
    }

    if (inet_ntop(AF_INET, &(arp_hdr->arp_tpa), buffer, sizeof(buffer)))
    {
        printf("dst IP: %s\n", buffer);
    }
    else
    {
        printf("src IP: Error while parsing");
    }
}

/**
 * @brief Function that prints the HEX and char representation of the packet
 *
 * @param packet pointer to the packet
 * @param pkt_hdr pointer to the packet header
 */
void print_packet(const unsigned char *packet, struct pcap_pkthdr *pkt_hdr)
{
    char buffer[TMP_BUFFER_SIZE] = {0};

    for (bpf_u_int32 i = 0; i < pkt_hdr->caplen; i++)
    {
        // print the position on the start of each row
        if (i % PACKET_PRINT_ROW == 0)
        {
            printf("0x%04x: ", i);
        }

        // Print the hex representation
        printf("%02x ", packet[i]);

        // Add the char representation to the buffer
        if (!isprint(packet[i]))
        {
            buffer[i % PACKET_PRINT_ROW] = '.';
        }
        else
        {
            buffer[i % PACKET_PRINT_ROW] = packet[i];
        }

        // At the end of a line, print the char representation from the buffer
        if (i % PACKET_PRINT_ROW == PACKET_PRINT_ROW - 1)
        {
            buffer[PACKET_PRINT_ROW] = 0;
            printf("\t%s\n", buffer);
        }
    }

    // Handle the padding for the last line if it was incomplete
    if (pkt_hdr->caplen % PACKET_PRINT_ROW != 0)
    {
        buffer[pkt_hdr->caplen % PACKET_PRINT_ROW] = 0;
        for (bpf_u_int32 i = 0; i < PACKET_PRINT_ROW - pkt_hdr->caplen % PACKET_PRINT_ROW; i++)
        {
            printf("   ");
        }
        printf("\t%s\n", buffer);
    }
}

/**
 * @brief Function that handles the IPv4 packets
 *
 * @param packet pointer to the packet
 */
void handle_ipv4(const unsigned char *packet)
{
    // Get ipv4 header
    struct iphdr *ip_hdr;
    ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

    print_ipv4s(ip_hdr);

    // Switch based on protocol
    switch (ip_hdr->protocol)
    {
    case IPPROTO_TCP:
        struct tcphdr *tcp_hdr;
        tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        handle_tcp(tcp_hdr);
        break;
    case IPPROTO_UDP:
        struct udphdr *udp_hdr;
        udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        handle_udp(udp_hdr);
        break;
    case IPPROTO_ICMP:
        struct icmphdr *icmp_hdr;
        icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        handle_icmp(icmp_hdr);
        break;
    default:
        printf("Unsupported IPv4 protocol: %u\n", ip_hdr->protocol);
    }
}

/**
 * @brief Functon that handles the IPv6 packets
 *
 * @param packet pointer to the packet
 */
void handle_ipv6(const unsigned char *packet)
{
    // Get ipv6 header
    struct ip6_hdr *ipv6_hdr;
    ipv6_hdr = (struct ip6_hdr *)packet + sizeof(struct ether_header);

    print_ipv6s(ipv6_hdr);

    // switch based on protocol
    switch (ipv6_hdr->ip6_nxt)
    {
    case IPPROTO_TCP:
        struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        handle_tcp(tcp_hdr);
        break;
    case IPPROTO_UDP:
        struct udphdr *udp_hdr;
        udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        handle_udp(udp_hdr);
        break;
    case IPPROTO_ICMPV6:
        struct icmphdr *icmp_hdr;
        icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        handle_icmp(icmp_hdr);
        break;
    default:
        printf("Unsupported IPv6 protocol: %u\n", ipv6_hdr->ip6_nxt);
    }
}

/**
 * @brief Function that handles the ARP packet
 *
 * @param packet pointer to the packet
 */
void handle_arp(const unsigned char *packet)
{
    // Get ARP header
    struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));

    // Print IPs
    print_arp_ips(arp_hdr);

    // Switch to print the type of the ARP packet
    switch ((unsigned int)(ntohs(arp_hdr->arp_op)))
    {
    case ARPOP_REQUEST:
        printf("type: ARP REQUEST\n");
        break;
    case ARPOP_REPLY:
        printf("type: ARP REPLY\n");
        break;
    default:
        printf("type: ARP %u\n", (unsigned int)(ntohs(arp_hdr->arp_op)));
    }
}

/**
 * @brief Function that handles TCP packets
 *
 * @param tcp_hdr pointer to the TCP header
 */
void handle_tcp(struct tcphdr *tcp_hdr)
{
    printf("type: TCP\n");
    printf("src port: %u\n", ntohs(tcp_hdr->source));
    printf("dst port : %u\n", ntohs(tcp_hdr->dest));
}

/**
 * @brief Function that handles UDP packets
 *
 * @param udp_hdr pointer to the UDP header
 */
void handle_udp(struct udphdr *udp_hdr)
{
    printf("type: UDP\n");
    printf("src port: %u\n", ntohs(udp_hdr->source));
    printf("dst port : %u\n", ntohs(udp_hdr->dest));
}

/**
 * @brief Function that handles the ICMP packet
 *
 * @param icmp_hdr pointer to the ICMP header
 */
void handle_icmp(struct icmphdr *icmp_hdr)
{
    // Switch to print the type of the packet
    switch ((unsigned int)(icmp_hdr->type))
    {
    case ICMP_ECHO:
        printf("type: ICMP ECHO\n");
        break;
    case ICMP_ECHOREPLY:
        printf("type: ICMP ECHO REPLY\n");
        break;
    default:
        printf("type: ICMP %u\n", (unsigned int)(icmp_hdr->type));
    }
}

/**
 * @brief Function that sets up pcap handle and opens it
 *        INSPIRED BY <https://www.tcpdump.org/pcap.html>
 * 
 * @param settings pointer to the settings struct
 * @param filter pointer to the filter string
 * @return int 0 on success, others on error
 */
int setup_pcap_handle(sniffer_settings_t *settings, char *filter)
{
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(settings->interface, &net, &mask, pcap_error_buffer) == -1)
    {
        fprintf(stderr, "Error in pcap_lookupnet - interface: %s\n", settings->interface);
        net = 0;
        mask = 0;
    }

    pcap_handle = pcap_open_live(settings->interface, BUFSIZ, 1, 1000, pcap_error_buffer);
    if (pcap_handle == NULL)
    {
        fprintf(stderr, "Error in pcap_open_live on device %s: %s\n", settings->interface, pcap_error_buffer);
        return 1;
    }

    if (pcap_compile(pcap_handle, &compiled_filter, filter, 0, net) == -1)
    {
        fprintf(stderr, "Error in pcap_compile with filter string '%s': %s\n", filter, pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return 1;
    }

    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s does not provide Ethernet headers.\n", settings->interface);
        pcap_close(pcap_handle);
        return 1;
    }

    if (pcap_setfilter(pcap_handle, &compiled_filter) == -1)
    {
        fprintf(stderr, "Error in pcap_setfilter with filter string '%s': %s\n", filter, pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return 1;
    }
    return 0;
}

/**
 * @brief Function that runs the sniffer
 *
 * @param settings pointer to the settings structure
 * @param filter pointer to the filter string
 * @return int 0 on success, others on error
 */
int sniff_packets(sniffer_settings_t *settings, char *filter)
{
    int res = setup_pcap_handle(settings, filter);
    if (res != 0)
    {
        return res;
    }

    // Loop to get the number of packets specified in settings
    long counter = 0;
    while (counter < settings->num)
    {

        counter++;

        const unsigned char *packet;
        struct pcap_pkthdr header;

        // Get packet
        packet = pcap_next(pcap_handle, &header);

        // Print timestamp
        print_timestamp(&header);

        // Get Ethernet header
        struct ether_header *eth_hdr;
        eth_hdr = (struct ether_header *)packet;

        // Print MACs and frame length
        print_macs(eth_hdr);
        printf("frame length: %u bytes\n", header.len);

        // Switch based on ether type to handle packets
        switch (ntohs(eth_hdr->ether_type))
        {
        case ETHERTYPE_IPV6:
            handle_ipv6(packet);
            break;
        case ETHERTYPE_IP:
            handle_ipv4(packet);
            break;
        case ETHERTYPE_ARP:
            handle_arp(packet);
            break;
        default:
            printf("Unsupported ether type: %u\n", ntohs(eth_hdr->ether_type));
        }

        // Print the packet
        printf("\n");
        print_packet(packet, &header);
        printf("\n");
    }

    // Close the pcap handle and free compiled filter
    pcap_close(pcap_handle);
    pcap_handle = NULL;
    pcap_freecode(&compiled_filter);
    return 0;
}

int main(int argc, char **argv)
{
    // Setup signal handler
    signal(SIGINT, sigint_handler);

    // Setup setings
    sniffer_settings_t settings;
    setup_sniffer_settings(&settings);

    // Parse arguments
    int res = parse_args(argc, argv, &settings);
    if (res == -1)
    {
        return 1;
    }
    else if (res == -2)
    {
        return 0;
    }

    // Setup filter
    char filter[FILTER_BUFFER_SIZE] = {0};
    generate_filter_string(filter, &settings);

    // Sniff packets
    int ret = sniff_packets(&settings, filter);

    return ret;
}