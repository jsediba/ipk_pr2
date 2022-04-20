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
                strncat(buffer, " or ", FILTER_BUFFER_SIZE - strlen(buffer));
            }
            strncat(buffer, "(tcp", FILTER_BUFFER_SIZE - strlen(buffer));
            if (settings->port != -1)
            {
                strncat(buffer, port_buffer, FILTER_BUFFER_SIZE - strlen(buffer));
            }
            strncat(buffer, ")", FILTER_BUFFER_SIZE - strlen(buffer));
        }

        if (settings->udp)
        {
            if (strlen(buffer) != 0)
            {
                strncat(buffer, " or ", FILTER_BUFFER_SIZE - strlen(buffer));
            }
            strncat(buffer, "(udp", FILTER_BUFFER_SIZE - strlen(buffer));
            if (settings->port != -1)
            {
                strncat(buffer, port_buffer, FILTER_BUFFER_SIZE - strlen(buffer));
            }
            strncat(buffer, ")", FILTER_BUFFER_SIZE - strlen(buffer));
        }

        if (settings->icmp)
        {
            if (strlen(buffer) != 0)
            {
                strncat(buffer, " or ", FILTER_BUFFER_SIZE - strlen(buffer));
            }
            strncat(buffer, "icmp or icmp6", FILTER_BUFFER_SIZE - strlen(buffer));
        }

        if (settings->arp)
        {
            if (strlen(buffer) != 0)
            {
                strncat(buffer, " or ", FILTER_BUFFER_SIZE - strlen(buffer));
            }
            strncat(buffer, "arp", FILTER_BUFFER_SIZE - strlen(buffer));
        }
    }
    else
    {
        if (settings->port != -1)
        {
            snprintf(port_buffer, TMP_BUFFER_SIZE, "port %ld", settings->port);
            strncat(buffer, port_buffer, FILTER_BUFFER_SIZE - strlen(buffer));
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

    pcap_t *pcap_handle = pcap_open_live(settings->interface, BUFSIZ, 0, 1000, pcap_error_buffer);
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

    struct pcap_pkthdr header;
    const unsigned char *packet;
    /* Grab a packet */
    packet = pcap_next(pcap_handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    pcap_close(pcap_handle);
    return (0);
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