#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAC_ADDRSTRLEN 2*6+5+1
// #define ETHERTYPE_IP        0x0800    /* IP protocol */
// #define ETHERTYPE_ARP       0x0806    /* Addr. resolution protocol */
// #define ETHERTYPE_REVARP    0x8035    /* reverse Addr. resolution protocol */
// #define ETHERTYPE_IPV6      0x86dd    /* IPv6 */
// #define ETHERTYPE_LOOPBACK  0x9000    /* used to test interfaces */

char *ip_pair_sum_key[100000][2];
int ip_pair_sum[100000] = {0}, ip_pair_cnt = 0;

char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDRSTRLEN];

    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return str;
}

char *ip_ntoa(void *i, int type) {
    static char str[INET_ADDRSTRLEN];

    if (type == 4) {
        inet_ntop(AF_INET, i, str, sizeof(str));
    }
    else if (type == 6) {
        inet_ntop(AF_INET6, i, str, sizeof(str));
    }
    else {
        printf("IP ntop error: type = %d\n\n", type);
        exit(0);
    }

    return str;
}

void sum_ip_pairs(char *src, char *dst)
{
    int i, flag;
    for(i = 0; i < ip_pair_cnt; i++) {
        flag = 0;
        if (strcmp(src, ip_pair_sum_key[i][0]) == 0) {
            flag ++;
        }
        if (strcmp(dst, ip_pair_sum_key[i][1]) == 0) {
            flag ++;
        }
        if (flag == 2)  {
            break;
        }
    }

    if (flag == 2) {
        
        ip_pair_sum[i] ++;
    }
    else {
        // ip_pair_sum_key[ip_pair_cnt][0] = src;
        // ip_pair_sum_key[ip_pair_cnt][1] = dst;
        ip_pair_sum_key[ip_pair_cnt][0] = strdup(src);
        ip_pair_sum_key[ip_pair_cnt][1] = strdup(dst);
        ip_pair_cnt ++;
    }
}

void dump_tcp_udp(u_int32_t length, const u_char *content, int protocol_type)
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    char *protocol;
    u_int16_t source_port, destination_port;
    
    if (!protocol_type) {
        // TCP
        struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

        source_port = ntohs(tcp->th_sport);
        destination_port = ntohs(tcp->th_dport);
        protocol = "TCP";
    }
    else {
        // UDP
        struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

        source_port = ntohs(udp->uh_sport);
        destination_port = ntohs(udp->uh_dport);
        protocol = "UDP";
    }

    printf("| Protocol:                                      %s|\n", protocol);
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:                                 %5u|\n", source_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Destination Port:                            %5u|\n", destination_port);
    printf("+-------------------------+-------------------------+\n");
}

void dump_ip(u_int32_t length, const u_char *content, int type) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    u_char protocol = ip->ip_p;

    printf("| Source IP Address:                 %15s|\n",  ip_ntoa(&ip->ip_src, type));
    printf("+---------------------------------------------------+\n");
    printf("| Destination IP Address:            %15s|\n", ip_ntoa(&ip->ip_dst, type));
    printf("+---------------------------------------------------+\n");

    sum_ip_pairs(ip_ntoa(&ip->ip_src, type), ip_ntoa(&ip->ip_dst, type));

    switch (protocol) {
        case IPPROTO_UDP:
            //printf("Next is UDP\n");
            dump_tcp_udp(length, content, 1);
            break;

        case IPPROTO_TCP:
            //printf("Next is TCP\n");
            dump_tcp_udp(length, content, 0);
            break;

        case IPPROTO_ICMP:
            printf("Next is ICMP\n");
            break;

        default:
            printf("Next is %d\n", protocol);
            break;
    }
}

void dump_ethernet(u_int32_t length, const u_char *content) {
    struct ether_header *ethernet = (struct ether_header *)content;
    char dst_mac_addr[MAC_ADDRSTRLEN] = {};
    char src_mac_addr[MAC_ADDRSTRLEN] = {};
    u_int16_t type;

    //copy header
    strcpy(dst_mac_addr, mac_ntoa(ethernet->ether_dhost));
    strcpy(src_mac_addr, mac_ntoa(ethernet->ether_shost));
    type = ntohs(ethernet->ether_type);

    //print
    if(type <= 1500)
        printf("IEEE 802.3 Ethernet Frame:\n");
    else
        printf("Ethernet Frame:\n");

    printf("+-------------------------+-------------------------+\n");
    printf("| Destination MAC Address:         %17s|\n", dst_mac_addr);
    printf("+-------------------------+-------------------------+\n");
    printf("| Source MAC Address:              %17s|\n", src_mac_addr);
    printf("+-------------------------+-------------------------+\n");
    if (type < 1500)
        printf("| Length:                        %5u|\n", type);
    else
        printf("| Ethernet Type:                              0x%04x|\n", type);
    printf("+-------------------------+-------------------------+\n");

    switch (type) {

        case ETHERTYPE_IP:
            //printf("Next is IP\n");
            dump_ip(length, content, 4);
            break;

        case ETHERTYPE_IPV6:
            //printf("Next is IPv6\n");
            dump_ip(length, content, 6);
            break;

        default:
            printf("Next is %#06x", type);
            break;
    }

}

int main(int argc, char *argv[])
{
    pcap_t *handle;		                /* Session handle */
    char *dev;	                        /* Device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	    /* Error string */
    struct bpf_program fp;		        /* The compiled filter expression */
    char filter_exp[] = "port 23";	    /* The filter expression */
    bpf_u_int32 mask;		            /* The netmask of our sniffing device */
    bpf_u_int32 net;		            /* The IP of our sniffing device */
    struct pcap_pkthdr *header = NULL;	/* The header that pcap gives us */
	const u_char *packet = NULL;		/* The actual packet */
    char *filename = "target2.pcap";
    int i;

    /* 監聽dev封包 */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    if (argc == 1) {
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
    }
    else if (argc == 3) {
        // filename = argv[2];
        handle = pcap_open_offline(filename, errbuf);
        if(!handle) {
            fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
            return(2);
        }
    }
    else {
        fprintf(stderr, "parameters error\n");
        return (2);
    }

    /* Grab a packet */
    int ret;
    while(ret = pcap_next_ex(handle, &header, &packet) != -2) {
        if(ret == 1) {
            struct tm ltime;
            char timestr[26];
            time_t local_tv_sec;

            local_tv_sec = header->ts.tv_sec;
            ltime = *localtime(&local_tv_sec);
            strftime(timestr, 26, "%Y-%m-%d %H:%M:%S", &ltime);

            //print header
            printf("Time: %s.%.6d\n", timestr, (int)header->ts.tv_usec);
            printf("Length: %d bytes\n", header->len);
            printf("Capture length: %d bytes\n", header->caplen);
            
            //print packets
            // for(i = 0 ; i < header->caplen ; i++) {
            //     printf("%d ", packet[i]);
            // }

            // print ethernet packet
            dump_ethernet(header->caplen, packet);

            printf("\n\n");
        }
        else if(ret == 0) {
            printf("Timeout\n");
        }
        else if(ret == -1) {
            fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(handle));
        }
        else if(ret == -2) {
            printf("No more packet from file\n");
        }
    }
	pcap_close(handle);

    printf("IP PAIRS : \n");
    printf("+-------------------------+-------------------------+-------------------------+\n");
    for (i = 0; i < ip_pair_cnt; i++) {
        printf("| SRC IP: %16s| DST IP: %16s| sum: %19d|\n", ip_pair_sum_key[i][0], ip_pair_sum_key[i][1], ip_pair_sum[i]);
        printf("+-------------------------+-------------------------+-------------------------+\n");
    }
    return(0);
}