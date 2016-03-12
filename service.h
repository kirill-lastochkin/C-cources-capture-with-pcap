#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <ctype.h>
#include <unistd.h>

#define IP 0x0800
#define ARP 0x0806
#define TCP 6
#define UDP 17
#define ICMP 1

extern char *optarg;
//extern int optind, opterr, optopt;

struct sniff_eth
{
    u_char eth_dhost[6];
    u_char eth_shost[6];
    short int eth_type;
} __attribute__((__packed__));

struct sniff_arp
{
    u_char htype[2];
    u_char ptype[2];
    u_char hlenl;
    u_char plen;
    u_char oper[2];
    u_char sha[4];
    u_char spa[4];
    u_char tha[4];
    u_char tpa[4];
} __attribute__((__packed__));

struct sniff_ip
{
    u_int ip_hl:4;
    u_int ip_v:4;
    u_char ToS;
    u_char len[2];
    u_char identifier[2];
    u_int flags:3;
    u_int offset:13;
    u_char ttl;
    u_char protocol;
    u_char cs[2];
    u_char ip_source[4];
    u_char ip_dest[4];
} __attribute__((__packed__));

struct sniff_udp
{
    u_char source_port[2];
    u_char dest_port[2];
    u_char len[2];
    u_char cs[2];
} __attribute__((__packed__));

struct sniff_tcp
{
    u_char source_port[2];
    u_char dest_port[2];
    u_char nseq[4];
    u_char nack[4];
    u_int reserved:4;
    u_int hdrlen:4;
    u_char flags;
    u_char winsize[2];
    u_char cs[2];
    u_char urgent[2];
    u_char options[4];
}__attribute__((__packed__));

void my_callback(u_char *user, const struct pcap_pkthdr* hdr, const u_char* packet);

void StartCap(char *fltr);
void EndCap(void);
void WorkCap(void);
