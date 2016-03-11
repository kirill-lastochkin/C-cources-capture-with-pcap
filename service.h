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

void my_callback(u_char *user, const struct pcap_pkthdr* hdr, const u_char* packet);

void StartCap(char *fltr);
void EndCap(void);
void WorkCap(void);
