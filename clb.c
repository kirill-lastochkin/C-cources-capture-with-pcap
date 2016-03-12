#include "service.h"

pcap_t *dev;

//колбэк функция
//разбираем на заголовки
void my_callback(u_char *user, const struct pcap_pkthdr* hdr, const u_char* packet)
{
    static int cnt=1;
    u_int i;
    struct sniff_eth *eth;
    struct sniff_arp *arp;
    struct sniff_ip *ip;
    struct sniff_udp *udp;
    struct sniff_tcp *tcp;

    eth=(struct sniff_eth*)packet;

    printf("-----ETHERNET HEADER-----\n|src mac: ");
    for(i=0;i<5;i++)
    {
        printf("%x-",eth->eth_shost[i]);
    }
    printf("%x",eth->eth_shost[5]);
    printf("\n|dst mac: ");
    for(i=0;i<5;i++)
    {
        printf("%x-",eth->eth_dhost[i]);
    }
    printf("%x",eth->eth_dhost[5]);
    printf("\n|type %x\n",ntohs(eth->eth_type));
    if(ntohs(eth->eth_type)==ARP)
    {
        arp=(struct sniff_arp*)(packet+sizeof(struct sniff_eth));
        printf("--------ARP HEADER--------\n");
        printf("|ptype: %x%x\n|operation: %x%x\n",arp->ptype[0],arp->ptype[1],
                arp->oper[0],arp->oper[1]);
    }
    if(ntohs(eth->eth_type)==IP)
    {
        ip=(struct sniff_ip*)(packet+sizeof(struct sniff_eth));
        printf("--------IP HEADER--------\n");
        printf("|source ip: %d.%d.%d.%d\n|dest ip:%d.%d.%d.%d\n",ip->ip_source[0],
                ip->ip_source[1],ip->ip_source[2],ip->ip_source[3],ip->ip_dest[0],
                ip->ip_dest[1],ip->ip_dest[2],ip->ip_dest[3]);
        printf("|ttl=%d\n",ip->ttl);
        //printf("|test param = %x\n",ip->protocol);
        switch(ip->protocol)
        {
        case ICMP:
            printf("|icmp message caugt\n");
            break;
        case UDP:
            udp=(struct sniff_udp*)(packet+sizeof(struct sniff_eth)+sizeof(struct sniff_ip));
            printf("--------UDP HEADER----------\n");
            printf("|source port: %d\n|dest port: %d\n",ntohs(*((int*)udp->source_port)),
                   ntohs(*((int*)udp->dest_port)));
            for(i=sizeof(struct sniff_eth)+sizeof(struct sniff_ip)+sizeof(struct sniff_udp);i<hdr->len;i++)
            {
                if(isprint(packet[i]))
                {
                    printf("%c",packet[i]);
                }
                else
                {
                    printf(".");
                }
            }
            break;
        case TCP:
            tcp=(struct sniff_tcp*)(packet+sizeof(struct sniff_eth)+sizeof(struct sniff_ip));
            printf("--------TCP HEADER----------\n");
            printf("|source port: %d\n|dest port: %d\n",ntohs(*((int*)tcp->source_port)),
                   ntohs(*((int*)tcp->dest_port)));
            for(i=sizeof(struct sniff_eth)+sizeof(struct sniff_ip)+4*tcp->hdrlen;i<hdr->len;i++)
            {
                if(isprint(packet[i]))
                {
                    printf("%c",packet[i]);
                }
                else
                {
                    printf(".");
                }
            }
            break;
        }

    }
    printf("\n----------END-----------\n");
    if(cnt==NUM_OF_PACKETS_TO_CAPTURE) pcap_breakloop(dev);
    cnt++;
}

//старт рсар
void StartCap(char *fltr)
{
    char *dev1,err[PCAP_ERRBUF_SIZE];
    int chk;
    struct bpf_program filter;
    bpf_u_int32 msk,net;
    //находим устройство
    dev1 = pcap_lookupdev(err);
    if(dev1==NULL)
    {
        puts(err);
    }
    printf("chosen device: %s\n",dev1);
    dev=pcap_open_live(dev1,BUFSIZ,0,-1,err);
    if(dev==NULL)
    {
        puts(err);
    }
    //вытаскиваем данные о сети
    chk=pcap_lookupnet(dev1,&net,&msk,err);
    if(chk==-1)
    {
        puts(err);
    }
    //ставим фильтр
    chk=pcap_compile(dev,&filter,fltr,0,net);
    if(chk==-1)
    {
        puts("compile err");
    }
    chk=pcap_setfilter(dev,&filter);
}

void EndCap(void)
{
    pcap_close(dev);
}

void WorkCap(void)
{
    pcap_loop(dev,-1,my_callback,NULL);
}

