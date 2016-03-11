#include "service.h"

pcap_t *dev;

void my_callback(u_char *user, const struct pcap_pkthdr* hdr, const u_char* packet)
{
    int i;
    struct sniff_eth *eth;
    struct sniff_arp *arp;

    eth=(struct sniff_eth*)packet;

    printf("-----ETHERNET FRAME-----\n|src mac: ");
    for(i=0;i<6;i++)
    {
        printf("%x",eth->eth_shost[i]);
    }
    printf("\n|dst mac: ");
    for(i=0;i<6;i++)
    {
        printf("%x",eth->eth_dhost[i]);
    }
    printf("\n|type %x\n",ntohs(eth->eth_type));
    if(ntohs(eth->eth_type)==0x806)
    {
        arp=(struct sniff_arp*)(packet+sizeof(struct sniff_eth));
        printf("|ptype: %x%x\n|operation: %x%x\n",arp->ptype[0],arp->ptype[1],
                arp->oper[0],arp->oper[1]);
    }
    printf("------------------------\n");
}


void StartCap(char *fltr)
{
    char *dev1,err[PCAP_ERRBUF_SIZE];
    int chk;
    struct bpf_program filter;
    bpf_u_int32 msk,net;

    dev1 = pcap_lookupdev(err);
    if(dev1==NULL)
    {
        puts(err);
    }
    printf("chosen device: %s\n",dev1);
    dev=pcap_open_live(dev1,BUFSIZ,1,-1,err);
    if(dev==NULL)
    {
        puts(err);
    }

    chk=pcap_lookupnet(dev1,&net,&msk,err);
    if(chk==-1)
    {
        puts(err);
    }
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

