#include "service.h"

extern pcap_t *dev;

int main(int argc, char *argv[])
{
    int chk,flag=0;
    //вытаскиваем опции
    while((chk=getopt(argc,argv,"f:"))!=-1)
    {
        switch(chk)
        {
        case 'f': StartCap(optarg);
            flag=1;
            printf("filter is set: %s\n",optarg);
            break;
        case '?': printf("type -f option for filtering\n");return 0;
        }
    }
    //если фильты не были указаны, ловим все
    if(flag==0)
    {
        StartCap("");
        printf("no filtering\n");
    }
    WorkCap();
    EndCap();
    return 0;
}


