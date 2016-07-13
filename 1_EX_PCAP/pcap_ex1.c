#include <stdio.h>
#include <pcap.h>

// TODO : QT로 재구현 (GUI)

#define ETHER_ADDR_LEN 6
// Ethernet 헤더의 MAC 어드레스는 6바이트이다.
#define SIZE_ETHERNET 14
// Ethernet 헤더의 크기는 14바이트이다.


typedef bpf_u_int32 in_addr_t;
typedef struct in_addr
{
    in_addr_t s_addr;
}IN_ADDR;

// TODO : 왜 여기서 구조체 쓰는지 알아보기

typedef struct sniff_ethernet 
{
	u_char ether_dhost[ETHER_ADDR_LEN]; // Destination Host의 Mac Address
	u_char ether_shost[ETHER_ADDR_LEN]; // Source Host의 Mac Address
	u_short ether_type;					// Ethernet Type
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
		u_char ip_tos;		// 서비스 타입. 서비스의 우선 순위를 제공한다고 한다.
		u_short ip_len; 	// IP 패킷의 길이를 바이트 단위로 보여준다.
		u_short ip_id;		// Fragment Identifier로 단편화된 패킷을 결합하기 위한 식별정보를 저장하고 있다.
		u_short ip_off;		// Fragment offset으로 조각에 저장된 원래 데이터들을의 범위를 보여준다고 한다.
		u_char ip_ttl;		// Time-to-Live 데이터가 소멸하기 이전에 데이터가 이동 할 수 있는 단계의 수를 나타낸다.
		u_char ip_p;		// 상위 계층의 프로토콜을 검사한다. 우리는 TCP를 거를 것이므로 6이 아니면 다 거르면 될 것 같다.
		u_short ip_sum;		// 변조방지를 위해 IP 패킷의 체크섬을 저장한다.
		struct in_addr ip_src,ip_dst;	// 각각 출발지 IP 주소, 목적지 IP 주소

		#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)		// 헤더 길이를 구하는 매크로.
		#define IP_V(ip)		(((ip)->ip_vhl) >> 4)		// IP 버전을 구하는 매크로.
}SF_IP;



typedef u_int tcp_seq;

#define TH_FIN 0x01		// 데이터 전송 종료
#define TH_SYN 0x02		// 통신 시작 시 연결을 요청하고 ISN을 교환한다.
#define TH_RST 0x04		// 송신자가 유효하지 않은 연결을 시도할 때 거부하는 데에 사용하고,
						// 통신의 연결 및 종료를 정상적으로 할 수 없을 때 사용한다.
#define TH_PUSH 0x08	// 모든 데이터를 전송하고 마지막에 보내는 신호이다.
#define TH_ACK 0x10		// SYN에 대한 확인의 의미이다.
						// TODO : 3Way-Handshaking에 관해 연구
#define TH_URG 0x20		// Urgent Point 필드와 함께 사용되며 플래그 설정 시 TCP는 해당 세그먼트를
						// 전송 큐의 제일 앞으로 보낸다. 
#define TH_ECE 0x40		// 통신 혼잡 감지 시, 수신자가 ECE를 설정하여 송신자에게 알린다.
#define TH_CWR 0x80		// 송신자가 자신의 윈도우 사이즈를 줄임을 알린다.
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)	// 플래그 정의

typedef struct sniff_tcp 
{
	u_short th_sport;		// 소스 포트
	u_short th_dport;		// Destination 포트
	tcp_seq th_seq;			// Sequence Number. 세그먼트 데이터의 순서를 표기한다.
	tcp_seq th_ack;			// Acknowledge Number. Sequence Number의 확인 응답.
	u_char th_offx2;		// 예약된 데이터. 항상 0.

#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)		// 헤더 길이를 구해줌.
	
	u_char th_flags;		// Flag 데이터
	u_short th_win;			// 송신 시스템에서 자신이 수용하는 한 버퍼의 크기를 byte단위로 나타낸다.
	u_short th_sum;			// TCP 패킷 체크섬
	u_short th_urp;			// 긴급한 처리를 요구하는 Urgent 데이터의 마지막 byte의 일련번호
}SF_TCP;

void print_ips(unsigned int ipadd)
{
	u_short first = ipadd & 0x000000ff;
	u_short second = (ipadd & 0x0000ff00) >> 8;
	u_short third = (ipadd & 0x00ff0000) >> 16;
	u_short last = (ipadd & 0xff000000) >> 24;
	printf("SOURCE IP ADDRESS : %u.%u.%u.%u\n",first,second,third,last);
}

void print_ipd(unsigned int ipadd)
{
	u_short first = ipadd & 0x000000ff;
	u_short second = (ipadd & 0x0000ff00) >> 8;
	u_short third = (ipadd & 0x00ff0000) >> 16;
	u_short last = (ipadd & 0xff000000) >> 24;
	printf("DESTINATION IP ADDRESS : %u.%u.%u.%u\n",first,second,third,last);
}

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	// errbuf는 Exception log를 찍어준다.

	struct pcap_pkthdr header;
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	const u_char *packet;
	pcap_t *handle;

	dev = pcap_lookupdev(errbuf);

	// pcap_lookupdev는 pcap이 알아서 default device를
	// 잡아주는 함수인듯. 

    printf("Device: %s\n", dev);

	if (dev == NULL) 
    {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
	{
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	// pcap_open_live는 packet sniffing을 위해서 장치를 열어주는 함수이다.
	// 첫번째 파라메터인 dev는 대상 장치의 이름
	// 두번째 파라메터는 pcap에 의해 잡히는 패킷의 최대 용량을 이야기하며
	// 현재는 pcap.h에 정의된 BUFSIZ를 이용한다.
	// 세번쨰 파라메터는 True값을 주면 Promiscuous 모드로 진행을 한다는데,
	// 뭔지는 잘 모르겠으나, 회선에 연결된 모든 트래픽을 스니프한다는 모양임.
	// 네번째 파라메터는 패킷을 읽기 전에 요구되는 Delay를 주는 것 같다.
	// 다섯번째 파라메터는 위와 같은 errbuf이다. 

	// TODO : '장치를 연다' 것의 정확한 의미를 알아보기.
	// * 장치를 연다는 것, pcap_open_live()를 사용한다는 것은,
	//   Sniffing Session(컴퓨터 간의 활성화 된 접속)을 연다는 뜻이다.
	// TODO : Promiscuous Mode에 대한 추가 조사

	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}

	// 모든 패킷이 공격자가 받고자 하는 형태의 Link-Layer 헤더를 가지고 있지는 않기 때문에,
	// pcap_datalink()를 이용해서 걸러 줘야 함. 우리의 경우에는, Ethernet Device가 아니면
	// 걸러줘야 하므로, DLT_EN10MB를 사용. (이들 또한 헤더 파일에 정의되어 있는 모양)

	// TODO : Link-Layer Header Type에 대해서 조사하기.

	int wantmore = 1;

	// 무한루프를 돌리기 보다는 나중에 콜백함수로 돌리는 게 나을 것 같음. 나중에 GUI이식을 하게 될 경우 ClickEventListener로 처리를 해야 하는데,
	// 이러한 루프문은 하나도 도움이 안됨.

	while(1)
	{
		packet = pcap_next(handle, &header);

		const SF_ETHERNET *ethernet;
		const SF_IP *ip;
		const SF_TCP *tcp;
		const char *payload;

		u_int size_ip;
		u_int size_tcp;


		ethernet = (SF_ETHERNET*)(packet);

		if(ethernet->ether_type != 128)
			continue;
		// 위의 if 구문을 넣어주지 않으면 Segmentation Fault가 발생함. 아무래도 Ethernet Type이 IPV4가 아니면 아래의 포인터 할당이 전부 흐트러지는 듯.
		// Segmentation Fault 나기 전까지는 이런 필터를 넣을 필요 조차 못 느낌....

		ip = (SF_IP*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip)*4;
		tcp = (SF_TCP*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		
		// Payload 시작 위치를 정해주는 다른 방법이 있다고 들은거 같은데 기억 안남.

		if(ip->ip_p == 6)
		{
			printf("\n ----- CONNECTION DATA -----\n\n");
			printf("Ethernet Type : %u\n", ethernet->ether_type);
			printf("DESTINATION HOST MAC ADDRESS : [ %02X : %02X : %02X : %02X : %02X : %02X ] \n"
					,ethernet->ether_dhost[0]
					,ethernet->ether_dhost[1]
					,ethernet->ether_dhost[2]
					,ethernet->ether_dhost[3]
					,ethernet->ether_dhost[4]
					,ethernet->ether_dhost[5]);
			printf("SOURCE HOST MAC ADDRESS : [ %02X : %02X : %02X : %02X : %02X : %02X ] \n"
					,ethernet->ether_shost[0]
					,ethernet->ether_shost[1]
					,ethernet->ether_shost[2]
					,ethernet->ether_shost[3]
					,ethernet->ether_shost[4]
					,ethernet->ether_shost[5]);

			print_ips(ip->ip_src.s_addr);
			print_ipd(ip->ip_dst.s_addr);

			printf("SOURCE PORT : %u\n",tcp->th_sport);
			printf("DESTINATION PORT : %u\n",tcp->th_dport);

			printf("Protocol : %u\n\n", ip->ip_p);

			printf("\n ----- HEX DATA -----\n\n");
			for(int s = 0; s < header.len; s++)
			{	
				printf("%02X ",packet[s]);
				if((s+1)%10 == 0)
					printf("\n");
			}
			printf("\n\n ----- ASC II DATA -----\n\n");
			for (int i = 0; i < header.len; i++) 
			{
    			if (33 <= packet[i] && packet[i] <= 126) 
      				printf("%c", packet[i]);
				else 
      				printf(".");

				if((i+1)%20 == 0)
					printf("\n");
			}

			printf("\n\n ----- PAYLOAD  DATA -----\n\n");
			while(*payload != NULL)
			{
				printf("%c",*payload);
				payload++;
			}

			printf("\n");
		}
		else
			printf("Sorry, It's not TCP Packet. We cannot read it.\n");
	}

	pcap_close(handle); 

	return 0;
}