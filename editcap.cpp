#include <iostream>
#include <map>
#include <string>
#include <ctime>
#include <cstdlib>
#include <iomanip>

//#define __USE_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
// #define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

extern "C" {
#include <pcap.h>
}

using namespace std;

#define PCAP_BUF_SIZE	1024
#define PCAP_SRC_FILE1	0

int icmpCount = 0;
int tcpCount = 0;
int udpCount = 0;
int g_num = 0;

struct rtp_hdr_ttt{
	unsigned version:2;			/* protocol version       */
	unsigned p:1;				/* padding flag           */
	unsigned x:1;				/* header extension flag  */
	unsigned cc:4;				/* CSRC count             */
	unsigned m:1;				/* marker bit             */
	unsigned pt:7;				/* payload type           */
	unsigned seq:16;			/* sequence number        */
	unsigned ts:32;				/* timestamp              */
	unsigned ssrc:32;			/* synchronization source */
} ;


int main(int argc, char **argv) {

    pcap_t *fp_pcap_t;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_dumper_t* out_pcap;
    std::map<int, int> data_map;
    //读取数据包
	struct pcap_pkthdr packet;
	const u_char *pktStr;
    char outprint[512];
    
    if(argc != 3) {
        std::cout << "usage: " <<  argv[0] << " filename, 3 parameters are required " <<  std::endl;     
        return -1;
    }

    fp_pcap_t = pcap_open_offline(argv[1], errbuf);
    if (fp_pcap_t == NULL) {
	    fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);

	    return 0;
    }
    out_pcap  = pcap_dump_open(fp_pcap_t, argv[2]);

    
    while (1)
    {
        pktStr=pcap_next(fp_pcap_t, &packet);
		if( NULL==pktStr )
		{
			cout << "pcap_next() return NULL " << endl;
			break;		
		}
		else
		{
            g_num++;
            const struct ether_header* ethernetHeader;
            const struct ip* ipHeader;
            const struct udphdr* udpHeader;
            const struct rtp_hdr_ttt* rtpHeader;
            char sourceIP[INET_ADDRSTRLEN];
            char destIP[INET_ADDRSTRLEN];
            u_int sourcePort, destPort, len, checkSum, rtpseq, rtpssrc;
            u_char *data;
            int dataLength = 0;
            ethernetHeader = (struct ether_header*)pktStr;
            
            ipHeader = (struct ip*)(pktStr + sizeof(struct ether_header) + PCAP_SRC_FILE1);
            inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
            
            sprintf(outprint, "sourceIP : %s, destIP : %s  ,ipHeader->ip_p:%d", sourceIP, destIP, ipHeader->ip_p);
            cout << outprint << endl;
            
            if (ipHeader->ip_p == IPPROTO_UDP) {
                udpCount = udpCount + 1;
                udpHeader = (struct udphdr*)(pktStr + sizeof(struct ether_header) + PCAP_SRC_FILE1 + sizeof(struct ip));
                sourcePort = ntohs(udpHeader->source);
                destPort = ntohs(udpHeader->dest);
                len = ntohs(udpHeader->len);
                checkSum = ntohs(udpHeader->check);
                dataLength = packet.len - (sizeof(struct ether_header) + PCAP_SRC_FILE1 + sizeof(struct ip) + sizeof(struct udphdr));
                
                rtpHeader = (struct rtp_hdr_ttt*)(pktStr + sizeof(struct ether_header) + PCAP_SRC_FILE1 + sizeof(struct ip)  + sizeof(struct udphdr) );
                rtpseq = ntohs(rtpHeader->seq);
                rtpssrc = htonl(rtpHeader->ssrc);
                sprintf(outprint, "sourcePort : %d, destPort : %d len:%d, check:0x%04x ,dataLength:%d, rtpseq:%d, rtpssrc:0x%08x---------", sourcePort, destPort, len, checkSum, dataLength, rtpseq, rtpssrc);
                cout << outprint << endl;
                
                if ( data_map.find(rtpseq) != data_map.end() && data_map[rtpseq] == rtpssrc )
                {
                    cout << "---------err find in map: " << rtpseq << " rtpssrc: " << rtpssrc << endl;
                }else{
                    data_map[rtpseq] = rtpssrc;
                    pcap_dump((u_char*)out_pcap, &packet, pktStr);
                    cout << "rtpseq : " << rtpseq << endl;
                }
        
            }
            cout << "g_num:" << g_num << endl;

        }
    }
    
    
    pcap_dump_flush(out_pcap);
    
    pcap_dump_close(out_pcap);

    pcap_close(fp_pcap_t);

    sprintf(outprint,"Protocol Summary: %d ICMP packets, %d TCP packets, %d UDP packets\n", icmpCount, tcpCount, udpCount);
    cout << outprint << endl;
    return 0;

}
