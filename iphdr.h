#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	uint8_t  header_len    :4;	
    uint8_t  version       :4;	
    uint8_t  tos;					 
    uint16_t total_length;		
    uint16_t id;					
    uint8_t  frag_offset   :5;	
    uint8_t  more_fragment :1;	
    uint8_t  dont_fragment :1;	
    uint8_t  reserved_zero :1;	
    uint8_t  frag_offset1;		
    uint8_t  ttl;					
    uint8_t  protocol;			
    uint16_t checksum;			
    Ip sip_;
    Ip tip_;

    Ip sip() { return ntohl(sip_); }
    Ip tip() { return ntohl(tip_); }
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)