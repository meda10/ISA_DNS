//
// Created by petr on 4.10.18.
//
//#include <cstdint>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define ANS_ERROR 0
#define ANS_POINTER 1
#define ANS_NAME 2
#define T_A 1
#define T_NS 2
#define T_CNAME 5
#define T_SOA 6
#define T_MX 15
#define T_TXT 16
#define T_PTR 12
#define T_AAAA 28
#define T_DS 43
#define T_RRSIG 46
#define T_NSEC 47
#define T_DNSKEY 48
#define T_LOC 29
#define T_SSHFP 44

typedef struct param {
    long timeout;
    char* file;
    char* interface;
    char* syslog_server;
    int error;
} TParam;

#pragma pack(push)
#pragma pack(1)
struct DNS_HEADER { //12
    uint16_t id;

    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;

    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;

    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};
#pragma pack(pop)


#pragma pack(push)
#pragma pack(1)
struct DNS_LEN{ //2
    uint16_t len;
};
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
struct txt_len{ //2
    uint8_t txt_len;
};
#pragma pack(pop)

#pragma pack(push,1)
struct tcp_o {
    uint32_t	rt;
    uint32_t	drt;
    uint16_t	seq;
    uint16_t	ac;
};
#pragma pack(pop)

#pragma pack(push,1)
struct mx_preference {
    uint16_t	preference;
};
#pragma pack(pop)

#pragma pack(push,1)
struct dnskey {
    uint16_t	flags;
    uint8_t 	protocol;
    uint8_t 	algorithm;
};
#pragma pack(pop)

#pragma pack(push,1)
struct dns_nsec {
    uint16_t    len;
};
#pragma pack(pop)

#pragma pack(push,1)
struct dns_nsec_bitmp {
    unsigned char bit_8 :1;
    unsigned char bit_7 :1;
    unsigned char bit_6 :1;
    unsigned char bit_5 :1;
    unsigned char bit_4 :1;
    unsigned char bit_3 :1;
    unsigned char bit_2 :1;
    unsigned char bit_1 :1;
};
#pragma pack(pop)

#pragma pack(push,1)
struct dns_soa {
    uint32_t	serial;
    uint32_t	refresh;
    uint32_t	retry;
    uint32_t	expire;
    uint32_t	ttl;
};
#pragma pack(pop)

#pragma pack(push,1)
struct dns_rrsig {
    uint16_t	type_c;
    uint8_t     algorithm;
    uint8_t	    labels;
    uint32_t	original_ttl;
    uint32_t	sig_exp;
    uint32_t	sig_inc;
    uint16_t	tag;
};
#pragma pack(pop)

#pragma pack(push,1)
struct dns_ds {
    uint16_t	key_id;
    uint8_t     algorithm;
    uint8_t	    digest_type;
};
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
struct QUERY{
    unsigned short qtype;
    unsigned short qclass;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct R_DATA {
    unsigned short type;
    unsigned short _class;
    uint32_t ttl;
    unsigned short data_len;
};
#pragma pack(pop)