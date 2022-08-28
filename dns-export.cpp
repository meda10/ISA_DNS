#include <string>
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <cstdlib>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <cstring>
#include <cassert>
#include <getopt.h>
#include <sstream>
#include <bits/signum.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <ctime>
#include <chrono>
#include <climits>
#include <rpc/types.h>
#include <netinet/ip6.h>
#include "dns-export.h"
#include "base64.h"

#define NUM_PACKETS 1
using namespace std;

pcap_t *device_handle;
int arr_pos = 0;
int arr_len = 10;
string **array = new string*[arr_len];
string **temp;
unsigned int alarm_time = 10;
char *pac = NULL;
int pac_len = 0;
char* syslog = NULL;

/**
 * Zkontroluje argumenty programu a naplní strukturu TParam
 * @param argc - počet argumentů
 * @param argv - argumenty
 * @return - struktura s parametry
 */
TParam check_params(int argc, char *argv[]){
    TParam parametry;
    parametry.file = NULL;
    parametry.interface = NULL;
    parametry.syslog_server = NULL;
    parametry.timeout = 60;
    parametry.error = 0;

    int c;
    char *error;
    while ((c = getopt(argc, argv, "hr:i:s:t:")) != -1){
        switch (c){
            case 'r':
                parametry.file = optarg;
                break;
            case 'i':
                parametry.interface = optarg;
                break;
            case 's':
                parametry.syslog_server = optarg;
                break;
            case 'h':
                printf("--------------------------------------------\n"
                       "------------------  HELP  ------------------\n"
                       "Spuštění programu - vypsání nápovědy \n"
                       "./dns-export [-h] \n"
                       "\n"
                       "Spuštění programu - Normální spuštění \n"
                       "./dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]\n"
                       "\n"
                       "-r   - volitelný parametr,  zpracuje daný .pcap soubor\n"
                       "-i   - volitelný parametr, naslouchá na daném síťovém rozhraní a zpracovává DNS provoz\n"
                       "-s   - volitelný parametr, hostname/ipv4/ipv6 adresa syslog serveru\n"
                       "-t   - volitelný parametr, doba výpočtu statistik, výchozí hodnota 60s\n"
                       "--------------------------------------------\n"
                );
                exit(0);
                break;
            case 't':
                parametry.timeout = strtol(optarg, &error, 10);
                if(*error != '\0') {
                    fprintf(stderr, "Chyba v parametru t, neplatny znak  %s\n", error);
                    parametry.error = 1;
                }
                break;
            default:
                exit(0);
        }
    }

    if(parametry.file == NULL && parametry.interface == NULL){
        exit(0);
    }
    if(parametry.file != NULL && parametry.interface != NULL){
        fprintf(stderr, "Chyba: zadejte pouze parametr -i nebo -r  %s\n", error);
        exit(1);
    }
    return parametry;
}

/**
 * Link:  https://www.epochconverter.com/programming/c
 * Author: random_dude
 *
 * Konvertuje epoch timestamp na čas čitelý pro člověka
 * @param t - Epoch time
 * @return - čas
 */
string convert_time(uint32_t t){
    time_t time = (time_t)t;
    struct tm ts;
    char buf[80];

    ts = *localtime(&time);
    //strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ts);

    std::stringstream s;
    s << buf;
    std::string ret = s.str();
    return ret;
}

/**
 * Link: https://codereview.stackexchange.com/questions/11921/getting-current-time-with-milliseconds
 * Author: saeedn
 * Authors profile: https://codereview.stackexchange.com/users/8354/saeedn
 *
 * Vytvoří zprávu pro syslog server
 * @param msg - získané statistiky
 * @return - syslog zpráva
 */
std::string make_msg(string msg) {
    timeval curTime;
    gettimeofday(&curTime, NULL);
    int ms = curTime.tv_usec / 1000;

    char buffer [80];
    strftime(buffer, 80, "%Y-%m-%dT%H:%M:%S", localtime(&curTime.tv_sec));

    char currentTime[84] = "";
    sprintf(currentTime, "%s:%dZ", buffer, ms);
    std::string time = currentTime;

    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);
    std::string s = "1 ";

    return "<134>" + s + time + " " + hostname + " dns-export - - - " + msg.c_str();
}

/**
 * Pošle zprávu na syslog server - port 514
 * @param msg - zpráva
 * @param hostname - IPv4/IPv6/hostname syslog serveru
 */
void send_to_syslog(string msg, char* hostname) {
    int sock = 0;
    char ii[100];
    struct in_addr ip;
    struct in_addr **addr_l;
    struct sockaddr_in s_addr;
    struct hostent *host;

    if (inet_pton(AF_INET, hostname, &ip)) {
        if((sock = socket(AF_INET,SOCK_DGRAM,0)) <= 0){
            return;
        }
        bzero(&s_addr,sizeof(s_addr));
        s_addr.sin_family = AF_INET;
        s_addr.sin_port = htons(514);
        s_addr.sin_addr.s_addr=inet_addr(hostname);
    }else if (inet_pton(AF_INET6, hostname, &ip)) {
        if((sock = socket(AF_INET6,SOCK_DGRAM,0)) <= 0){
            return;
        }
        bzero(&s_addr,sizeof(s_addr));
        s_addr.sin_family = AF_INET6;
        s_addr.sin_addr.s_addr = inet_addr(hostname);
        s_addr.sin_port = htons(514);
    }else{
        sock = socket(AF_INET,SOCK_DGRAM,0);
        if((host = gethostbyname(hostname)) == NULL){
            return;
        }
        addr_l = (struct in_addr **) host->h_addr_list;
        for(int i = 0; addr_l[i] != NULL; i++){
            strcpy(ii,inet_ntoa(*addr_l[i]));
        }
        bzero(&s_addr,sizeof(s_addr));
        s_addr.sin_family = AF_INET;
        s_addr.sin_addr.s_addr = inet_addr(ii);
        s_addr.sin_port = htons(514);
    }
    sendto(sock,msg.c_str(),strlen(msg.c_str()),0, (struct sockaddr *)&s_addr,sizeof(s_addr));
    close (sock);
}

/**
 * Funkce na zpracování signálu
 * @param sig - signál
 */
void signal_handler(int sig){
    switch (sig) {
        case SIGALRM:
            alarm(alarm_time);
            //printf(">>>> TIMEOUT %d, send data to server %s\n", alarm_time, syslog);
            for (int i = 0; i < arr_pos; i++) {
                std::stringstream s;
                s << array[i][0] << " " << array[i][1];
                if(syslog != NULL){
                    send_to_syslog(make_msg(s.str()),syslog);
                }
                //std::cout << array[i][0] << " " << array[i][1] << endl;
            }
            break;
        case SIGUSR1:
            for (int i = 0; i < arr_pos; i++) {
                std::cout << array[i][0] << " " << array[i][1] << endl;
            }
            printf("\n");
            break;
    }
}

/**
 * Funkce na inicializaci pole
 */
void init(){
    for(int i = 0; i < arr_len; i++){
        array[i] = new string[2];
    }
}

/**
 * Funkce přidá statistiku do pole
 * @param s - statistika která se má přidat
 * @param pos - pokud se daná statistika v poli už nachází tak toto je její pozice
 */
void add_to_array(string s,int pos){
    if(arr_pos < arr_len){
        if(pos == -1){
            array[arr_pos][0] = s;
            array[arr_pos][1] = "1";
            arr_pos++;
        }else{
            array[pos][0] = s;
            int a = atoi(array[pos][1].c_str()) + 1;

            std::ostringstream stm ;
            stm << a ;
            stm.str();

            array[pos][1] = stm.str();
        }
    }else if(arr_pos == arr_len){
        temp = new string*[arr_len + 500];
        for(int i = 0; i < arr_len + 500; i++){
            temp[i] = new string[2];
        }

        for(int i = 0; i < arr_pos; i++){
            temp[i][0] = array[i][0];
            temp[i][1] = array[i][1];
        }

        for(int i = 0; i < arr_len; ++i) {
            delete [] array[i];
        }
        delete [] array;

        arr_len += 500;

        array = temp;

        if(pos == -1){
            array[arr_pos][0] = s;
            array[arr_pos][1] = "1";
            arr_pos++;
        }else{
            array[pos][0] = s;
            int a = atoi(array[pos][1].c_str()) + 1;

            std::ostringstream stm ;
            stm << a ;
            stm.str();

            array[pos][1] = stm.str();
        }
        //printf(">> %d\n",arr_len);
    }
}

/**
 * Zjistí zda se string nacházív poli
 * @param s - hledaný string
 * @return - při úspěchu vrací pozici jinak -1
 */
int find_in_arr(string s){
    for(int i = 0; i < arr_len; i++){
        int a = s.compare(array[i][0]);
        if(a == 0){
            return i;
        }
    }
    return -1;
}

/**
 * Čte DNS jména, pokud jméno obsahuje pointer tak funkce vrací kód ANS_POINTER a v promněné n je uložen pointer.
 * Pokud jméno pointern neobsahuje vrací ANS_NAME.
 * @param packet - paket ze kterého čteme
 * @param pos - pozice v paketu na které se momentálně nachází
 * @param len - délka paketu
 * @param code - podle kódu se pozná co semá dělat dál (ANS_POINTER,ANS_NAME,ANS_ERROR)
 * @param n - pokud jméno obsahuje pointer takten je uložen zde
 * @return - jméno
 */
char* read_rr(const uint8_t * packet, int *pos, int *len, int *code, int *n){
    char *name = NULL;
    int p = *pos;
    int name_len = 0;

    for(int i = p; i < *len + p; i++){
        uint8_t c = packet[i];
        //printf(">> %X > %c\n",c,c);
        if ((c & 0xc0) == 0xc0) {
            if(i == p){
                //name = (char*)malloc(1*sizeof(char)); //2
                i++;
                //name[0] = packet[i];
                *code = ANS_POINTER;
                *pos += 2;
                //printf("POS +2 (C0XX) == %d\n",*pos);
                *len = 2;
                int a = 0;

                switch (c){
                    case 193:
                        a = 256 + packet[i];
                        n[0] = a;
                        break;
                    case 194:
                        a = 512 + packet[i];
                        n[0] = a;
                        break;
                    case 195:
                        a = 768 + packet[i];
                        n[0] = a;
                        break;
                    case 196:
                        a = 1024 + packet[i];
                        n[0] = a;
                        break;
                    case 197:
                        a = 1280 + packet[i];
                        n[0] = a;
                        break;
                    case 198:
                        a = 1536 + packet[i];
                        n[0] = a;
                        break;
                    case 199:
                        a = 1792 + packet[i];
                        n[0] = a;
                        break;
                    case 200:
                        a = 2048 + packet[i];
                        n[0] = a;
                        break;
                    case 201:
                        a = 2304 + packet[i];
                        n[0] = a;
                        break;
                    case 202:
                        a = 2560 + packet[i];
                        n[0] = a;
                        break;
                    case 203:
                        a = 2816 + packet[i];
                        n[0] = a;
                        break;
                    case 204:
                        a = 3072 + packet[i];
                        n[0] = a;
                        break;
                    case 205:
                        a = 3328 + packet[i];
                        n[0] = a;
                        break;
                    case 206:
                        a = 3584 + packet[i];
                        n[0] = a;
                        break;
                    case 207:
                        a = 3840 + packet[i];
                        n[0] = a;
                        break;
                    default:
                        n[0] = packet[i];
                }
                return name;
            }
            if(i != p){

                name = (char*)malloc(sizeof(char)*name_len + 1);

                int position = 0;
                for(int j = 1; j < name_len; j++){
                    uint8_t c = packet[p+j];
                    if (c >= '!' && c <= '~' && c != '\\') {
                        name[position] = c;
                        //printf("<<< %c %X --> name[%d]=%c\n",c,c,position,name[position]);
                        position++;
                    } else {
                        if(j != 54){
                            if(j != 0){
                                name[position] = '.';
                                //printf("<<< %c %X --> name[%d]=%c\n",c,c,position,name[position]);
                                position++;
                            }
                        }
                    }
                }
                name[position] = '.';
                name[position+1] = '\0';

                *code = ANS_POINTER;
                *pos += 2 + i - p;
                //printf("POS +%d (C0XX)++ == %d\n",2 + i - p,*pos);
                *len = 2;

                i++;
                int a = 0;
                switch (c){
                    case 193:
                        a = 256 + packet[i];
                        n[0] = a;
                        break;
                    case 194:
                        a = 512 + packet[i];
                        n[0] = a;
                        break;
                    case 195:
                        a = 768 + packet[i];
                        n[0] = a;
                        break;
                    case 196:
                        a = 1024 + packet[i];
                        n[0] = a;
                        break;
                    case 197:
                        a = 1280 + packet[i];
                        n[0] = a;
                        break;
                    case 198:
                        a = 1536 + packet[i];
                        n[0] = a;
                        break;
                    case 199:
                        a = 1792 + packet[i];
                        n[0] = a;
                        break;
                    case 200:
                        a = 2048 + packet[i];
                        n[0] = a;
                        break;
                    case 201:
                        a = 2304 + packet[i];
                        n[0] = a;
                        break;
                    case 202:
                        a = 2560 + packet[i];
                        n[0] = a;
                        break;
                    case 203:
                        a = 2816 + packet[i];
                        n[0] = a;
                        break;
                    case 204:
                        a = 3072 + packet[i];
                        n[0] = a;
                        break;
                    case 205:
                        a = 3328 + packet[i];
                        n[0] = a;
                        break;
                    case 206:
                        a = 3584 + packet[i];
                        n[0] = a;
                        break;
                    case 207:
                        a = 3840 + packet[i];
                        n[0] = a;
                        break;
                    default:
                        n[0] = packet[i];
                }
                return name;
            }

        }
        if(c == 0){
            name_len++;
            if(name_len == 1){
                name = (char*)malloc(sizeof(char)*7);
                name[0] = '<';
                name[1] = 'R';
                name[2] = 'o';
                name[3] = 'o';
                name[4] = 't';
                name[5] = '>';
                name[6] = '\0';

                *code = ANS_NAME;
                *pos += name_len;
                *len = name_len;
                return name;
            }
            break;
        }else{
            name_len++;
        }
    }
    //printf(">>>>>>>>>>>%d\n",name_len);

    name = (char*)malloc(1 * sizeof(char) + (name_len * sizeof(char)));
    //name = (char*)malloc(150 * sizeof(char));

    int position = 0;
    for (int i = p; i < name_len + p; i++) {
        uint8_t c = packet[i];
        if (c >= '!' && c <= '~' && c != '\\') {
            if(i != p){
                name[position] = c;
                //printf("<<< %c %X --> name[%d]=%c\n",c,c,position,name[position]);
                position++;
            }
        } else {
            //if(i != 54){
                if(i != p){
                    name[position] = '.';
                    //printf("<<< %c %X --> name[%d]=%c\n",c,c,position,name[position]);
                    position++;
                }
            //}
        }
    }
    if(name_len > 2){
        name[name_len - 2] = '\0';
    }

    *code = ANS_NAME;
    *pos += name_len;
    *len = name_len;
    //printf("POS +%d (NAME LEN) == %d\n",name_len,*pos);
    return name;
}

/**
 * Spojí dohromady 2 stringy
 * @param s1 - string 1
 * @param s2 - string 2
 * @return - spojený string
 */
char* concat_c(const char *s1, const char *s2) {
    if(s1 != NULL && s2 != NULL){
        //size_t a = strlen(s1) + strlen(s2) + 1;
        char *result = (char*)malloc((strlen(s1) + strlen(s2) + 1) * sizeof(char));
        strcpy(result, s1);
        strcat(result, s2);
        return result;
    } else if(s1 != NULL){
        char *result = (char*)malloc((strlen(s1) + 1) * sizeof(char));
        strcpy(result, s1);
        return result;
    }else if(s2 != NULL){
        char *result = (char*)malloc((strlen(s2) + 1) * sizeof(char));
        strcpy(result, s1);
        return result;
    }else {
        return NULL;
    }
}

/**
 * Link: https://stackoverflow.com/questions/3381614/c-convert-string-to-hexadecimal-and-vice-versa
 * Author: fredoverflow
 * Authors profile: https://stackoverflow.com/users/252000/fredoverflow
 * Author: Abyx
 * Authors profile: https://stackoverflow.com/users/343443/abyx
 *
 * Převede na hexadecimílní tvar
 * @param s - string
 * @return - hexadecimální tvar
 */
string to_hex(string s){
    static const char* const lut = "0123456789ABCDEF";
    size_t len = s.length();
    std::string sig_out;
    sig_out.reserve(2 * len);
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = s[i];
        sig_out.push_back(lut[c >> 4]);
        sig_out.push_back(lut[c & 15]);
    }
    return sig_out;
}

/**
 * Vrací typ RR jako string
 * @param type - typ
 * @return typ
 */
string type(int type){
    std::string t;
    switch (type) {
        case T_A:
            t = "A";
            break;
        case T_NS:
            t = "NS";
            break;
        case T_CNAME:
            t = "CNAME";
            break;
        case T_SOA:
            t = "SOA";
            break;
        case T_MX:
            t = "MX";
            break;
        case T_AAAA:
            t = "AAAA";
            break;
        case T_DS:
            t = "DS";
            break;
        case T_RRSIG:
            t = "RRSIG";
            break;
        case T_NSEC:
            t = "NSEC";
            break;
        case T_DNSKEY:
            t = "DNSKEY";
            break;
        case T_LOC:
            t = "LOC";
            break;
        case T_SSHFP:
            t = "SSHFP";
            break;
        case T_TXT:
            t = "TXT";
    }
    return t;
}

/**
 * Používá se v DS. Vrací typ šifrování
 * @param type - typ
 * @return - typ šifrování
 */
string digest_type(int type){
    std::string t;
    switch (type) {
        case 0:
            t = "Reserved";
            break;
        case 1:
            t = "SHA-1";
            break;
        case 2:
            t = "SHA-256";
            break;
        case 3:
            t = "GOST R 34.11-94";
            break;
        case 4:
            t = "SHA-384";
            break;
    }
    return t;
}

/**
 * Typy algoritmů
 * @param type -typ
 * @return - algoritmus
 */
string type_algorythm(int type){
    std::string t;
    switch (type) {
        case 0:
            t = "Delete DS";
            break;
        case 1:
            t = "RSA/MD5";
            break;
        case 2:
            t = "Diffie-Hellman";
            break;
        case 3:
            t = "DSA/SHA1";
            break;
        case 5:
            t = "RSA/SHA1";
            break;
        case 6:
            t = "DSA-NSEC3-SHA1";
            break;
        case 7:
            t = "RSA/SHA1-NSEC3-SHA1";
            break;
        case 8:
            t = "RSA/SHA-256";
            break;
        case 10:
            t = "RSA/SHA-512";
            break;
        case 12:
            t = "GOST R 34.10-2001";
            break;
        case 13:
            t = "ECDSA Curve P-256 with SHA-256";
            break;
        case 14:
            t = "ECDSA Curve P-384 with SHA-384";
            break;
        case 15:
            t = "Ed25519";
            break;
        case 16:
            t = "Ed448";
            break;
        default:
            t = "Reserved";
            break;
    }
    return t;
}

/**
 * Parsuje daný paket, zjistí zda je to DNS paket pokud ano zapíše si statistiky
 * @param u - 0
 * @param h - hlavička pcap souboru
 * @param packet - paket
 */
void packetHandler(u_char *u, const struct pcap_pkthdr* h, const u_char* packet) {
    const struct ether_header* ethernet;
    struct ip* ip;
    struct ip6_hdr* ipv6;
    const struct tcphdr* tcp;
    const struct udphdr* udp;
    struct DNS_HEADER* dns;
    struct QUERY* query;
    struct R_DATA* r_data;
    struct dns_soa* soa;
    struct dns_nsec* nsec;
    struct dns_ds* ds;
    struct mx_preference* mx_p;
    struct txt_len* txt_l;
    struct dnskey* d_key;
    struct dns_rrsig* rrsig;
    struct tcp_o* tcp_o;
    struct DNS_LEN* l;
    int code;

    ethernet = (struct ether_header*)packet;
    if (ntohs(ethernet->ether_type) ==  ETHERTYPE_IP || ntohs(ethernet->ether_type) ==  ETHERTYPE_IPV6) {
        if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IP){
            ip = (struct ip*)(packet + sizeof(struct ether_header));
        }
        if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IPV6){
            ipv6 = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
            //printf("--> %d\n",ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
            ip = (struct ip*)(packet + sizeof(struct ether_header));
            ip->ip_p = ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        }

        int p = 0;

        if (ip->ip_p == IPPROTO_TCP) {
            if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IP){
                tcp = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                if(ntohs(static_cast<uint16_t>(tcp->source)) != 53 && ntohs(static_cast<uint16_t>(tcp->dest)) != 53){
                    return;
                }
                l = ((DNS_LEN*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct tcp_o)));
            } else{
                tcp = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
                if(ntohs(static_cast<uint16_t>(tcp->source)) != 53 && ntohs(static_cast<uint16_t>(tcp->dest)) != 53){
                    return;
                }
                l = ((DNS_LEN*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + sizeof(struct tcp_o)));
            }


            /*
            printf("TH SPORT > %d\n",ntohs(tcp->th_sport));
            printf("TH DPORT > %d\n",ntohs(tcp->th_dport));
            printf("TH SEQ > %X\n",ntohl(tcp->th_seq));
            printf("TH ACK > %X\n",ntohl(tcp->th_ack));
            printf("TH X2 > %d\n",tcp->th_x2);
            printf("TH OFF > %d\n",tcp->th_off);
            printf("TH FLAG > 0x%X\n",tcp->th_flags);
            printf("TH WIN > %d\n",ntohs(tcp->th_win));
            printf("TH SUM > %d\n",ntohs(tcp->th_sum));
            printf("TH URP > %d\n",tcp->th_urp);
            printf("-----\n");
            printf("SOURCE > %d\n",ntohs(tcp->source));
            printf("DEST > %d\n",ntohs(tcp->dest));
            printf("SEQ > %X\n",tcp->seq);
            printf("ACK SEQ > %X\n",ntohl(tcp->ack_seq));
            printf("-----\n");
            printf("RES1 > %X\n",tcp->res1);
            printf("DOFF > %d\n",tcp->doff);
            printf("FIN > %d\n",tcp->fin);
            printf("SYN > %d\n",tcp->syn);
            printf("RST > %d\n",tcp->rst);
            printf("PSH > %d\n",tcp->psh);
            printf("ACK > %d\n",tcp->ack);
            printf("URG > %d\n",tcp->urg);
            printf("RES2 > %d\n",tcp->res2);
            printf("-----\n");
            printf("URG PTR > %d\n",tcp->urg_ptr);
            printf("CHCEK > %d\n",ntohs(tcp->check));
            printf("WINDOW > %d\n",ntohs(tcp->window));
            printf("----------------------------------\n");
            */

            if(tcp->psh != 1){
                if(pac == NULL){
                    pac = (char*)malloc(((h->len - 66)) * sizeof(char));
                    memset(pac,0,h->len - 66);
                    memcpy(pac, &packet[66], (h->len - 66));
                    pac_len += h->len - 66;
                } else{
                    char *g;
                    g = pac;

                    char *result = (char*)malloc((pac_len + h->len - 66) * sizeof(char));
                    memset(result,0,pac_len + h->len - 66);
                    memcpy(result, &pac[0],pac_len);
                    memmove (result + pac_len,&packet[66], h->len - 66);

                    pac = result;
                    free(g);

                    pac_len += h->len - 66;
                }
                return;
            } else{
                char *g;
                g = pac;
                char *result = (char*)malloc((pac_len + h->len - 66) * sizeof(char));
                memset(result,0,pac_len + h->len - 66);
                memcpy(result, &pac[0],pac_len);
                memmove (result + pac_len,&packet[66], h->len - 66);

                pac = result;
                free(g);
                pac_len += h->len - 66;


                char *j;
                j = pac;
                char *r = (char*)malloc((pac_len + 66) * sizeof(char));
                memset(r,0,pac_len + 66);
                memcpy(r, &packet[0],66);
                memmove (r + 66, &pac[0], pac_len);

                pac = r;
                pac_len += 66;
                packet = (u_char*)pac;
                pac = NULL;
                pac_len = 0;
                free(j);
            }
            if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IP) {
                dns = ((DNS_HEADER *) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct tcp_o) + sizeof(struct DNS_LEN)));
                p = 80;
            } else{
                dns = ((DNS_HEADER *) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + sizeof(struct tcp_o) + sizeof(struct DNS_LEN)));
                p = 100;
            }
        }

        if (ip->ip_p == IPPROTO_UDP) {
            if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IP) {
                udp = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                if(ntohs(static_cast<uint16_t>(udp->dest)) != 53 && ntohs(static_cast<uint16_t>(udp->source)) != 53){
                    return;
                }
                dns = ((DNS_HEADER*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)));
                p = 54;
            } else{
                udp = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
                if(ntohs(static_cast<uint16_t>(udp->dest)) != 53 && ntohs(static_cast<uint16_t>(udp->source)) != 53){
                    return;
                }
                dns = ((DNS_HEADER*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr)));
                p = 74;
            }

        }

        if(ip->ip_p == IPPROTO_UDP || ip->ip_p == IPPROTO_TCP){
            /**
             * QUERY
             */
            int len;
            if(ntohs(dns->q_count) == 1){
                code = ANS_ERROR;
                if (ip->ip_p == IPPROTO_UDP) {
                    len = ntohs(udp->len) - 8 - 12;
                } else{
                    len = ntohs(l->len) - 12;
                }
                char *name = read_rr(packet,&p,&len,&code,NULL);
                query = ((QUERY*)(packet + sizeof(uint8_t)*p));
                p +=4;
                free(name);
            }else{
                return;
            }

            /**
             * RR
             */
            int r = ntohs(dns->ans_count) + ntohs(dns->auth_count) + ntohs(dns->add_count);
            if(r > 0 && r < 80){
                for(int i = 0; i < r; i++){

                    /**
                     * RR Name
                     */
                    char *name;
                    char *answer;
                    char *g;
                    char *old_name = (char*)malloc(sizeof(char));
                    int *n = (int*)malloc(sizeof(int));
                    code = ANS_ERROR;


                    if (ip->ip_p == IPPROTO_UDP) {
                        len = ntohs(udp->len) - 8 - 12;
                    } else{
                        len = ntohs(l->len) - 12;
                    }

                    old_name[0] = '\0';
                    name = read_rr(packet,&p,&len,&code,n);

                    while(code == ANS_POINTER){
                        int pos;
                        if (ip->ip_p == IPPROTO_UDP) {
                            len = ntohs(udp->len) - 8 - 12;
                            if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IP){
                                pos = 42 + n[0];
                            } else{
                                pos = 62 + n[0]; //v6 == 62
                            }
                        } else{
                            len = ntohs(l->len) - 12;
                            if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IP){
                                pos = 66 + n[0] + 2; //66 na zacatek dns paketu + 2 lenhth --> TCP
                            } else{
                                pos = 86 + n[0] + 2;
                            }
                        }

                        free(name);
                        name = read_rr(packet,&pos,&len,&code,n);
                        if(code == ANS_POINTER){
                            g = old_name;
                            old_name = concat_c(old_name,name);
                            free(g);
                        }
                    }

                    answer = concat_c(old_name,name);

                    /**
                     * RR Data
                     */
                    r_data = ((R_DATA*)(packet + sizeof(uint8_t)*p));
                    p +=10;
/*
                    printf("ANS : %s\n",answer);
                    printf("Class %d\n",ntohs(r_data->_class));
                    printf("Type %d\n",ntohs(r_data->type));
                    printf("TTL %d\n",ntohl(r_data->ttl));
                    printf("DATA len %d\n",ntohs(r_data->data_len));
*/

/**
                    std::string s = answer;
                    std::size_t found = s.find("..");
                    if (found!=std::string::npos){
                        return;
                    }
*/

                    char *rr_data = (char*)malloc(sizeof(char)*ntohs(r_data->data_len));

                    for(int j = 0; j < ntohs(r_data->data_len);j++) {
                        rr_data[j] = packet[j + p];
                    }

                    /**
                    * IPv4 address
                    */
                    if(ntohs(r_data->type) == T_A){
                        char str[INET_ADDRSTRLEN];
                        memset(&str,0, sizeof(str));
                        if (inet_ntop(AF_INET, rr_data, str, sizeof(str)) == NULL) {
                            fprintf(stderr, "Chyba priprevodu adresy\n");
                            exit(1);
                        }
                        p+= ntohs(r_data->data_len);
//                        printf("READ: %s\n", str);

                        //todo END -> A
                        std::stringstream s;
                        s << "" << answer << " "
                          << "A" << " "
                          << str;
                        std::string a_ans = s.str();
                        add_to_array(a_ans,find_in_arr(a_ans));
                    }

                    /**
                     * IPv6 address
                     */
                    if(ntohs(r_data->type) == T_AAAA){
                        char str[INET6_ADDRSTRLEN];
                        if (inet_ntop(AF_INET6, rr_data, str, sizeof(str)) == NULL) {
                            fprintf(stderr, "Chyba priprevodu adresy\n");
                            exit(1);
                        }
                        p+= ntohs(r_data->data_len);
//                        printf("READ: %s\n", str);

                        //todo END -> AAAA
                        std::stringstream s;
                        s << "" << answer << " "
                          << "AAAA" << " "
                          << str;
                        std::string aaaa_ans = s.str();
                        add_to_array(aaaa_ans,find_in_arr(aaaa_ans));
                    }

                    if(ntohs(r_data->type) == T_MX){
                        mx_p = (mx_preference*) (packet + sizeof(uint8_t) * p);
                        p += 2;
//                        printf("PREF: %d\n",ntohs(mx_p->preference));
                    }

                    if(ntohs(r_data->type) == T_RRSIG){
                        rrsig = ((dns_rrsig*)(packet + sizeof(uint8_t) * p));
                        p+=18;

                        /*
                        printf("TYPE: %d\n",ntohs(rrsig->type_c));
                        printf("ALG: %d\n",rrsig->algorithm);
                        printf("LABELS: %d\n",rrsig->labels);
                        printf("TTL: %d\n",ntohl(rrsig->original_ttl));
                        printf("TAG: %d\n",ntohs(rrsig->tag));
                        */
                    }

                    /**
                     * CNAME & SOA & NS & MX & NSEC & RRSIG
                     */
                    if(ntohs(r_data->type) == T_NSEC || ntohs(r_data->type) == T_RRSIG || ntohs(r_data->type) == T_SOA || ntohs(r_data->type) == T_CNAME || ntohs(r_data->type) == T_NS || ntohs(r_data->type) == T_MX){

                        code = ANS_ERROR;
                        char *name_n;
                        int p_old = p;
                        char *old_name_n = (char*)malloc(sizeof(char));
                        int *n_n = (int*)malloc(sizeof(int));
                        char *answer_n = NULL;
                        old_name_n[0] = '\0';

                        if (ip->ip_p == IPPROTO_UDP) {
                            len = ntohs(udp->len) - 8 - 12;
                        } else{
                            len = ntohs(l->len) - 12;
                        }

                        name_n = read_rr(packet,&p,&len,&code,n_n);

                        while(code == ANS_POINTER){
                            if(code == ANS_POINTER ){
                                g = old_name_n;
                                old_name_n = concat_c(old_name_n,name_n);
                                free(g);

                                //printf("OLD NAME IN>> %s\n",old_name_n);
                                //printf("NAME IN>> %s\n",name_n);
                            }

                            int pos;
                            if (ip->ip_p == IPPROTO_UDP) {
                                len = ntohs(udp->len) - 8 - 12;
                                if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IP){
                                    pos = 42 + n_n[0];
                                } else{
                                    pos = 62 + n_n[0];
                                }
                            } else{
                                len = ntohs(l->len) - 12;
                                if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IP){
                                    pos = 66 + n_n[0] + 2; //66 na zacatek dns paketu + 2 lenhth
                                } else{
                                    pos = 86 + n_n[0] + 2;
                                }
                            }
                            free(name_n);

                            name_n = read_rr(packet,&pos,&len,&code,n_n);
                            //printf("OLD NAME OUT>> %s\n",old_name_n);
                            //printf("NAME OUT>> %s\n",name_n);
                            //printf("CODE>> %d\n",code);
                            //printf("----------------\n");
                        }

                        answer_n = concat_c(old_name_n,name_n);

                        //printf("OLD_NAME_AA: %s\n", old_name_n);
                        //printf("NAME_AA: %s\n", name_n);
                        //printf("READ_RR: %s\n", rr_data);
                        //printf("POSSSSSSSSS_END %d\n", p);
//                        printf("READ_SN: %s\n", answer_n);

                        if(ntohs(r_data->type) == T_SOA ){
                            code = ANS_ERROR;
                            char *name_s;
                            char *old_name_s = (char*)malloc(sizeof(char));
                            int *n_s = (int*)malloc(sizeof(int));
                            char *answer_s = NULL;
                            old_name_s[0] = '\0';

                            if (ip->ip_p == IPPROTO_UDP) {
                                len = ntohs(udp->len) - 8 - 12;
                            } else{
                                len = ntohs(l->len) - 12;
                            }
                            name_s = read_rr(packet,&p,&len,&code,n_s);

                            while(code == ANS_POINTER){
                                if(code == ANS_POINTER ){
                                    g = old_name_s;
                                    old_name_s = concat_c(old_name_s,name_s);
                                    free(g);
                                }
                                int pos;
                                if (ip->ip_p == IPPROTO_UDP) {
                                    len = ntohs(udp->len) - 8 - 12;
                                    if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IP){
                                        pos = 42 + n_s[0];
                                    } else{
                                        pos = 62 + n_s[0];
                                    }
                                } else{
                                    len = ntohs(l->len) - 12;
                                    if(ntohs(ethernet->ether_type) ==  ETHERTYPE_IP){
                                        pos = 66 + n_s[0] + 2; //66 na zacatek dns paketu + 2 lenhth
                                    } else{
                                        pos = 86 + n_s[0] + 2;
                                    }
                                }
                                free(name_s);
                                name_s = read_rr(packet,&pos,&len,&code,n_s);
                            }

                            answer_s = concat_c(old_name_s,name_s);
                            soa = (dns_soa*) (packet + sizeof(uint8_t) * p);
                            p += 20;

                            std::stringstream s;
                            s << "" << answer << " "
                               <<"SOA" << " "
                               <<answer_n << " "
                               <<answer_s << " "
                               <<ntohl(soa->serial) << " "
                               <<ntohl(soa->refresh) << " "
                               <<ntohl(soa->retry) << " "
                               <<ntohl(soa->expire) << " "
                               <<ntohl(soa->ttl);
                            std::string soa_ans = s.str();
                            add_to_array(soa_ans,find_in_arr(soa_ans));

                            free(n_s);
                            free(name_s);
                            free(old_name_s);
                            free(answer_s);

                        }

                        if(ntohs(r_data->type) == T_NSEC){
                            nsec = ((dns_nsec*)(packet + sizeof(uint8_t) * p));
                            p+=2;

                            struct dns_nsec_bitmp *bitmap;
                            std::string map;

                            for(int i = 0; i < ntohs(nsec->len); i++){
                                bitmap = ((dns_nsec_bitmp*)(packet + sizeof(uint8_t) * p));
                                p+=1;
                                if(bitmap->bit_1){
                                    map += type(0 + i * 8) + " ";
                                }
                                if(bitmap->bit_2){
                                    map += type(1 + i * 8) + " ";
                                }
                                if(bitmap->bit_3){
                                    map += type(2 + i * 8) + " ";
                                }
                                if(bitmap->bit_4){
                                    map += type(3 + i * 8) + " ";
                                }
                                if(bitmap->bit_5){
                                    map += type(4 + i * 8) + " ";
                                }
                                if(bitmap->bit_6){
                                    map += type(5 + i * 8) + " ";
                                }
                                if(bitmap->bit_7){
                                    map += type(6 + i * 8) + " ";
                                }
                                if(bitmap->bit_8){
                                    map += type(7 + i * 8) + " ";
                                }
                            }

                            std::stringstream s;
                            s << "" << answer << " "
                              << "NSEC" << " "
                              << answer_n << " "
                              << map;
                            std::string ns_ans = s.str();
                            add_to_array(ns_ans,find_in_arr(ns_ans));
                        }

                        if(ntohs(r_data->type) == T_RRSIG){
                            int sig_len = ntohs(r_data->data_len) - (p - p_old + 18);
                            unsigned char *signature;
                            signature = (unsigned char*)malloc(sizeof(unsigned char)*sig_len);
                            memset(signature,0,(size_t)sig_len);
                            std::string str;
                            for(int o = 0; o < sig_len; o++){
                                signature[o] += packet[p + o];
                            }
                            str = base64_encode(signature,sig_len);
                            free(signature);

                            std::stringstream s;
                            s << answer << " "
                              <<"RRSIG" << " "
                              << type(ntohs(rrsig->type_c)) << " "
                              << type_algorythm(rrsig->algorithm) << " "
                              << (int)rrsig->labels << " "
                              << ntohl(rrsig->original_ttl) << " "
                              << convert_time(ntohl(rrsig->sig_exp)) << " "
                              << convert_time(ntohl(rrsig->sig_inc)) << " "
                              << ntohs(rrsig->tag) << " "
                              << answer_n << " "
                              << str;
                            std::string rrsig_ans = s.str();
                            add_to_array(rrsig_ans,find_in_arr(rrsig_ans));
                        }

                        p = p_old + ntohs(r_data->data_len);
                        if(ntohs(r_data->type) == T_MX){
                            p -= 2;
                        }
                        if(ntohs(r_data->type) == T_RRSIG){
                            p -= 18;
                        }
                        //TODO END -> MX CNAME NS

                        if(ntohs(r_data->type) == T_MX){
                            std::stringstream s;
                            s << "" << answer << " "
                              << "MX" << " "
                              << answer_n;
                            std::string mx_ans = s.str();
                            add_to_array(mx_ans,find_in_arr(mx_ans));
                        }

                        if(ntohs(r_data->type) == T_CNAME){
                            std::stringstream s;
                            s << "" << answer << " "
                              << "CNAME" << " "
                              << answer_n;
                            std::string cname_ans = s.str();
                            add_to_array(cname_ans,find_in_arr(cname_ans));
                        }

                        if(ntohs(r_data->type) == T_NS){
                            std::stringstream s;
                            s << "" << answer << " "
                              << "NS" << " "
                              << answer_n;
                            std::string ns_ans = s.str();
                            add_to_array(ns_ans,find_in_arr(ns_ans));
                        }

                        free(n_n);
                        free(name_n);
                        free(old_name_n);
                        free(answer_n);
                    }

                    if(ntohs(r_data->type) == T_TXT ){
                        txt_l = ((txt_len*)(packet + sizeof(uint8_t) * p));
                        p += 1;

                        std::string text;
                        for(int o = 0; o < txt_l->txt_len; o++){
                            text += packet[p + o];
                        }

                        std::stringstream s;
                        s << answer << " "
                          << "TXT" << " \""
                          << text << "\"";
                        std::string dnskey_ans = s.str();
                        add_to_array(dnskey_ans,find_in_arr(dnskey_ans));

                        p += ntohs(r_data->data_len) - 1;
                    }


                    /**
                     * DNSKEY
                     */
                    if(ntohs(r_data->type) == T_DNSKEY){
                        d_key = ((dnskey*)(packet + sizeof(uint8_t) * p));
                        p+=4;

                        int sig_len = ntohs(r_data->data_len) - 4;
                        unsigned char *signature;
                        signature = (unsigned char*)malloc(sizeof(unsigned char)*sig_len);
                        memset(signature,0,(size_t)sig_len);
                        std::string str;
                        for(int o = 0; o < sig_len; o++){
                            signature[o] += packet[p + o];
                        }
                        str = base64_encode(signature,sig_len);
                        free(signature);

                        std::stringstream s;
                        s << answer << " "
                          << "DNSKEY" << " "
                          << type_algorythm(d_key->algorithm) << " "
                          << (int)d_key->protocol << " "
                          <<  str;
                        std::string dnskey_ans = s.str();
                        add_to_array(dnskey_ans,find_in_arr(dnskey_ans));

                        p += ntohs(r_data->data_len) - 4;
                    }

                    /**
                     * DS
                     */
                    if(ntohs(r_data->type) == T_DS){
                        ds = ((dns_ds*)(packet + sizeof(uint8_t) * p));
                        p+=4;

                        int sig_len = ntohs(r_data->data_len) - 4;
                        std::string signature;
                        for(int o = 0; o < sig_len; o++){
                            signature += packet[p + o];
                        }

                        signature = to_hex(signature);
                        std::stringstream s;
                        s << answer << " "
                          << "DS" << " "
                          << "0x" << std::hex << ntohs(ds->key_id) << " "
                          << type_algorythm(ds->algorithm) << " "
                          << digest_type(ds->digest_type) << " "
                          << signature;
                        std::string rrsig_ans = s.str();

                        add_to_array(rrsig_ans,find_in_arr(rrsig_ans));

                        p += ntohs(r_data->data_len) - 4;

                    }

                    int type = ntohs(r_data->type);
                    if(type != T_TXT && type != T_DNSKEY && type != T_DS && type != T_NSEC && type != T_RRSIG && type != T_SOA && type != T_CNAME && type != T_NS && type != T_A && type != T_AAAA && type != T_MX){
                        p += ntohs(r_data->data_len);
                    }

                    //printf("-----------------------------------\n");
                    free(n);
                    free(name);
                    free(rr_data);
                    free(old_name);
                    free(answer);
                }
            }
            //printf("\n--------------------\n\n");
        }
    }
}

/**
 * Umožnuje naslouchání na daném rozhraní
 * @param interface - rozhraní na kterém chceme naslouhcat
 * @return - handle
 */
pcap_t* create_handle(char* interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(interface , BUFSIZ , 1 , 0 , errbuf);

    if (handle == NULL) {
        fprintf(stderr, "ERROR: Na rozhrani nelze naslouchat: %s\n", errbuf);
        exit(1);
    }
    return handle;
}

int main(int argc, char *argv[]) {

    TParam p = check_params(argc, argv);
    init();
    signal(SIGUSR1, signal_handler);
    syslog = p.syslog_server;
    alarm_time = p.timeout;

    if(p.interface != NULL){
        device_handle = create_handle(p.interface); //"wlp2s0"

        alarm(alarm_time);
        signal(SIGALRM, signal_handler);

        if (pcap_loop(device_handle, 0, packetHandler, NULL) < 0) {
            return 1;
        }
        pcap_close(device_handle);
    }

    if(p.file != NULL){
        pcap_t *file;
        char errbuf[PCAP_ERRBUF_SIZE];

        file = pcap_open_offline(p.file, errbuf);
        //file = pcap_open_offline("//home//petr//CLionProjects//ISA_Dns//pcap//ttt.pcap", errbuf);
        if (file == NULL) {
            cerr << "ERROR: Soubor nelze otevrit: " << errbuf << endl;
            return 1;
        }

        if (pcap_loop(file, 0, packetHandler, NULL) < 0) {
            return 1;
        }
        pcap_close(file);

        if(p.syslog_server != NULL){
            for (int i = 0; i < arr_pos; i++) {
                std::stringstream s;
                s << array[i][0] << " " << array[i][1];
                send_to_syslog(make_msg(s.str()),p.syslog_server);
            }

        }else{
            for(int i = 0; i < arr_pos; i++){
                std::cout << array[i][0] << " " << array[i][1] << endl;
            }
        }

    }

    for(int i = 0; i < arr_len; ++i) {
        delete [] array[i];
    }
    delete [] array;

    return 0;
}
