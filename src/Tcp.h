#ifndef TCP_H
#define TCP_H

#include "IP.h"

#include <iostream>
#include <vector>
#include <functional>
#include <set>
#include <map>

struct TcpHeader : tcphdr {

    uint16_t getDestinationPort() {
        return ntohs(dest);
    }

    uint16_t getSourcePort() {
        return ntohs(source);
    }

};

extern IP *globalIP;

struct Socket {

//    static unsigned short csum(char *p,int nbytes)
//    {
//        unsigned short *ptr = (unsigned short *) p;

//        register long sum;
//        unsigned short oddbyte;
//        register short answer;

//        sum=0;
//        while(nbytes>1) {
//            sum+=*ptr++;
//            nbytes-=2;
//        }
//        if(nbytes==1) {
//            oddbyte=0;
//            *((u_char*)&oddbyte)=*(u_char*)ptr;
//            sum+=oddbyte;
//        }

//        sum = (sum>>16)+(sum & 0xffff);
//        sum = sum + (sum>>16);
//        answer=(short)~sum;

//        return(answer);
//    }

    static unsigned short csum(const char *buf, unsigned size) {
            unsigned long long sum = 0;
            const unsigned long long *b = (unsigned long long *) buf;

            unsigned t1, t2;
            unsigned short t3, t4;

            /* Main loop - 8 bytes at a time */
            while (size >= sizeof(unsigned long long))
            {
                    unsigned long long s = *b++;
                    sum += s;
                    if (sum < s) sum++;
                    size -= 8;
            }

            /* Handle tail less than 8-bytes long */
            buf = (const char *) b;
            if (size & 4)
            {
                    unsigned s = *(unsigned *)buf;
                    sum += s;
                    if (sum < s) sum++;
                    buf += 4;
            }

            if (size & 2)
            {
                    unsigned short s = *(unsigned short *) buf;
                    sum += s;
                    if (sum < s) sum++;
                    buf += 2;
            }

            if (size)
            {
                    unsigned char s = *(unsigned char *) buf;
                    sum += s;
                    if (sum < s) sum++;
            }

            /* Fold down to 16 bits */
            t1 = sum;
            t2 = sum >> 32;
            t1 += t2;
            if (t1 < t2) t1++;
            t3 = t1;
            t4 = t1 >> 16;
            t3 += t4;
            if (t3 < t4) t3++;

            return ~t3;
    }

    struct pseudo_header
    {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t tcp_length;
    };

    // no need for copies?
    static unsigned short getChecksum(tcphdr *tcpHeader, pseudo_header *info, char *data = nullptr, size_t length = 0) {




        char buf[sizeof(tcphdr) + sizeof(pseudo_header) + 1024];

        memcpy(buf + sizeof(pseudo_header), tcpHeader, sizeof(tcphdr));

        memcpy(buf, info, sizeof(pseudo_header));

        memcpy(buf + sizeof(pseudo_header) + sizeof(tcphdr), data, length);

        return csum(buf, sizeof(tcphdr) + sizeof(pseudo_header) + length);


    }


    static unsigned short getChecksum(iphdr *tcpHeader, pseudo_header *info, char *data = nullptr, size_t length = 0) {
        char buf[sizeof(iphdr) + sizeof(pseudo_header) + 1024];
        memcpy(buf + sizeof(pseudo_header), tcpHeader, sizeof(iphdr));
        memcpy(buf, info, sizeof(pseudo_header));

        memcpy(buf + sizeof(pseudo_header) + sizeof(pseudo_header), data, length);

        return csum(buf, sizeof(iphdr) + sizeof(pseudo_header) + length);
    }

    static void sendPacket(uint32_t hostSeq, uint32_t hostAck, uint32_t networkDestIp, uint32_t networkSourceIp, int hostDestPort,
                           int hostSourcePort, bool flagAck, bool flagSyn, bool flagFin, bool flagRst, char *data, size_t length) {

        IpHeader *ipHeader = globalIP->getIpPacketBuffer();
        memset(ipHeader, 0, sizeof(iphdr));

        ipHeader->ihl = 5;
        ipHeader->version = 4;
        ipHeader->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr) + length);
        ipHeader->id = htonl(54321);
        ipHeader->ttl = 255;
        ipHeader->protocol = IPPROTO_TCP;
        ipHeader->saddr = networkSourceIp;
        ipHeader->daddr = networkDestIp;
        ipHeader->check = csum((char *) ipHeader, sizeof(iphdr));

        TcpHeader *tcpHeader = (TcpHeader *) ipHeader->getData();
        memset(tcpHeader, 0, sizeof(tcphdr));

        tcpHeader->ack = flagAck;
        tcpHeader->syn = flagSyn;
        tcpHeader->fin = flagFin;
        tcpHeader->rst = flagRst;
        if (data) {
            tcpHeader->psh = true;
        }

        tcpHeader->ack_seq = htonl(hostAck);
        tcpHeader->seq = htonl(hostSeq);
        tcpHeader->source = htons(hostSourcePort);
        tcpHeader->dest = htons(hostDestPort);

        // todo
        tcpHeader->doff = 5; // 5 * 4 = 20 bytes
        tcpHeader->window = htons(43690); // flow control

        // properly calculate checksum for this header
        pseudo_header info;
        info.dest_address = networkDestIp;
        info.source_address = networkSourceIp;
        info.placeholder = 0;
        info.protocol = IPPROTO_TCP;
        info.tcp_length = htons(sizeof(tcphdr) + length);
        tcpHeader->check = getChecksum(tcpHeader, &info, data, length);

        // copy shit in
        memcpy(((char *) tcpHeader) + sizeof(tcphdr), data, length);
    }

    void send(char *data, size_t length) {
        sendPacket(hostSeq, hostAck, networkIp, networkDestinationIp, hostPort, 4000, true, false, false, false, data, length);
        hostSeq += length;
    }

    // RST (is this blocked by the kernel?)
    void terminate() {
        //sendPacket(hostSeq, hostAck, networkIp, 0, hostPort, 4000, false, false, false, true, nullptr, 0);
    }

    void *userData;

    // per socket data
    uint32_t networkIp; // this is THEIR IP!
    uint16_t hostPort; // this is THEIR port

    // this is OUR IP!
    uint32_t networkDestinationIp;

    uint32_t hostAck;
    uint32_t hostSeq;
};

struct Endpoint {
    uint32_t networkIp;
    uint16_t hostPort;

    uint32_t networkDestinationIp;
};

inline bool operator<(const Endpoint a, const Endpoint b) {

    union hasher {
        Endpoint ep;
        uint64_t i;
    };

    hasher aH;
    aH.i = 0;
    aH.ep = a;

    hasher bH;
    bH.i = 0;
    bH.ep = b;

    return aH.i < bH.i;

    //return a.hostPort < b.hostPort;
}

struct Tcp {
    std::set<uint32_t> inSynAckState;
    IP *ip;
    int port;

    Tcp(IP *ip, int port) :ip(ip), port(port) {
        globalIP = ip;
    }

    std::map<Endpoint, Socket *> sockets;

    void dispatch(IpHeader *ipHeader, TcpHeader *tcpHeader);

    void run() {
        while (true) {
            int messages = ip->fetchPackageBatch();
            for (int i = 0; i < messages; i++) {
                IpHeader *ipHeader = ip->getIpPacket(i);
                TcpHeader *tcpHeader = (TcpHeader *) ipHeader->getData();
                if (tcpHeader->getDestinationPort() == port) {
                    dispatch(ipHeader, tcpHeader);
                }
            }
            ip->releasePackageBatch();
        }
    }

    std::function<void(Socket *)> onconnection;
    std::function<void(Socket *, char *, size_t)> ondata;
    std::function<void(Socket *)> ondisconnection;

    void onConnection(std::function<void(Socket *)> f) {
        onconnection = f;
    }

    void onDisconnection(std::function<void(Socket *)> f) {
        ondisconnection = f;
    }

    void onData(std::function<void(Socket *, char *, size_t)> f) {
        ondata = f;
    }
};

#endif // TCP_H
