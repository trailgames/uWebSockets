#ifndef TCP_H
#define TCP_H

#include "IP.h"

#include <iostream>
#include <vector>
#include <functional>
#include <set>

struct TcpHeader : tcphdr {

    uint16_t getDestinationPort() {
        return ntohs(dest);
    }

    uint16_t getSourcePort() {
        return ntohs(source);
    }

};

extern IP globalIP;

struct Socket {

    static unsigned short csum(unsigned short *ptr,int nbytes)
    {
        register long sum;
        unsigned short oddbyte;
        register short answer;

        sum=0;
        while(nbytes>1) {
            sum+=*ptr++;
            nbytes-=2;
        }
        if(nbytes==1) {
            oddbyte=0;
            *((u_char*)&oddbyte)=*(u_char*)ptr;
            sum+=oddbyte;
        }

        sum = (sum>>16)+(sum & 0xffff);
        sum = sum + (sum>>16);
        answer=(short)~sum;

        return(answer);
    }

    struct pseudo_header
    {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t tcp_length;
    };

    static unsigned short getChecksum(tcphdr *tcpHeader, pseudo_header *info, char *data = nullptr, size_t length = 0) {
        char buf[sizeof(tcphdr) + sizeof(pseudo_header) + 1024];
        memcpy(buf + sizeof(pseudo_header), tcpHeader, sizeof(tcphdr));
        memcpy(buf, info, sizeof(pseudo_header));

        memcpy(buf + sizeof(pseudo_header) + sizeof(tcphdr), data, length);

        return csum((unsigned short *) buf, sizeof(tcphdr) + sizeof(pseudo_header) + length);
    }


    static unsigned short getChecksum(iphdr *tcpHeader, pseudo_header *info, char *data = nullptr, size_t length = 0) {
        char buf[sizeof(iphdr) + sizeof(pseudo_header) + 1024];
        memcpy(buf + sizeof(pseudo_header), tcpHeader, sizeof(iphdr));
        memcpy(buf, info, sizeof(pseudo_header));

        memcpy(buf + sizeof(pseudo_header) + sizeof(pseudo_header), data, length);

        return csum((unsigned short *) buf, sizeof(iphdr) + sizeof(pseudo_header) + length);
    }

    static void sendPacket(uint32_t hostSeq, uint32_t hostAck, uint32_t networkDestIp, uint32_t networkSourceIp, int hostDestPort,
                           int hostSourcePort, bool flagAck, bool flagSyn, bool flagFin, bool flagRst, char *data, size_t length) {

        // has to include ip header to allow sending from (source) other than 127.0.0.1
        iphdr iph = {};
        iph.ihl = 5;
        iph.version = 4;
        iph.tot_len = htons(sizeof(iphdr) + sizeof(tcphdr) + length);
        iph.id = htonl(54321);
        iph.ttl = 255;
        iph.protocol = IPPROTO_TCP;
        iph.saddr = networkSourceIp;
        iph.daddr = networkDestIp;
        iph.check = csum ((unsigned short *) &iph, sizeof(iphdr));

        // take a copy as base!
        tcphdr newTcpHeader = {};

        // these are flags
        newTcpHeader.ack = flagAck;
        newTcpHeader.syn = flagSyn;
        newTcpHeader.fin = flagFin;
        newTcpHeader.rst = flagRst;

        if (data) {
            newTcpHeader.psh = true;
        }


        newTcpHeader.ack_seq = htonl(hostAck);
        newTcpHeader.seq = htonl(hostSeq);
        newTcpHeader.source = htons(hostSourcePort);
        newTcpHeader.dest = htons(hostDestPort);

        // todo
        newTcpHeader.doff = 5; // 5 * 4 = 20 bytes
        newTcpHeader.window = htons(43690); // flow control


        // properly calculate checksum for this header
        pseudo_header info;
        info.dest_address = networkDestIp;
        info.source_address = networkSourceIp;
        info.placeholder = 0;
        info.protocol = IPPROTO_TCP;
        info.tcp_length = htons(sizeof(tcphdr) + length);
        newTcpHeader.check = getChecksum(&newTcpHeader, &info, data, length);

        char buf[sizeof(iphdr) + sizeof(tcphdr) + length];
        memcpy(buf, &iph, sizeof(iphdr));
        memcpy(buf + sizeof(iphdr), &newTcpHeader, sizeof(tcphdr));
        memcpy(buf + sizeof(iphdr) + sizeof(tcphdr), data, length);

        // IP driver
        globalIP.writeIpPacket((IpHeader *) buf, sizeof(iphdr) + sizeof(tcphdr) + length, hostDestPort, networkDestIp);
    }

    void send(char *data, size_t length) {
        // assumes same ip as dest!
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

#include <map>


struct Tcp {
    std::set<uint32_t> inSynAckState;
    IP &ip;
    int port;

    Tcp(IP &ip, int port) :ip(ip), port(port) {
        globalIP = ip;
    }

    std::map<Endpoint, Socket *> sockets;

    void dispatch(IpHeader *ipHeader, TcpHeader *tcpHeader);

    void run() {

        while (true) {
            int length;
            IpHeader *ipHeader = ip.getNextIpPacket(length);

            TcpHeader *tcpHeader = (TcpHeader *) ipHeader->getData();
            if (tcpHeader->getDestinationPort() == port) {

                // this should never happen
                if (length != ipHeader->getTotalLength()) {
                    std::cout << "ERROR: Ip length does not match!" << std::endl;
                    exit(-1);
                }

                dispatch(ipHeader, tcpHeader);
            }
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
