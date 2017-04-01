#include "Tcp.h"

void Tcp::dispatch(IpHeader *ipHeader, TcpHeader *tcpHeader) {

    // source should always be 127.0.0.1, but destination (us) can be all interfaces
    static uint32_t lastSource = 0;
    if (lastSource == 0) {
        lastSource = ipHeader->saddr;
    } else if (lastSource != ipHeader->saddr) {
        std::cout << "ERROR: source changed!" << std::endl;
        exit(-1);
    }

    Endpoint endpoint = {ipHeader->saddr, ntohs(tcpHeader->source), ipHeader->daddr};

    // connection begin handler
    if (tcpHeader->syn) {

        uint32_t hostSeq = rand();
        inSynAckState.insert(htonl(hostSeq));

        Socket::sendPacket(hostSeq, ntohl(tcpHeader->seq) + 1, ipHeader->saddr, ipHeader->daddr, ntohs(tcpHeader->source), ntohs(tcpHeader->dest), true, true, false, false, nullptr, 0);

        // disconnection handler
    } else if (tcpHeader->fin) {

        if (sockets.find(endpoint) != sockets.end()) {
            Socket *socket = sockets[endpoint];
            ondisconnection(socket);
            sockets.erase(endpoint);

            // send fin, ack back
            socket->hostAck += 1;
            Socket::sendPacket(socket->hostSeq, socket->hostAck, ipHeader->saddr, ipHeader->daddr, ntohs(tcpHeader->source), ntohs(tcpHeader->dest), true, false, true, false, nullptr, 0);
        } else {
            std::cout << "FIN for already closed socket!" << std::endl;
        }

        // connection complete handler
    } else if (tcpHeader->ack) {

        // store ack and seq (tvärt om för oss)
        uint32_t ack = ntohl(tcpHeader->seq);
        uint32_t seq = ntohl(tcpHeader->ack_seq);

        // map from ip and port to ack and seq

        if (inSynAckState.find(htonl((seq - 1))) != inSynAckState.end()) {

            Socket *socket = new Socket({nullptr, ipHeader->saddr, tcpHeader->getSourcePort(), ipHeader->daddr, ack, seq});

            sockets[endpoint] = socket;

            onconnection(socket);

            inSynAckState.erase(htonl((seq - 1)));
        } else {
            // ack, psh?
        }
    }

    // data handler
    int tcpdatalen = ntohs(ipHeader->tot_len) - (tcpHeader->doff * 4) - (ipHeader->ihl * 4);
    if (tcpdatalen) {
        Socket *socket = sockets[endpoint];
        char *buf = (char *) ipHeader;

        socket->hostAck += tcpdatalen;
        Socket::sendPacket(socket->hostSeq, socket->hostAck, ipHeader->saddr, ipHeader->daddr, ntohs(tcpHeader->source), ntohs(tcpHeader->dest), true, false, false, false, nullptr, 0);

        ondata(socket, buf + ipHeader->ihl * 4 + tcpHeader->doff * 4, tcpdatalen);
    }
}

IP globalIP;
