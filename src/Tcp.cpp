#include "Tcp.h"

void Tcp::dispatch(IpHeader *ipHeader, TcpHeader *tcpHeader) {

    // lookup can be improved
    Endpoint endpoint = {ipHeader->saddr, ntohs(tcpHeader->source), ipHeader->daddr};

    // does this connection exist?
    auto it = sockets.find(endpoint);
    Socket *socket = nullptr;
    if (it != sockets.end()) {
        socket = it->second;
    }

    // connection begin handler
    if (tcpHeader->syn) {

        // cannot syn already established connection
        if (socket) {
            return;
        }

        // simply answer all syns
        uint32_t hostSeq = rand();
        inSynAckState.insert(htonl(hostSeq));
        Socket::sendPacket(hostSeq, ntohl(tcpHeader->seq) + 1, ipHeader->saddr, ipHeader->daddr, ntohs(tcpHeader->source), ntohs(tcpHeader->dest), true, true, false, false, nullptr, 0);

        // no data in syn
        return;

        // disconnection handler
    } else if (tcpHeader->fin) {

        if (!socket) {
            std::cout << "FIN for already closed socket!" << std::endl;
            return;
        }

        ondisconnection(socket);
        sockets.erase(endpoint);

        // send fin, ack back
        socket->hostAck += 1;
        Socket::sendPacket(socket->hostSeq, socket->hostAck, ipHeader->saddr, ipHeader->daddr, ntohs(tcpHeader->source), ntohs(tcpHeader->dest), true, false, true, false, nullptr, 0);

        // connection complete handler
    } else if (tcpHeader->ack) {

        // if no socket, see if we can establish one!
        if (!socket) {
            // store ack and seq (tvärt om för oss)
            uint32_t ack = ntohl(tcpHeader->seq);
            uint32_t seq = ntohl(tcpHeader->ack_seq);

            // map from ip and port to ack and seq
            if (inSynAckState.find(htonl((seq - 1))) != inSynAckState.end()) {
                Socket *socket = new Socket({nullptr, ipHeader->saddr, tcpHeader->getSourcePort(), ipHeader->daddr, ack, seq});
                sockets[endpoint] = socket;
                onconnection(socket);
                inSynAckState.erase(htonl((seq - 1)));
            }
        }
    }

    // data handler
    int tcpdatalen = ntohs(ipHeader->tot_len) - (tcpHeader->doff * 4) - (ipHeader->ihl * 4);
    if (tcpdatalen) {

        if (!socket) {
            std::cout << "DATA for already closed socket!" << std::endl;
            return;
        }

        char *buf = (char *) ipHeader;
        socket->hostAck += tcpdatalen;

        uint32_t lastHostSeq = socket->hostSeq;
        ondata(socket, buf + ipHeader->ihl * 4 + tcpHeader->doff * 4, tcpdatalen);
        // no data sent, need to send ack!
        if (lastHostSeq == socket->hostSeq) {
            Socket::sendPacket(socket->hostSeq, socket->hostAck, ipHeader->saddr, ipHeader->daddr, ntohs(tcpHeader->source), ntohs(tcpHeader->dest), true, false, false, false, nullptr, 0);
        }

    }
}

IP globalIP;
