import sys

import dpkt


class Pkt:
    ack = 16
    syn = 2
    fin = 1

    def __init__(self, eth, ts):
        self.ts = ts
        self.eth = eth
        self.ip = eth.data
        self.tcp = self.ip.data
        self.src_ip = ip_to_str(self.ip.src)
        self.dst_ip = ip_to_str(self.ip.dst)
        self.src_port = self.tcp.sport
        self.dst_port = self.tcp.dport
        self.flags = self.tcp.flags
        self.seq = self.tcp.seq
        self.ack = self.tcp.ack
        self.win = self.tcp.win


class TCPFlow:
    def __init__(self, start, end, srcip, srcport, dstip, dstport, win):
        self.start = start
        self.end = end
        self.srcip = srcip
        self.srcport = srcport
        self.dstip = dstip
        self.dstport = dstport
        self.ipportstring = 'Source: %s: %d\nDestination: %s: %d' % (self.srcip, self.srcport, self.dstip, self.dstport)
        self.win = win


def ip_to_str(ip):
    addr = ""
    for i in range(len(ip)):
        if i < len(ip) - 1:
            addr += str(ip[i]) + "."
        else:
            addr += str(ip[i])
    return addr


def analysis_pcap_tcp(filename):
    # rb for read binary
    f = open(filename, 'rb')
    sender_ip = "130.245.145.12"
    receiver_ip = "128.208.2.198"
    pcap = dpkt.pcap.Reader(f)

    num_tcp_flows = 0
    flow_calc_stack = []
    tcpflows = []
    pkts = []

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        p = Pkt(eth, ts)
        pkts.append(p)

    for i in range(len(pkts)):
        p = pkts[i]
        src_ip = p.src_ip
        dst_ip = p.dst_ip
        src_port = p.src_port
        dst_port = p.dst_port

        if src_ip == sender_ip and p.flags & Pkt.syn == Pkt.syn:
            flow_calc_stack.append(i)
            index = 0
            tup = dpkt.tcp.parse_opts(p.tcp.opts)
            for j in range(len(tup)):
                if tup[j][0] == 3:
                    index = j
            pkts[i].win = 2 ** dpkt.tcp.parse_opts(p.tcp.opts)[index][1][0]

        if dst_ip == receiver_ip and p.flags & Pkt.fin == Pkt.fin:
            index = 0
            for j in range(len(flow_calc_stack)):
                if pkts[flow_calc_stack[j]].src_port == src_port and pkts[flow_calc_stack[j]].src_ip == src_ip:
                    index = j
            start = flow_calc_stack.pop(index)
            num_tcp_flows += 1
            # print('IP %d: src-port=%s src-ip=%d dst-port=%s dst-ip=%d \n' % (i, src_ip, src_port, dst_ip, dst_port))
            tcpflows.append(TCPFlow(start, i, src_ip, src_port, dst_ip, dst_port, pkts[start].win))

    print('Number of TCPFlows: %d\n' % num_tcp_flows)

    for i in range(len(tcpflows)):
        print(tcpflows[i].ipportstring)
        j = tcpflows[i].start + 1
        # find handshake ack
        while pkts[j].src_port != tcpflows[i].srcport or pkts[j].flags & Pkt.ack != Pkt.ack or \
                pkts[j].src_ip != tcpflows[i].srcip:
            j += 1
        # skip handshake ack
        j += 1
        # find first ack
        while pkts[j].src_port != tcpflows[i].srcport or pkts[j].flags & Pkt.ack != Pkt.ack or \
                pkts[j].src_ip != tcpflows[i].srcip:
            j += 1
        k = j + 1
        tr1sendIndex = j
        tr1send = pkts[j]
        tr1send.win *= tcpflows[i].win
        print('Transaction 1 Send: Seq Number=%d Ack Number=%d Receive Window Size=%d' % (
            tr1send.seq, tr1send.ack, tr1send.win))
        while tr1send.ack != pkts[k].seq:
            k += 1
        tr1rec = pkts[k]
        tr1rec.win *= tcpflows[i].win
        print('Transaction 1 Receive: Seq Number=%d Ack Number=%d Receive Window Size=%d' % (
            tr1rec.seq, tr1rec.ack, tr1rec.win))
        j += 1
        while pkts[j].src_port != tcpflows[i].srcport or pkts[j].flags & Pkt.ack != Pkt.ack or \
                pkts[j].src_ip != tcpflows[i].srcip:
            j += 1
        k += 1
        tr2send = pkts[j]
        tr2send.win *= tcpflows[i].win
        print('Transaction 2 Send: Seq Number=%d Ack Number=%d Receive Window Size=%d' % (
            tr2send.seq, tr2send.ack, tr2send.win))
        while tr2send.ack != pkts[k].seq:
            k += 1
        tr2rec = pkts[k]
        tr2rec.win *= tcpflows[i].win
        print('Transaction 2 Receive: Seq Number=%d Ack Number=%d Receive Window Size=%d' % (
            tr2rec.seq, tr2rec.ack, tr2rec.win))

        # get last rec
        j = tcpflows[i].end
        while (pkts[j].src_ip != tcpflows[i].srcip or pkts[j].src_port != tcpflows[i].srcport or
               pkts[j].flags & Pkt.ack != Pkt.ack or pkts[j].flags & Pkt.fin == Pkt.fin):
            j -= 1
        lastsend = pkts[j]
        lastrec = pkts[j]
        lastrecIndex = j
        j += 1
        while j <= len(pkts) - 1:
            if lastsend.ack == pkts[j].seq:
                lastrec = pkts[j]
                lastrecIndex = j
            j += 1

        # get total data
        totalData = 0
        j = tr1sendIndex
        while pkts[j] != pkts[lastrecIndex]:
            if pkts[j].src_ip == tcpflows[i].srcip and pkts[j].src_port == tcpflows[i].srcport:
                totalData += len(pkts[j].tcp)
            j += 1
        elapsedTime = lastrec.ts - tr1send.ts
        # print('Period: %f' % elapsedTime)
        throughput = float(totalData) / float(elapsedTime)
        print('Throughput: %.2f bytes per second' % throughput)

        # congestion windows
        j = tcpflows[i].start + 1
        # find handshake ack
        while pkts[j].src_port != tcpflows[i].srcport or pkts[j].flags & Pkt.ack != Pkt.ack or \
                pkts[j].src_ip != tcpflows[i].srcip:
            j += 1
        # skip handshake ack
        j += 1
        # find first ack
        while pkts[j].src_port != tcpflows[i].srcport or pkts[j].flags & Pkt.ack != Pkt.ack or \
                pkts[j].src_ip != tcpflows[i].srcip:
            j += 1

        winSize = 0
        secPktSeq = 0
        # print(j)
        while j < tcpflows[i].end-1:
            if pkts[j].src_ip == tcpflows[i].srcip and pkts[j].src_port == tcpflows[i].srcport and \
                    pkts[j].flags & Pkt.ack == Pkt.ack:
                winSize += 1
                if winSize == 2:
                    secPktSeq = pkts[j].seq
            elif pkts[j].src_ip == tcpflows[i].dstip and pkts[j].src_port == tcpflows[i].dstport and \
                    pkts[j].flags & Pkt.ack == Pkt.ack and secPktSeq == pkts[j].ack:
                break
            j += 1
        # print(j)
        print('Congestion Window Size #1: %d' % winSize)
        while pkts[j].src_ip != tcpflows[i].srcip and pkts[j].src_port != tcpflows[i].srcport and \
                pkts[j].flags & Pkt.ack != Pkt.ack:
            j += 1

        winSize = 0
        secPktSeq = 0
        # print(j)
        while j < tcpflows[i].end - 1:
            if pkts[j].src_ip == tcpflows[i].srcip and pkts[j].src_port == tcpflows[i].srcport and \
                    pkts[j].flags & Pkt.ack == Pkt.ack:
                winSize += 1
                if winSize == 2:
                    secPktSeq = pkts[j].seq
            elif pkts[j].src_ip == tcpflows[i].dstip and pkts[j].src_port == tcpflows[i].dstport and \
                    pkts[j].flags & Pkt.ack == Pkt.ack and secPktSeq == pkts[j].ack:
                break
            j += 1
        # print(j)
        if winSize > 0:
            print('Congestion Window Size #2: %d' % winSize)
        while pkts[j].src_ip != tcpflows[i].srcip and pkts[j].src_port != tcpflows[i].srcport and \
                pkts[j].flags & Pkt.ack != Pkt.ack:
            j += 1

        winSize = 0
        secPktSeq = 0
        # print(j)
        while j < tcpflows[i].end - 1:
            if pkts[j].src_ip == tcpflows[i].srcip and pkts[j].src_port == tcpflows[i].srcport and \
                    pkts[j].flags & Pkt.ack == Pkt.ack:
                winSize += 1
                if winSize == 2:
                    secPktSeq = pkts[j].seq
            elif pkts[j].src_ip == tcpflows[i].dstip and pkts[j].src_port == tcpflows[i].dstport and \
                    pkts[j].flags & Pkt.ack == Pkt.ack and secPktSeq == pkts[j].ack:
                break
            j += 1
        # print(j)
        if winSize > 0:
            print('Congestion Window Size #3: %d' % winSize)
        while pkts[j].src_ip != tcpflows[i].srcip and pkts[j].src_port != tcpflows[i].srcport and \
                pkts[j].flags & Pkt.ack != Pkt.ack:
            j += 1

        # Retransmissions
        dups = {}
        tripDups = []
        tripDupRetrans = 0
        timeoutRetrans = 0
        j = tcpflows[i].start
        lastRec = 0
        lastSend = 0
        # find handshake ack
        while pkts[j].src_port != tcpflows[i].srcport or pkts[j].flags & Pkt.ack != Pkt.ack or \
                pkts[j].src_ip != tcpflows[i].srcip:
            j += 1
        # skip handshake ack
        j += 1
        # find first ack
        while pkts[j].src_port != tcpflows[i].srcport or pkts[j].flags & Pkt.ack != Pkt.ack or \
                pkts[j].src_ip != tcpflows[i].srcip:
            j += 1

        while j < tcpflows[i].end - 1:
            # receiver
            if pkts[j].src_ip == tcpflows[i].dstip and pkts[j].src_port == tcpflows[i].dstport:
                if lastRec == 0:
                    lastRec = pkts[j]
                elif pkts[j+1].ack <= lastRec.ack:
                    if pkts[j].ack not in dups:
                        dups[pkts[j].ack] = 1
                    else:
                        dups[pkts[j].ack] = dups[pkts[j].ack] + 1
                        if dups[pkts[j].ack] == 3:
                            tripDups.append(pkts[j].ack)
                else:
                    lastRec = pkts[j]

            # sender
            if pkts[j].src_ip == tcpflows[i].srcip and pkts[j].src_port == tcpflows[i].srcport:
                if lastSend == 0:
                    lastSend = pkts[j]

                elif pkts[j].seq <= lastSend.seq:
                    # assuming >3 dup acks is still 1 triple dup
                    if pkts[j].seq in tripDups:
                        tripDupRetrans += 1
                    else:
                        timeoutRetrans += 1
                else:
                    lastSend = pkts[j]
            j += 1
        print('Triple Dup Ack Retransmission: %d' % tripDupRetrans)
        print('Timeout Retransmissions: %d' % timeoutRetrans)

        print()


if __name__ == '__main__':
    analysis_pcap_tcp(sys.argv[1])
    # usage: python analysis_pcap_tcp.py assignment2.pcap
    # analysis_pcap_tcp("assignment2.pcap")
