SOCKETS: End points of a communication. An interface b/w application and network stack(kernel).

1) Stream Sockets: uses tcp. connection oriented. SOCK_STREAM in c++
2) Datagram Sockets: uses udp, connectionless. SOCK_DGRAM in c++

The control of upper two types is under kernel. It handles header stripping at each layer and then transfers pure data to application.

3) Raw / Packet Sockets: Manually build ip header. 
Control is left under developer. The whole packet is received as it is along with other layer headers untouched by kernel.(ie data link layer/ethernet header (mac addr info etc), ip header, transport header are all intact with the packet and not stripped yet) kernel creates a copy of the packet receives at datalink/network without removing headers and send to the packet/raw socket from where it is passed to application requestion it(sniffer). Meantime the original packet is passed throush osi layer and towards the actual target application.
This is done so for cases when you need to sniff the packet or look into header infos.

Raw sockets let you access network layer and above layer headers. Packet Sockets let you access even data link layer header.
In short these let you access lower layer headers.

    RAW SOCKETS FOR PACKET SNIFFER: 
        Usual c/c++ sniffers use libpcap library which uses raw sockets. I use raw sockets here for learning.

    RAW SOCKET IMPLEMENTATION: 
        SOCK_RAW in cpp.
        for sending/writing data IPPROTO_RAW is used.
        for receivig/reading data IPPROTO_Tcp/Udp is used.
        Socket(AF_INET, SOCK_RAW, IPPROTO_RAW).

    PACKET SOCKET IMPLEMENTAION:
        socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
            htons(ETH_P_ALL): cpturing all kinds of packets
            other may be 802.3, ip related only etc
            htons: host byte order(little endian) to network(big endian) short(16bits)
            ethpall header is provided by the OS

    Bind/connect syscalls arent needed. only creation and then recvfrom().

PROMISCUOUS MODE: when an interface allows a socket to recv packets meant for not only itself but all other interfaces aswell.
Raw/packet sockets can enable this mode for the particular interface it is used on, hence it can sniff all packets.

CONDITON TO USE RAW SOCKETS: 
    to use raw docket a process must either
        have effetive id as 0(ie root) or
        have capability CAP_NET_RAW.

STEPS:
1)  struct for filter options.
2)  sockadddr_in global objects for ease storing of ips
3)  options handling input loop
4)  get mac of interfaces if used in filter options
5)  create socket and start recvfrom()
6)  start processing
7)  parse ethhdr and filter mac/interface if any
8)  parse iphdr and filter ip if any
9)  parse tcphdr/udphdr and filter if any
10) log everything!!!

NOTES:
1) struct sockaddr describes a generic socket, sockaddr_in describes an ipv4 socket, sockaddr_in6 describes an ipv6 socket.
