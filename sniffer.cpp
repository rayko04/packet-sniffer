#include <iostream>
#include <string>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <unistd.h>
#include <cstdint>
#include <netinet/in.h>
#include <getopt.h>
#include <cerrno>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fstream>
#include <iomanip>
#include <vector>

//macro for clean exit
#define exit_with_error(msg) do {perror(msg); exit(EXIT_FAILURE);} while(0)

//define filter options
typedef struct {
    std::string s_ip{};
    std::string d_ip{};
    std::string s_if{};
    std::string d_if{};
    uint16_t s_port{0};
    uint16_t d_port{0};
    uint8_t s_mac[6] {};
    uint8_t d_mac[6] {};
    uint8_t t_protocol {0};
} PacketFilter;

//define sockaddr_in type objects to store ips for ease
struct sockaddr_in source_addr{}, dest_addr{};


void print_mac(const uint8_t* mac, std::ostream& out) {
    for (int i = 0; i < 6; ++i) {
        out << std::uppercase << std::hex
            << std::setw(2) << std::setfill('0')
            << static_cast<int>(mac[i]);
        if (i != 5) out << "-";
    }
    out << std::dec;
}

void log_eth_headers(const ethhdr* eth, std::ostream& out) {
    out << "\nEthernet Header\n\t-Source MAC: ";
    print_mac(eth->h_source, out);

    out << "\n\t-Destination MAC: ";
    print_mac(eth->h_dest, out);

    out << "\n\t-Protocol: "
        << ntohs(eth->h_proto) << "\n";
}

void log_ip_headers(const iphdr* ip, std::ostream& out) {
    out << "\nIP Header\n"
        << "\t-Version: " << static_cast<int>(ip->version) << "\n"
        << "\t-Header Length: " << ip->ihl * 4 << " bytes\n"
        << "\t-Type of Service: " << static_cast<int>(ip->tos) << "\n"
        << "\t-Total Length: " << ntohs(ip->tot_len) << "\n"        //ntohs needed only when multi bytes
        << "\t-Identification: " << ntohs(ip->id) << "\n"
        << "\t-Time To Live: " << static_cast<int>(ip->ttl) << "\n"
        << "\t-Protocol: " << static_cast<int>(ip->protocol) << "\n"
        << "\t-Header Checksum: " << ntohs(ip->check) << "\n"
        << "\t-Source IP: " << inet_ntoa(*(in_addr*)&ip->saddr) << "\n"
        << "\t-Destination IP: " << inet_ntoa(*(in_addr*)&ip->daddr) << "\n";
}

void log_tcp_headers(const tcphdr* tcp, std::ostream& out) {
    out << "\nTCP Header\n"
        << "\t-Source Port: " << ntohs(tcp->source) << "\n"
        << "\t-Destination Port: " << ntohs(tcp->dest) << "\n"
        << "\t-Sequence Number: " << ntohl(tcp->seq) << "\n"
        << "\t-Acknowledgement Number: " << ntohl(tcp->ack_seq) << "\n"
        << "\t-Header Length: " << tcp->doff * 4 << " bytes\n"
        << "\t-Flags: "
        << "URG=" << tcp->urg << " "
        << "ACK=" << tcp->ack << " "
        << "PSH=" << tcp->psh << " "
        << "RST=" << tcp->rst << " "
        << "SYN=" << tcp->syn << " "
        << "FIN=" << tcp->fin << "\n"
        << "\t-Window Size: " << ntohs(tcp->window) << "\n"
        << "\t-Checksum: " << ntohs(tcp->check) << "\n"
        << "\t-Urgent Pointer: " << tcp->urg_ptr << "\n";
}

void log_udp_headers(const udphdr* udp, std::ostream& out) {
    out << "\nUDP Header\n"
        << "\t-Source Port: " << ntohs(udp->source) << "\n"
        << "\t-Destination Port: " << ntohs(udp->dest) << "\n"
        << "\t-Length: " << ntohs(udp->len) << "\n"
        << "\t-Checksum: " << ntohs(udp->check) << "\n";
}

void log_payload(uint8_t* buffer, int bufflen, int iphdrlen, uint8_t protocol, const tcphdr* tcp, std::ostream& out)
{
    uint32_t transport_header_size = sizeof(udphdr);

    //cannot use sizeof(tcphdr), it may not include options.
    if (protocol == IPPROTO_TCP)
        transport_header_size = tcp->doff * 4;

    uint8_t* data = buffer + sizeof(ethhdr) + iphdrlen + transport_header_size;
    int data_size = bufflen - (sizeof(ethhdr) + iphdrlen + transport_header_size);

    out << "\nData\n";

    for (int i = 0; i < data_size; ++i) {
        if (i % 16 == 0)
            out << "\n";

        out << std::hex << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(data[i]) << " ";
    }

    out << std::dec << "\n";
}

//get mac of interface
void get_mac(PacketFilter *filter, std::string ifname, std::string iftype) {
    struct ifreq ifr{};
    //need a socket descriptor to perform ioctl on network interfaces.
    int fd {socket(AF_INET, SOCK_DGRAM, 0)};
    ifr.ifr_addr.sa_family = AF_INET;//ipv4, ifr_addr is an object of sockaddr struct
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ-1);////IFNAMSIZ: max length of interface name

    ioctl(fd, SIOCGIFHWADDR, &ifr);   //request mac address for ifr object
    close(fd);

    if( iftype == "source")
        memcpy(filter->s_mac, (uint8_t *)ifr.ifr_hwaddr.sa_data, 6); //6 bytes, memcpy safer than strcpy since we are copying raw bytes
    else
        memcpy(filter->d_mac, (uint8_t *)ifr.ifr_hwaddr.sa_data, 6);
}

//compare two mac addresses
bool maccmp(uint8_t *mac1, uint8_t *mac2) {
    for(int i {0}; i < 6; i++) {
        if(mac1[i] != mac2[i])
            return false;
    }
    return true;
}

bool filter_ip(PacketFilter *packet_filter) {
    //ntoa converts the binary ip address in source_addr.sin_addr to a human readable string format for comparison with the filter. if the filter is not specified (nullptr) then we ignore it and dont filter by that field
    if(!packet_filter->s_ip.empty() && strcmp(packet_filter->s_ip.c_str(), inet_ntoa(source_addr.sin_addr)) != 0)
        return false;
    if(!packet_filter->d_ip.empty() && strcmp(packet_filter->d_ip.c_str(), inet_ntoa(dest_addr.sin_addr)) != 0)
        return false;
    return true;
}

bool filter_port(uint16_t sport, uint16_t dport, PacketFilter* filter) {
    if(filter->s_port != 0 && filter->s_port != sport)  return false;
    if(filter->d_port != 0 && filter->d_port != dport)    return false;
    return true;
}

void process_packet(uint8_t *buffer, int bufflen, PacketFilter *filter, std::ofstream& log) {
    
    //process data link header
    // struct ethhdr{h_dest[6], h_source[6], h_proto}
    struct ethhdr *eth {(struct ethhdr *) (buffer)};

    //discard if upper layer proto isnt IPv4 (only handling IP packets)
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return;

    //filter by mac address if specified
    if (!filter->s_if.empty() && !maccmp(filter->s_mac, eth->h_source))
        return;
    if (!filter->d_if.empty() && !maccmp(filter->d_mac, eth->h_dest))
        return;

    //process ip layer header
    struct iphdr *ip {(struct iphdr *) (buffer + sizeof(struct ethhdr))};   //sizeof ethhdr is fixed
    int iphdrlen {ip->ihl*4};   ////ihl is the number of 32 bit words in the header, so we multiply by 4 to get the number of bytes, iphdr is variable length due to options, so we need to calculate the length to get to the transport layer header

    //store source and destination ip addresses in sockaddr_in structs for later comparison
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin_addr.s_addr = ip->saddr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_addr.s_addr = ip->daddr;

    if (!filter_ip(filter))    return;     //filter by ip
    if (filter->t_protocol != 0 && filter->t_protocol != ip->protocol)   return;     //filter by transport protocol if specified

    struct tcphdr *tcp = nullptr;
    struct udphdr *udp = nullptr;

    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));
        if (!filter_port(ntohs(tcp->source), ntohs(tcp->dest), filter))  return;
    } 
    else if(ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));
        if (!filter_port(ntohs(udp->source), ntohs(udp->dest), filter))  return;
    }
    else    //if neither tcp nor udp(not handled others yet)
        return;
    
    log_eth_headers(eth, log);
    log_ip_headers(ip, log);

    if (tcp)
        log_tcp_headers(tcp, log);

    if (udp)
        log_udp_headers(udp, log);

    log_payload(buffer, bufflen, iphdrlen, ip->protocol, tcp, log);
}


int main(int argc, char **argv) {
    int c{};
    std::string logfile {"snif.txt"};   //default file name
    PacketFilter filter{};

    while (1) {
        //long options choice
        // struct options {name, argu, flag, value(int)}
        static struct option long_options[] {
            {"sip", required_argument, nullptr, 's'},
            {"dip", required_argument, nullptr, 'd'},
            {"sif", required_argument, nullptr, 'i'},
            {"dif", required_argument, nullptr, 'g'},
            {"sport", required_argument, nullptr, 'p'},
            {"dport", required_argument, nullptr, 'o'},
            {"logfile", required_argument, nullptr, 'f'},
            {"tcp", no_argument, nullptr, 't'},
            {"udp", no_argument, nullptr, 'u'},
            {0, 0, 0, 0}    //denotes end of array
        };
        
        //no colon after means no arguments necessary "tus:d:p:o:i:g:f:"
        c = getopt_long(argc, argv, "tus:d:i:g:p:o:f:", long_options, nullptr);
        if (c == -1)    break;

        switch (c) {
            case 't': filter.t_protocol = IPPROTO_TCP; break;
            case 'u': filter.t_protocol = IPPROTO_UDP; break;
            case 's': filter.s_ip = optarg; break;    //argument stored in optarg
            case 'd': filter.d_ip = optarg; break;    //as string (char *)
            case 'i': filter.s_if = optarg; break;    //atoi string(ascii) to int
            case 'g': filter.d_if = optarg; break;
            case 'p': filter.s_port = atoi(optarg); break;
            case 'o': filter.d_port = atoi(optarg); break;
            case 'f': logfile = optarg; break;
            
            default: abort();
        }
    }

    //display for debug
    std::cout << "t_protocol: " << filter.t_protocol << std::endl;
    std::cout << "source_port: " << filter.s_port << std::endl;
    std::cout << "dest_port: " << filter.d_port << std::endl;
    std::cout << "source_ip: " << filter.s_ip << std::endl;
    std::cout << "dest_ip: " << filter.d_ip << std::endl;
    std::cout << "source_if_name: " << filter.s_if << std::endl;
    std::cout << "dest_if_name: " << filter.d_if << std::endl;
    std::cout << "file " << logfile << std::endl;

    std::ofstream log(logfile);
    if (!log) { exit_with_error("Failed to open log file."); }

    if (!filter.s_if.empty())
        get_mac(&filter, filter.s_if, "source");
    if (!filter.d_if.empty())
        get_mac(&filter, filter.d_if, "destination");

    int saddr_len{}, sockfd{}, bufflen{};
    struct sockaddr saddr{};    //not using sockaddr_in since we are working at mac level here
    constexpr int BUFFSIZE{65536};      //max ip packet size
    std::vector<uint8_t> buffer(BUFFSIZE, 0);

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));    //packet socket
    if (sockfd < 0) { exit_with_error("Failed to create socket."); }
    
    //keep listening and capturing packets
    while (1) {
        saddr_len = sizeof(saddr);

        //recvfrom(fd, buffer, size of buffer, flags, source addr, size of source addr
        bufflen = recvfrom(sockfd, buffer.data(), BUFFSIZE, 0, &saddr, (socklen_t *)&saddr_len);
        if(bufflen < 0) { exit_with_error("Failed to read from socket.");}
        //the addr of incoming packets will be stored in saddr, not really necessary here since we dont want to reply

        process_packet(buffer.data(), bufflen, &filter, log);
    }
}
