#include "arp_socket.hpp"
#include "endpoint.hpp"
#include <cstring>
#include <net/if.h> // Must be declared before linux/if_arp.h
#include <linux/if_arp.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <unistd.h>

spoof::Ip4Addr spoof::locate_ip4_addr(const char* interface, const char* ip4)
{
    constexpr int kWaitInterval = 500000;

    // Create temp socket
    int sfd = endpoint_udp();
    if (sfd == -1) {
        throw std::runtime_error("Error initializing UDP socket");
    }

    // Discover address
    if (spoof::endpoint_connect(sfd, ip4, 8888) == -1) {
        ::close(sfd);
        throw std::runtime_error("Error connecting socket");
    }

    char buf[6] = {static_cast<char>(0xff)};
    if (endpoint_write(sfd, buf, 6) == -1) {
        ::close(sfd);
        throw std::runtime_error("Error writing to endpoint");
    }

    ::usleep(kWaitInterval);

    // Get ARP data
    struct in_addr ipAddr = {};
    if (::inet_aton(ip4, &ipAddr) == 0) {
        ::close(sfd);
        throw std::runtime_error("");
    }

    struct arpreq request = {};
    (reinterpret_cast<sockaddr_in*>(&request.arp_pa))->sin_addr = ipAddr;
    (reinterpret_cast<sockaddr_in*>(&request.arp_pa))->sin_family = AF_INET;

    std::strncpy(request.arp_dev, interface, sizeof(request.arp_dev) - 1);

    if (::ioctl(sfd, SIOCGARP, reinterpret_cast<caddr_t>(&request)) == -1) {
        ::close(sfd);
        throw std::runtime_error("");
    }

    ::close(sfd);

    const char* const mac_addr = request.arp_ha.sa_data;

    Ip4Addr addr = {};

    std::memcpy(addr.mac, mac_addr, 6);
    std::memcpy(addr.ip4, ip4, strlen(ip4));

    return addr;
}

namespace {
    /*! Helper */
    inline bool locate_my_mac_addr_impl(const int sfd,
                                        const char* const interface,
                                        struct ifreq& ifr)
    {
        ::memset(&ifr, 0, sizeof(ifreq));
        ::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);

        // use ioctl to look up interface name and get its mac address.
        return ::ioctl(sfd, SIOCGIFHWADDR, &ifr) != -1;
    }

    /*! Helper */
    inline bool locate_my_ip4_addr_impl(const int sfd,
                                        const char* const interface,
                                        struct ifreq& ifr)
    {
        ::memset(&ifr, 0, sizeof(ifreq));
        ::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);

        // use ioctl to look up interface name and get its mac address.
        return ::ioctl(sfd, SIOCGIFADDR, &ifr) != -1;
    }
} // namespace

/*! Helper */
spoof::Ip4Addr spoof::locate_my_ip4_addr(const char* interface)
{
    // Create temp socket for resolving interface
    int sfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        throw std::runtime_error("Error creating socket");
    }

    // Get my interface-related data structures
    ifreq ifreqIP;
    ifreq ifrHW;

    if (!locate_my_ip4_addr_impl(sfd, interface, ifreqIP)) {
        throw std::runtime_error("Couldn't locate our IP address");
    }

    if (!locate_my_mac_addr_impl(sfd, interface, ifrHW)) {
        throw std::runtime_error("Couldn't locate our MAC address");
    }

    // Cleanup
    ::close(sfd);

    // Create arp socket interface
    Ip4Addr addr = {};

    const char* saddr = ::inet_ntoa(
        reinterpret_cast<struct sockaddr_in*>(&ifreqIP.ifr_addr)->sin_addr);
    ::memcpy(addr.ip4, saddr, strlen(saddr));
    ::memcpy(addr.mac, ifrHW.ifr_hwaddr.sa_data, 6);

    return addr;
}

namespace {
    // Builds header
    inline void eth_hdr_hdr_broadcast(char* frame, const char* const srcMac)
    {
        // Destination MAC address: broadcast address
        ::memset(&frame[0], 0xff, 6);
        // Source MAC addresses
        ::memcpy(&frame[6], srcMac, 6);

        // Next is ethernet type code (ETH_P_ARP for ARP)
        // http://www.iana.org/assignments/ethernet-numbers
        frame[12] = ETH_P_ARP / 256;
        frame[13] = ETH_P_ARP % 256;
    }

    // Builds header
    inline void eth_hdr_hdr(char* frame,
                            const char* const tgtMac,
                            const char* const srcMac)
    {
        // Destination MAC address
        ::memcpy(&frame[0], tgtMac, 6);
        // Source MAC addresses
        ::memcpy(&frame[6], srcMac, 6);

        // Next is ethernet type code (ETH_P_ARP for ARP)
        // http://www.iana.org/assignments/ethernet-numbers
        frame[12] = ETH_P_ARP / 256;
        frame[13] = ETH_P_ARP % 256;
    }

    // Builds header
    inline void arp_hdr_hdr(char* frame)
    {
        // Hardware type (16 bits): 1 for ethernet
        std::uint16_t htype = ::htons(1);
        ::memcpy(&frame[0], &htype, sizeof(std::uint16_t));

        // Protocol type (16 bits): 2048 for IP
        std::uint16_t ptype = ::htons(ETH_P_IP);
        ::memcpy(&frame[2], &ptype, sizeof(std::uint16_t));

        // Hardware address length (8 bits): 6 bytes for MAC address
        frame[4] = 0x6;

        // Protocol address length (8 bits): 4 bytes for IPv4 address
        frame[5] = 0x4;
    }

    // Opcode
    inline void arp_hdr_opc(char* frame, const std::uint16_t value)
    {
        std::uint16_t v = ::htons(value);
        ::memcpy(&frame[6], &v, sizeof(std::uint16_t));
    }

    // Sender hardware address
    inline void arp_hdr_sha(char* frame, const char* const value)
    {
        ::memcpy(&frame[8], value, 6);
    }

    // Sender protocol address
    inline void arp_hdr_spa(char* frame, const char* const value)
    {
        ::inet_pton(AF_INET, value, &frame[14]);
    }

    // Target hardware address
    inline void arp_hdr_tha(char* frame, const char* const value)
    {
        ::memcpy(&frame[18], value, 6);
    }

    // Target protocol address
    inline void arp_hdr_tpa(char* frame, const char* const value)
    {
        ::inet_pton(AF_INET, value, &frame[24]);
    }
} // namespace

spoof::ArpSocket* spoof::ArpSocket::create_broadcast(const char* interface)
{
    Ip4Addr srcAddr = locate_my_ip4_addr(interface);
    return new ArpSocket(interface, srcAddr);
}

spoof::ArpSocket* spoof::ArpSocket::create_spoofed_gateway(
    const char* interface,
    const Ip4Addr& tgtAddr,
    const char* gatewayAddr)
{
    Ip4Addr myFakeAddr = locate_my_ip4_addr(interface);
    ::memcpy(myFakeAddr.ip4, gatewayAddr, ::strlen(gatewayAddr));

    return new ArpSocket(interface, myFakeAddr, tgtAddr);
}

spoof::ArpSocket* spoof::ArpSocket::create_spoofed_machine(
    const char* interface,
    const Ip4Addr& tgtAddr,
    const char* machineAddr)
{
    Ip4Addr myFakeAddr = locate_my_ip4_addr(interface);
    ::memcpy(myFakeAddr.ip4, machineAddr, ::strlen(machineAddr));

    return new ArpSocket(interface, myFakeAddr, tgtAddr);
}

spoof::ArpSocket::ArpSocket(const char* const interface, const Ip4Addr& srcAddr)
{
    // Create socket
    sfd_ = socket(PF_PACKET, SOCK_RAW, ::htons(ETH_P_ALL));
    if (sfd_ == -1) {
        throw std::runtime_error("Error creating raw socket");
    }

    // Create sockaddr_ll struct
    ::memset(&device_, 0, sizeof(sockaddr_ll));
    ::memcpy(&device_.sll_addr[0], srcAddr.mac, 6);

    device_.sll_ifindex = ::if_nametoindex(interface);
    if (device_.sll_ifindex == 0) {
        throw std::runtime_error("");
    }

    device_.sll_halen = 6;
    device_.sll_family = AF_PACKET;

    char* eth = header_;
    char* arp = header_ + kEthlen;

    // Zero out header
    ::memset(header_, 0, kHeaderLen);

    // Fill out ethernet header
    eth_hdr_hdr_broadcast(eth, srcAddr.mac);
    // Fill out arp header
    arp_hdr_hdr(arp);
    // Fill out src hardware address
    arp_hdr_sha(arp, srcAddr.mac);
    // Fill out src protocol address
    arp_hdr_spa(arp, srcAddr.ip4);
}

spoof::ArpSocket::ArpSocket(const char* const interface,
                            const Ip4Addr& srcAddr,
                            const Ip4Addr& tgtAddr)
{
    // Create socket
    sfd_ = socket(PF_PACKET, SOCK_RAW, ::htons(ETH_P_ALL));
    if (sfd_ == -1) {
        throw std::runtime_error("Error creating raw socket");
    }

    // Create sockaddr_ll struct
    ::memset(&device_, 0, sizeof(sockaddr_ll));
    ::memcpy(&device_.sll_addr[0], srcAddr.mac, 6);

    device_.sll_ifindex = ::if_nametoindex(interface);
    if (device_.sll_ifindex == 0) {
        throw std::runtime_error("");
    }

    device_.sll_halen = 6;
    device_.sll_family = AF_PACKET;

    char* eth = header_;
    char* arp = header_ + kEthlen;

    // Zero out header
    ::memset(header_, 0, kHeaderLen);

    // Fill out ethernet header.
    eth_hdr_hdr(eth, tgtAddr.mac, srcAddr.mac);
    // Fill out arp header
    arp_hdr_hdr(arp);
    // Fill out src hardware address
    arp_hdr_sha(arp, srcAddr.mac);
    // Fill out src protocol address
    arp_hdr_spa(arp, srcAddr.ip4);
    // Fill out tgt hardware address
    arp_hdr_tha(arp, tgtAddr.mac);
    // Fill out tgt protocol address
    arp_hdr_tpa(arp, tgtAddr.ip4);
}

void spoof::ArpSocket::close()
{
    ::close(sfd_);
}

bool spoof::ArpSocket::send_reply() const
{
    return send_impl(ARPOP_REPLY);
}

bool spoof::ArpSocket::send_request() const
{
    return send_impl(ARPOP_REQUEST);
}

bool spoof::ArpSocket::send_impl(int opcode) const
{
    const auto* ptrdevice = reinterpret_cast<const struct sockaddr*>(&device_);

    // Generate outgoing frame
    char frame[kHeaderLen];
    ::memcpy(&frame[0], header_, kHeaderLen);

    // OpCode: 1 for ARP request
    arp_hdr_opc(&frame[kEthlen], static_cast<::uint16_t>(opcode));

    // Send frame
    const int nbytes = ::sendto(
        sfd_, frame, sizeof(frame), 0, ptrdevice, sizeof(sockaddr_ll));
    return nbytes != -1;
}
