#pragma once

#include <cstddef>
#include <linux/if_packet.h>
#include <memory>
#include <string>

namespace spoof {

    //! class Ip4Addr
    /* IPv4 address */
    struct Ip4Addr {
        static constexpr size_t kBuffSize = 32;
        std::string ip4;
        std::string mac;
    };

    Ip4Addr locate_ip4_addr(const std::string& interface,
                            const std::string& ip4);
    Ip4Addr locate_my_ip4_addr(const std::string& interface);

    //! @class ArpSocket
    class ArpSocket {
    public:
        static std::unique_ptr<ArpSocket> create_broadcast(
            const std::string& interface);

        static std::unique_ptr<ArpSocket> create_spoofed_gateway(
            const std::string& interface,
            const Ip4Addr& tgtAddr,
            const std::string& gatewayAddr);

        static std::unique_ptr<ArpSocket> create_spoofed_machine(
            const std::string& interface,
            const Ip4Addr& tgtAddr,
            const std::string& machineAddr);

        ~ArpSocket();

        ArpSocket(const std::string& interface, const Ip4Addr& srcAddr);
        ArpSocket(const std::string& interface,
                  const Ip4Addr& srcAddr,
                  const Ip4Addr& tgtAddr);

        ArpSocket(const ArpSocket&) = delete;
        ArpSocket(ArpSocket&&) = delete;

        void close();
        bool send_reply() const;
        bool send_request() const;
    private:
        bool send_impl(int opcode) const;

        static const std::size_t kEthlen = 14; // Ethernet header length
        static const std::size_t kArpLen = 28; // ARP header length

        // Total Header length
        static const std::size_t kHeaderLen = kEthlen + kArpLen;

        sockaddr_ll device_;

        int sfd_ = -1;

        char header_[kHeaderLen];
    };
} // namespace spoof
