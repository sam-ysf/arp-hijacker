#pragma once

#include <cstddef>
#include <linux/if_packet.h>

namespace spoof {

    //! class Ip4Addr
    /*! IPv4 address */
    struct Ip4Addr {
        char ip4[32];
        char mac[32];
    };

    Ip4Addr locate_ip4_addr(const char* interface, const char* const ip4);
    Ip4Addr locate_my_ip4_addr(const char* interface);

    //! @class ArpSocket
    class ArpSocket {
    public:
        static ArpSocket* create_broadcast(const char* interface);

        static ArpSocket* create_spoofed_gateway(const char* interface,
                                                 const Ip4Addr& tgtAddr,
                                                 const char* gatewayAddr);

        static ArpSocket* create_spoofed_machine(const char* interface,
                                                 const Ip4Addr& tgtAddr,
                                                 const char* machineAddr);

        ArpSocket(const char* interface, const Ip4Addr& srcAddr);
        ArpSocket(const char* interface,
                  const Ip4Addr& srcAddr,
                  const Ip4Addr& tgtAddr);

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

        int sfd_ = 0;

        char header_[kHeaderLen];
    };
} // namespace spoof
