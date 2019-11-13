#include <iostream>
#include <thread>
#include <cstring>
#include <unistd.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <dnet.h>


struct icmp_packet {
    icmphdr header{};
    char msg[56]{};

    explicit icmp_packet(const char *msg, bool is_ipv6) {
        header.type = is_ipv6 ? ICMPV6_ECHO_REQUEST : ICMP_ECHO;
        header.code = 0;
        header.un.echo.id = getpid();
        header.un.echo.sequence = 1;
        strncpy(this->msg, msg, 55);
        checksum();
    }

    uint16_t checksum() {
        this->header.checksum = 0;
        int len = sizeof(*this);
        auto *current = reinterpret_cast<const uint16_t *>(this);
        uint32_t sum = 0;
        while (len > 1) {
            len -= 2;
            sum += *current++;
        }
        if (len)
            sum += *reinterpret_cast<const uint8_t *>(current);
        sum = (sum >> 16u) + (sum & 0xFFFFu);
        sum += sum >> 16u;
        return this->header.checksum = ~sum;
    }
};

char *dns_lookup(const char *hostname, sockaddr_storage &addr, bool &is_ipv6) {
    static char ip[INET6_ADDRSTRLEN];
    static addrinfo hint{}, *res = nullptr;
    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_ALL;

    if (getaddrinfo(hostname, nullptr, &hint, &res)) {
        std::cerr << "Invalid address" << std::endl;
        return nullptr;
    }
    is_ipv6 = res->ai_family == AF_INET6;
    memcpy(&addr, res->ai_addr, sizeof(addr));
    if (is_ipv6)
        inet_ntop(res->ai_family, &(reinterpret_cast<sockaddr_in6 *>(res->ai_addr)->sin6_addr), ip, res->ai_addrlen);
    else
        inet_ntop(res->ai_family, &(reinterpret_cast<sockaddr_in *>(res->ai_addr)->sin_addr), ip, res->ai_addrlen);
    return ip;
}

void send_request(int &sock_fd, const sockaddr_storage &addr, bool is_ipv6 = false) {
    icmp_packet packet("echo requests", is_ipv6);
    sockaddr_storage r_addr{};
    socklen_t r_len = sizeof(r_addr);
    int cnt = 100;
    while (cnt--) {
        if (sendto(sock_fd, &packet, sizeof(packet), 0,
                   reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) < 1) {
            std::cerr << "Failed to send packet" << std::endl;
            continue;
        }

        icmp_packet buffer("echo reply", is_ipv6);
        auto start = std::chrono::high_resolution_clock::now();
        while (buffer.header.type != 69 + 60 * is_ipv6) {
            if (recvfrom(sock_fd, &buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr *>(&r_addr), &r_len) <= 0) {
                std::cout << "Packet loss" << std::endl;
                break;
            }
        }

        bool time_exceeded = is_ipv6 ? buffer.header.code == ICMPV6_TIME_EXCEED : buffer.header.code == 192;
        if (time_exceeded) {
            std::cout << "Time exceeded" << std::endl;
            continue;
        }

        // std::cout << int(buffer.header.type) << std::endl;

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> rtt = end - start;
        std::cout << "Received reply: seq=" << packet.header.un.echo.sequence
                  << " rrt=" << rtt.count() << "ms" << std::endl;
        ++packet.header.un.echo.sequence;
        packet.checksum();
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(500ms);
    }

}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " " << "(hostname|ip address)" << std::endl;
        return 1;
    }
    socklen_t ttl = (argc == 3) ? atoi(argv[2]) : 64;
    bool is_ipv6 = false;
    sockaddr_storage addr{};
    char *ip = dns_lookup(argv[1], addr, is_ipv6);
    std::cout << "PING " << argv[1] << " (" << ip << ")" << std::endl;
    int sock_fd = socket(is_ipv6 ? PF_INET6 : PF_INET, SOCK_RAW, is_ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (sock_fd < 0) {
        std::cerr << "Cannot open socket fd\n" << "Consider running with sudo" << std::endl;
        return sock_fd;
    }
    if (setsockopt(sock_fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)))
        std::cerr << "Error setting TTL" << std::endl;
    send_request(sock_fd, addr, is_ipv6);
    return 0;
}
