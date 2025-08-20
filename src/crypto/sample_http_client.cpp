#include "sample_tls_crypto.hpp"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>

static int connect_tcp_nb(const std::string& host, const std::string& port) {
    addrinfo hints{}, *res=nullptr;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0)
        throw std::runtime_error("getaddrinfo failed");

    int fd = -1;
    for (auto p=res; p; p=p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK, p->ai_protocol);
        if (fd == -1) continue;
        int rc = ::connect(fd, p->ai_addr, p->ai_addrlen);
        if (rc == 0 || errno == EINPROGRESS) { break; }
        ::close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd == -1) throw std::runtime_error("connect failed");

    return fd;
}

static void send_all_nb(int fd, std::vector<uint8_t>& buf) {
    size_t off = 0;
    while (off < buf.size()) {
        ssize_t n = ::send(fd, buf.data() + off, buf.size() - off, 0);
        if (n > 0) off += (size_t)n;
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        else throw std::runtime_error("send failed");
    }
    if (off > 0) buf.erase(buf.begin(), buf.begin() + off);
}

int main() {
    std::string host = "graphicsblast.com";
    std::string port = "443";

    int fd = connect_tcp_nb(host, port);

    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep == -1) { perror("epoll_create1"); return 1; }

    epoll_event ev{};
    ev.events = EPOLLOUT | EPOLLIN | EPOLLET; // edge-triggered for low latency
    ev.data.fd = fd;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) == -1) { perror("epoll_ctl"); return 1; }

    TLSClientNB tls(host);

    std::vector<uint8_t> to_send;   // ciphertext pending to send
    std::vector<uint8_t> app_out;   // plaintext received from TLS

    // Kick handshake once (it may queue ClientHello into wbio)
    TLSStatus st = tls.handshake_step();
    tls.drain_encrypted(to_send);
    send_all_nb(fd, to_send);

    // Prepare HTTP request
    const std::string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    bool request_sent = false;

    const int MAX_EVENTS = 4;
    epoll_event events[MAX_EVENTS];

    while (true) {
        int n = epoll_wait(ep, events, MAX_EVENTS, /*timeout ms*/ 2000);
        if (n < 0) { if (errno == EINTR) continue; perror("epoll_wait"); break; }
        if (n == 0) continue;

        for (int i = 0; i < n; ++i) {
            uint32_t ee = events[i].events;
            if (ee & (EPOLLERR | EPOLLHUP)) { std::cerr << "socket error/hup\n"; goto out; }

            if (ee & EPOLLIN) {
                // Read whatever is available
                for (;;) {
                    uint8_t netbuf[32 * 1024];
                    ssize_t r = ::recv(fd, netbuf, sizeof(netbuf), 0);
                    if (r > 0) {
                        tls.feed_encrypted(netbuf, (size_t)r);

                        // Advance handshake or read plaintext
                        if (!tls.handshake_complete()) {
                            st = tls.handshake_step();
                            tls.drain_encrypted(to_send);
                        } else {
                            // Decrypt any app data
                            st = tls.read_plain(app_out);
                            // Print plaintext immediately (low latency)
                            if (!app_out.empty()) {
                                std::cout.write(reinterpret_cast<const char*>(app_out.data()), app_out.size());
                                app_out.clear();
                            }
                        }
                    } else if (r == 0) {
                        // peer closed TCP; TLS may still have data pending (unlikely)
                        goto out;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    } else {
                        perror("recv");
                        goto out;
                    }
                }
            }

            if (ee & EPOLLOUT) {
                // First time we get writable after handshake: send HTTP request
                if (tls.handshake_complete() && !request_sent) {
                    size_t consumed = 0;
                    st = tls.write_plain(reinterpret_cast<const uint8_t*>(req.data()), req.size(),
                                         to_send, consumed);
                    // If partial, loop again on next EPOLLOUT to finish, but HTTP is small so likely 1 shot
                    request_sent = (consumed == req.size());
                }

                // Flush any ciphertext
                if (!to_send.empty()) send_all_nb(fd, to_send);
            }

            // If TLS indicates it wants to write and we have bytes, make sure we flush them
            if (st.want_write && !to_send.empty()) send_all_nb(fd, to_send);

            // If TLS queued new ciphertext (e.g., handshake flight or acks), drain it
            tls.drain_encrypted(to_send);
            if (!to_send.empty()) send_all_nb(fd, to_send);

            if (st.closed) goto out;
        }
    }

out:
    // Try graceful TLS close
    {
        std::vector<uint8_t> bye;
        tls.start_shutdown(bye);
        if (!bye.empty()) send_all_nb(fd, bye);
        // best-effort; not looping to wait for peer close in example
    }
    ::close(fd);
    ::close(ep);
    return 0;
}
