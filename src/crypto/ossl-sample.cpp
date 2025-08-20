#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <stdexcept>

static void throw_ssl_err(const char* where) {
    unsigned long e = ERR_get_error();
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    throw std::runtime_error(std::string(where) + ": " + buf);
}

static int connect_tcp(const std::string& host, const std::string& port) {
    addrinfo hints{}, *res=nullptr;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0)
        throw std::runtime_error("getaddrinfo failed");

    int fd = -1;
    for (auto p=res; p; p=p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == -1) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd == -1) throw std::runtime_error("connect failed");
    return fd;
}

static void drain_wbio_to_socket(BIO* wbio, int fd) {
    for (;;) {
        int pending = BIO_pending(wbio);
        printf("drain wbio %i\n", pending);
        if (pending <= 0) break;
        char buf[16 * 1024];
        int n = BIO_read(wbio, buf, std::min<int>(pending, sizeof(buf)));
        if (n <= 0) break;
        int left = n; const char* p = buf;
        while (left > 0) {
            ssize_t s = ::send(fd, p, left, 0);
            if (s <= 0) throw std::runtime_error("send failed");
            p += s; left -= (int)s;
        }
    }
}

static void feed_rbio_from_socket(BIO* rbio, int fd) {
    char inbuf[16 * 1024];
    ssize_t n = ::recv(fd, inbuf, sizeof(inbuf), 0);
    if (n == 0) throw std::runtime_error("peer closed");
    if (n < 0)  throw std::runtime_error("recv failed");
    int w = BIO_write(rbio, inbuf, (int)n);
    if (w <= 0) throw std::runtime_error("BIO_write(rbio) failed");
}

int main() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const std::string host = "graphicsblast.com";
    const std::string port = "443";

    int fd = connect_tcp(host, port);

    // --- Context (TLS 1.2 only) ------------------------------------------------
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) throw_ssl_err("SSL_CTX_new");

    // ★ Force TLS 1.2 only (you advertise only TLS 1.2 and will negotiate only 1.2)
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) throw_ssl_err("set_min");
    if (!SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)) throw_ssl_err("set_max");

    // ★ Good TLS 1.2 cipher policy (ECDHE + AEAD; exclude legacy/weak)
    //    Adjust as needed for your policy / compliance requirements.
    if (!SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:!"
        "aNULL:!eNULL:!MD5:!DSS"))
    {
        throw_ssl_err("SSL_CTX_set_cipher_list");
    }

    // ★ Preferred groups for ECDHE (OpenSSL 1.1.1+ defaults are usually fine; set explicitly if you want)
    // SSL_CTX_set1_groups_list(ctx, "X25519:P-256");

    // ★ Trust store (use system defaults or load your own CA set)
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        throw_ssl_err("SSL_CTX_set_default_verify_paths");
    }
    // Alternatively:
    // if (SSL_CTX_load_verify_locations(ctx, "/path/ca-bundle.crt", nullptr) != 1) throw_ssl_err(...);

    // --- SSL object + memory BIOs ----------------------------------------------
    SSL* ssl = SSL_new(ctx);
    if (!ssl) throw_ssl_err("SSL_new");

    // ★ Require peer cert verification
    SSL_set_verify(ssl, SSL_VERIFY_PEER, nullptr);

    // ★ Hostname verification (no partial wildcards)
    // Use either SSL_set1_host OR X509_VERIFY_PARAM on the connection:
    // (OpenSSL >= 1.1.0)
    if (SSL_set1_host(ssl, host.c_str()) != 1) throw_ssl_err("SSL_set1_host");
    X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

    // SNI
    if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) throw_ssl_err("SSL_set_tlsext_host_name");

    // Modes for fine-grained buffer handling
    long modes = SSL_get_mode(ssl);
    modes |= SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_RELEASE_BUFFERS;
    SSL_set_mode(ssl, modes);

    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio) throw_ssl_err("BIO_new");
    SSL_set_bio(ssl, rbio, wbio); // SSL takes ownership

    SSL_set_connect_state(ssl); // client mode

    // --- Handshake --------------------------------------------------------------
    bool handshaked = false;
    while (!handshaked) {
        int r = SSL_do_handshake(ssl);
        if (r == 1) {
            printf("1\n");
            drain_wbio_to_socket(wbio, fd);
            handshaked = true;
            break;
        }
        int err = SSL_get_error(ssl, r);
        if (err == SSL_ERROR_WANT_READ) {
            printf("wantread\n");
            drain_wbio_to_socket(wbio, fd);
            feed_rbio_from_socket(rbio, fd);
        } else if (err == SSL_ERROR_WANT_WRITE) {
            printf("wantwrite\n");
            drain_wbio_to_socket(wbio, fd);
        } else {
            throw_ssl_err("SSL_do_handshake");
        }
    }

    // ★ Post-handshake sanity checks (optional but nice):
    // - Verify result must be X509_V_OK
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        throw std::runtime_error("certificate verification failed");
    }
    // - Enforced TLS version is 1.2 by configuration, but you can assert:
    const SSL_SESSION* sess = SSL_get0_session(ssl);
    if (SSL_SESSION_get_protocol_version(sess) != TLS1_2_VERSION) {
        throw std::runtime_error("negotiated protocol is not TLS 1.2");
    }

    // --- Example HTTP request over TLS -----------------------------------------
    const std::string request =
        "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";

    // Write plaintext → encrypted records appear in wbio → you send them
    {
        size_t off = 0;
        while (off < request.size()) {
            size_t wrote = 0;
            int r = SSL_write_ex(ssl, request.data() + off, request.size() - off, &wrote);
            if (r == 1) {
                off += wrote;
                drain_wbio_to_socket(wbio, fd);
            } else {
                int err = SSL_get_error(ssl, r);
                if (err == SSL_ERROR_WANT_READ) {
                    drain_wbio_to_socket(wbio, fd);
                    feed_rbio_from_socket(rbio, fd);
                } else if (err == SSL_ERROR_WANT_WRITE) {
                    drain_wbio_to_socket(wbio, fd);
                } else {
                    throw_ssl_err("SSL_write_ex");
                }
            }
        }
    }

    // Read loop
    std::vector<unsigned char> appbuf(32 * 1024);
    for (;;) {
        size_t got = 0;
        int r = SSL_read_ex(ssl, appbuf.data(), appbuf.size(), &got);
        if (r == 1) {
            //std::cout.write(reinterpret_cast<const char*>(appbuf.data()), got);
            continue;
        }
        int err = SSL_get_error(ssl, r);
        if (err == SSL_ERROR_WANT_READ) {
            drain_wbio_to_socket(wbio, fd);
            feed_rbio_from_socket(rbio, fd);
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            break; // clean shutdown by peer
        } else if (err == SSL_ERROR_WANT_WRITE) {
            drain_wbio_to_socket(wbio, fd);
        } else {
            throw_ssl_err("SSL_read_ex");
        }
    }

    // Shutdown (send close_notify; drain)
    int sdr = SSL_shutdown(ssl);
    if (sdr == 0) { // needs a second call per spec if bidirectional shutdown desired
        drain_wbio_to_socket(wbio, fd);
        // If you want full bidirectional shutdown, you can feed peer's close_notify here
        // and call SSL_shutdown(ssl) again until it returns 1.
    }
    drain_wbio_to_socket(wbio, fd);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ::close(fd);
    return 0;
}
