#include "sample_tls_crypto.hpp"
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <algorithm>

void TLSClientNB::throw_ssl_err(const char* where) {
    unsigned long e = ERR_get_error();
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    throw std::runtime_error(std::string(where) + ": " + buf);
}

void TLSClientNB::drain_wbio(BIO* wbio, std::vector<uint8_t>& out) {
    char buf[16 * 1024];
    for (;;) {
        int pending = BIO_pending(wbio);
        if (pending <= 0) break;
        int n = BIO_read(wbio, buf, std::min<int>(pending, (int)sizeof(buf)));
        if (n > 0) out.insert(out.end(), buf, buf + n);
        else break;
    }
}

TLSClientNB::TLSClientNB(const std::string& host) : host_(host) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ensure_tls12_ctx();
    make_connection_obj();
}

TLSClientNB::~TLSClientNB() {
    if (ssl_) SSL_free(ssl_);
    if (ctx_) SSL_CTX_free(ctx_);
}

void TLSClientNB::ensure_tls12_ctx() {
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) throw_ssl_err("SSL_CTX_new");

    // TLS 1.2 only
    if (!SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION)) throw_ssl_err("min_proto");
    if (!SSL_CTX_set_max_proto_version(ctx_, TLS1_2_VERSION)) throw_ssl_err("max_proto");

    // Strong TLS 1.2 cipher list (ECDHE + AEAD)
    if (!SSL_CTX_set_cipher_list(ctx_,
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:!"
        "aNULL:!eNULL:!MD5:!DSS"))
    {
        throw_ssl_err("cipher_list");
    }

    // Trust store (system default). Swap for SSL_CTX_load_verify_locations if you ship a bundle.
    if (SSL_CTX_set_default_verify_paths(ctx_) != 1)
        throw_ssl_err("default_verify_paths");
}

void TLSClientNB::make_connection_obj() {
    ssl_ = SSL_new(ctx_);
    if (!ssl_) throw_ssl_err("SSL_new");

    SSL_set_verify(ssl_, SSL_VERIFY_PEER, nullptr);

    // Hostname verification (OpenSSL >= 1.1.0)
    if (SSL_set1_host(ssl_, host_.c_str()) != 1) throw_ssl_err("SSL_set1_host");
    X509_VERIFY_PARAM* param = SSL_get0_param(ssl_);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

    // SNI
    if (SSL_set_tlsext_host_name(ssl_, host_.c_str()) != 1)
        throw_ssl_err("SSL_set_tlsext_host_name");

    // Modes for low-latency partial writes & buffer reuse
    long m = SSL_get_mode(ssl_);
    m |= SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_RELEASE_BUFFERS;
    SSL_set_mode(ssl_, m);

    rbio_ = BIO_new(BIO_s_mem());
    wbio_ = BIO_new(BIO_s_mem());
    if (!rbio_ || !wbio_) throw_ssl_err("BIO_new");
    SSL_set_bio(ssl_, rbio_, wbio_); // SSL now owns BIOs

    SSL_set_connect_state(ssl_);
}

void TLSClientNB::feed_encrypted(const uint8_t* data, size_t len) {
    if (len == 0) return;
    int w = BIO_write(rbio_, data, (int)len);
    if (w <= 0) throw_ssl_err("BIO_write(rbio_)");
}

size_t TLSClientNB::drain_encrypted(std::vector<uint8_t>& out) {
    size_t before = out.size();
    drain_wbio(wbio_, out);
    return out.size() - before;
}

TLSStatus TLSClientNB::handshake_step() {
    TLSStatus st{};
    if (handshake_done_) { st.handshake_done = true; return st; }

    int r = SSL_do_handshake(ssl_);
    if (r == 1) {
        // Finished; flush any final flight
        st.want_write |= BIO_pending(wbio_) > 0;
        // Verify chain+hostname
        if (SSL_get_verify_result(ssl_) != X509_V_OK)
            throw std::runtime_error("certificate verification failed");
        const SSL_SESSION* s = SSL_get0_session(ssl_);
        if (!s || SSL_SESSION_get_protocol_version(s) != TLS1_2_VERSION)
            throw std::runtime_error("negotiated protocol is not TLS 1.2");
        handshake_done_ = true;
        st.handshake_done = true;
        return st;
    }
    int err = SSL_get_error(ssl_, r);
    if (err == SSL_ERROR_WANT_READ) {
        st.want_read = true;
    } else if (err == SSL_ERROR_WANT_WRITE) {
        st.want_write = true;
    } else {
        throw_ssl_err("SSL_do_handshake");
    }
    // If wbio has bytes, we should write them
    if (BIO_pending(wbio_) > 0) st.want_write = true;
    return st;
}

TLSStatus TLSClientNB::write_plain(const uint8_t* data, size_t len,
                                   std::vector<uint8_t>& out_cipher, size_t& consumed) {
    TLSStatus st{};
    consumed = 0;
    if (!handshake_done_) { st = handshake_step(); return st; }

    size_t wrote = 0;
    int r = SSL_write_ex(ssl_, data, len, &wrote);
    if (r == 1) {
        consumed = wrote;
    } else {
        int err = SSL_get_error(ssl_, r);
        if (err == SSL_ERROR_WANT_READ) st.want_read = true;
        else if (err == SSL_ERROR_WANT_WRITE) st.want_write = true;
        else throw_ssl_err("SSL_write_ex");
        consumed = wrote; // may have partially consumed
    }
    if (BIO_pending(wbio_) > 0) {
        drain_wbio(wbio_, out_cipher);
        st.want_write = true;
    }
    st.handshake_done = true;
    return st;
}

TLSStatus TLSClientNB::read_plain(std::vector<uint8_t>& out_plain) {
    TLSStatus st{};
    if (!handshake_done_) { st = handshake_step(); return st; }

    char buf[16 * 1024];
    for (;;) {
        size_t got = 0;
        int r = SSL_read_ex(ssl_, buf, sizeof(buf), &got);
        if (r == 1 && got > 0) {
            out_plain.insert(out_plain.end(), buf, buf + got);
            continue; // grab all available plaintext
        }
        int err = SSL_get_error(ssl_, r);
        if (err == SSL_ERROR_WANT_READ) { st.want_read = true; break; }
        if (err == SSL_ERROR_WANT_WRITE) { st.want_write = true; break; }
        if (err == SSL_ERROR_ZERO_RETURN) { st.closed = true; got_shutdown_ = true; break; }
        // If r==0 but not ZERO_RETURN, likely needs more data
        if (r == 0) { st.want_read = true; break; }
        throw_ssl_err("SSL_read_ex");
    }
    // If TLS produced control records, they’re in wbio
    if (BIO_pending(wbio_) > 0) st.want_write = true;
    st.handshake_done = true;
    return st;
}

TLSStatus TLSClientNB::start_shutdown(std::vector<uint8_t>& out_cipher) {
    TLSStatus st{};
    if (!sent_shutdown_) {
        int r = SSL_shutdown(ssl_); // first call queues close_notify to wbio
        (void)r;
        drain_wbio(wbio_, out_cipher);
        sent_shutdown_ = true;
        st.want_write = !out_cipher.empty();
    }
    st.closed = got_shutdown_;
    st.handshake_done = handshake_done_;
    return st;
}
