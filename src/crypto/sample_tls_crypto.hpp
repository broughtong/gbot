#pragma once
#include <openssl/ssl.h>
#include <string>
#include <vector>
#include <cstdint>

struct TLSStatus {
    bool want_read  = false;  // needs more ciphertext from peer
    bool want_write = false;  // has ciphertext to flush / TLS wants to write more
    bool handshake_done = false;
    bool closed = false;      // peer sent close_notify (or local shutdown finished)
};

class TLSClientNB {
public:
    explicit TLSClientNB(const std::string& host);
    ~TLSClientNB();

    // --- Wiring (no syscalls inside) ---
    // Feed encrypted bytes received from socket.
    void feed_encrypted(const uint8_t* data, size_t len);

    // Drain encrypted bytes to send on your socket.
    // Returns number of bytes appended into out.
    size_t drain_encrypted(std::vector<uint8_t>& out);

    // --- Handshake driver (call whenever you fed/ drained or socket became writable) ---
    TLSStatus handshake_step();  // advances handshake; never blocks

    // --- Application I/O (after handshake_done) ---
    // Encrypt plaintext -> ciphertext to send (appends to out_cipher). 'consumed' is how much plaintext used.
    TLSStatus write_plain(const uint8_t* data, size_t len,
                          std::vector<uint8_t>& out_cipher, size_t& consumed);

    // Decrypt whatever is available (after you feed_encrypted); appends plaintext to out_plain.
    TLSStatus read_plain(std::vector<uint8_t>& out_plain);

    // Initiate graceful close; appends close_notify to out_cipher (if any).
    TLSStatus start_shutdown(std::vector<uint8_t>& out_cipher);

    // Helpers
    bool handshake_complete() const { return handshake_done_; }

private:
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_     = nullptr;
    BIO* rbio_    = nullptr;  // in from network
    BIO* wbio_    = nullptr;  // out to network
    std::string host_;
    bool handshake_done_ = false;
    bool sent_shutdown_  = false;
    bool got_shutdown_   = false;

    void ensure_tls12_ctx();         // ctx_ init with TLS 1.2 only, trust, policy
    void make_connection_obj();      // ssl_ + BIOs, SNI + hostname verification
    static void throw_ssl_err(const char* where);
    static void drain_wbio(BIO* wbio, std::vector<uint8_t>& out);
};
