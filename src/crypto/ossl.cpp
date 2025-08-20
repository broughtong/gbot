///#pragma once

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <string>


static SSL_CTX* ctx = nullptr;

struct Connection
{
    SSL* ssl;
    BIO* wbio;
    BIO* rbio;
};

bool initSSL()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx)
        return false;

    if(!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION))
        return false; 

    if(!SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION))
        return false;

    if(!SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "aNULL:!eNULL:!MD5:!DSS"))
        return false;
    
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        return false;
    }



    return true;
}

bool initConnection(std::string hostname, Connection& connection)
{
    connection.ssl = SSL_new(ctx);
    if(!connection.ssl)
        return false;

    SSL_set_verify(connection.ssl, SSL_VERIFY_PEER, nullptr);

    if (SSL_set1_host(connection.ssl, hostname.c_str()) != 1)
        return false;

    X509_VERIFY_PARAM* param = SSL_get0_param(connection.ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

    if(SSL_set_tlsext_host_name(connection.ssl, hostname.c_str()) != 1)
        return false;

    long modes = SSL_get_mode(connection.ssl);
    modes |= SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_RELEASE_BUFFERS;
    SSL_set_mode(connection.ssl, modes);

    connection.rbio = BIO_new(BIO_s_mem());
    connection.wbio = BIO_new(BIO_s_mem());
    if (!connection.rbio || !connection.wbio)
        return false;

    SSL_set_bio(connection.ssl, connection.rbio, connection.wbio);

    SSL_set_connect_state(connection.ssl);

    return true;
}

bool isHandshakingFinished(Connection& connection)
{
    return SSL_is_init_finished(connection.ssl) == 1;
}

int processHandshakingState(Connection& connection)
{
    return SSL_do_handshake(connection.ssl);
}

int txHandshakeStep(Connection& connection, char* txBuffer, int txBufferSize)
{
    int pending = BIO_pending(connection.wbio);
    if (pending <= 0)
        return 0;

    int n = BIO_read(connection.wbio, txBuffer, std::min<int>(pending, txBufferSize));
    return n;
}

int rxHandshakeStep(Connection& connection, char* rxBuffer, int rxBufferSize)
{
    int w = BIO_write(connection.rbio, rxBuffer, rxBufferSize);
    return w;
}

int encryptBuffer(Connection& connection, const char* textBuffer, int textBufferSize, char* encryptedBuffer, int encryptedBufferSize)
{
    size_t wrote = 0;
    int r = SSL_write_ex(connection.ssl, textBuffer, textBufferSize, &wrote);

    int pending = BIO_pending(connection.wbio);
    if (pending <= 0)
        return 0;

    int n = BIO_read(connection.wbio, encryptedBuffer, std::min<int>(pending, encryptedBufferSize));
    return n;
}

int decryptBuffer(Connection& connection, char* encryptedBuffer, int encryptedBufferSize, char* textBuffer, int textBufferSize)
{
    int w = BIO_write(connection.rbio, encryptedBuffer, encryptedBufferSize);
    if(w <= 0)
        printf("error pushing to buf\n");

    size_t got = 0;
    int success = SSL_read_ex(connection.ssl, textBuffer, textBufferSize, &got);
    
    return got;
}

void closeConnection(Connection& connection)
{
    SSL_shutdown(connection.ssl);
    SSL_free(connection.ssl);
}

void closeSSL()
{
    SSL_CTX_free(ctx);
}

