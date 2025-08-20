#include "ossl.hpp"
#include <openssl/err.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string>
#include <chrono>
#include <thread>

void print_hex(const char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char byte = static_cast<unsigned char>(data[i]);
        std::printf("%02X ", byte);
    }
    std::printf("\n");
}


void print_ascii(const char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%c", buf[i], (unsigned char)buf[i]);
    }
}

int connect_tcp(const std::string& host, const std::string& port)
{
    addrinfo hints{}, *res=nullptr;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (auto p=res; p; p=p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == -1) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int main()
{
    initSSL();

    Connection conn;
    std::string hostname = "graphicsblast.com";
    std::string port = "443";

    if(!initConnection(hostname, conn))
    {
        printf("Unable to creat conn");
        return -1;
    }

    int fd = connect_tcp(hostname, port);
    if(fd < 0)
    {
        printf("Unable to open socket\n");
        return -1;
    }

    const int rxBufferSize = 14000;
    const int txBufferSize = 1400;
    char* rxBuffer = new char[rxBufferSize];
    char* txBuffer = new char[txBufferSize];

    printf("conn open, attempting handshake\n");

    bool handshaked = false;
    while(!handshaked)
    {
        int state = processHandshakingState(conn);
        if(state == 1)
        {
            //flush pending
            int toWriteSize = txHandshakeStep(conn, txBuffer, txBufferSize); 
            if(toWriteSize)
            {
                ssize_t s = ::send(fd, txBuffer, toWriteSize, 0);
                if(s <= 0)
                    printf("Failed\n");
            }
            handshaked = true;
            break;
        }

        int err = SSL_get_error(conn.ssl, state);
        if(err == SSL_ERROR_WANT_WRITE)
        {
            //flush pending
            int toWriteSize = txHandshakeStep(conn, txBuffer, txBufferSize); 
            if(toWriteSize)
            {
                ssize_t s = ::send(fd, txBuffer, toWriteSize, 0);
                if(s <= 0)
                    printf("Failed\n");
            }
        }
        else if(err == SSL_ERROR_WANT_READ)
        {
            //flush pending
            int toWriteSize = txHandshakeStep(conn, txBuffer, txBufferSize); 
            while(toWriteSize)
            {
                ssize_t s = ::send(fd, txBuffer, toWriteSize, 0);
                if(s <= 0)
                    printf("Failed\n");
                toWriteSize = txHandshakeStep(conn, txBuffer, txBufferSize); 
            }

            char inbuf[16 * 1024];
            ssize_t n = ::recv(fd, inbuf, sizeof(inbuf), 0);
            if (n == 0) printf("peer closed\n");
            if (n < 0)  printf("recv failed\n");
            int w = BIO_write(conn.rbio, inbuf, (int)n);
            if (w <= 0) printf("bio_write failed\n");
        }
        else
        {
            while ((err = ERR_get_error()) != 0) {
                char buf[256];
                ERR_error_string_n(err, buf, sizeof(buf));
                printf("OpenSSL error: %s\n", buf);
            }

            return -1;
        }
    }

    printf("Handshook!\n");
    printf("%i\n", isHandshakingFinished(conn));

    const std::string request =
        "GET / HTTP/1.1\r\nHost: " + hostname + "\r\nConnection: close\r\n\r\n";

    int toWriteSize = encryptBuffer(conn, request.c_str(), request.length(), txBuffer, txBufferSize);
    ssize_t s = ::send(fd, txBuffer, toWriteSize, 0);
    printf("Writing %i bytes, wrote %li bytes\n", toWriteSize, s);

    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    printf("Reading...\n");

    ssize_t n = ::recv(fd, rxBuffer, rxBufferSize, 0);
    if (n == 0) printf("peer closed\n");
    if (n < 0)  printf("recv failed\n");
    printf("Recvd %li bytes\n", n);

    char plainBuffer[2048 * 16];
    int plainBufferSize = 2048 * 16;
    int bytesIn = decryptBuffer(conn, rxBuffer, n, plainBuffer, plainBufferSize);
    printf("recv %i\n", bytesIn); 
    print_ascii(plainBuffer, bytesIn);

    delete[] txBuffer;
    delete[] rxBuffer;

    closeConnection(conn);

    closeSSL();

    return 0;
}
