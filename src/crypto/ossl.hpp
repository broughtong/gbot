#pragma once

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <string>

struct Connection
{
    SSL* ssl;
    BIO* wbio;
    BIO* rbio;
};

bool initSSL();

bool initConnection(std::string hostname, Connection& connection);

bool isHandshakingFinished(Connection& connection);

int processHandshakingState(Connection& connection);

int txHandshakeStep(Connection& connection, char* txBuffer, int txBufferSize);

int rxHandshakeStep(Connection& connection, char* rxBuffer, int rxBufferSize);

int encryptBuffer(Connection& connection, const char* textBuffer, int textBufferSize, char* encryptedBuffer, int encryptedBufferSize);

int decryptBuffer(Connection& connection, char* encryptedBuffer, int encryptedBufferSize, char* textBuffer, int textBufferSize);

void closeConnection(Connection& connection);

void closeSSL();
