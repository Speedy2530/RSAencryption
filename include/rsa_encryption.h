#ifndef RSA_ENCRYPTION_H
#define RSA_ENCRYPTION_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>

class RSAEncryption {
public:
    RSAEncryption();
    ~RSAEncryption();

    void generateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile);
    std::string encrypt(const std::string& publicKeyFile, const std::string& plaintext);
    std::string decrypt(const std::string& privateKeyFile, const std::string& ciphertext);

private:
    void handleOpenSSLError();
};

#endif
