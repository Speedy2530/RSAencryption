#include "rsa_encryption.h"
#include <fstream>
#include <iostream>

RSAEncryption::RSAEncryption() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

RSAEncryption::~RSAEncryption() {
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
}

void RSAEncryption::generateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile) {
    int bits = 2048;
    unsigned long e = RSA_F4;

    RSA* rsa = RSA_generate_key(bits, e, nullptr, nullptr);

    BIO* pri = BIO_new_file(privateKeyFile.c_str(), "w+");
    PEM_write_bio_RSAPrivateKey(pri, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free_all(pri);

    BIO* pub = BIO_new_file(publicKeyFile.c_str(), "w+");
    PEM_write_bio_RSAPublicKey(pub, rsa);
    BIO_free_all(pub);

    RSA_free(rsa);
}

std::string RSAEncryption::encrypt(const std::string& publicKeyFile, const std::string& plaintext) {
    RSA* rsa = nullptr;
    BIO* keybio = BIO_new_file(publicKeyFile.c_str(), "r");
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, nullptr, nullptr);

    if (rsa == nullptr) {
        handleOpenSSLError();
        return "";
    }

    int rsaLen = RSA_size(rsa);
    std::string encryptedText(rsaLen, '\0');
    int result = RSA_public_encrypt(plaintext.size(), (const unsigned char*)plaintext.c_str(),
                                    (unsigned char*)encryptedText.data(), rsa, RSA_PKCS1_PADDING);

    if (result == -1) {
        handleOpenSSLError();
    }

    RSA_free(rsa);
    BIO_free_all(keybio);

    return encryptedText;
}

std::string RSAEncryption::decrypt(const std::string& privateKeyFile, const std::string& ciphertext) {
    RSA* rsa = nullptr;
    BIO* keybio = BIO_new_file(privateKeyFile.c_str(), "r");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, nullptr, nullptr);

    if (rsa == nullptr) {
        handleOpenSSLError();
        return "";
    }

    int rsaLen = RSA_size(rsa);
    std::string decryptedText(rsaLen, '\0');
    int result = RSA_private_decrypt(ciphertext.size(), (const unsigned char*)ciphertext.c_str(),
                                     (unsigned char*)decryptedText.data(), rsa, RSA_PKCS1_PADDING);

    if (result == -1) {
        handleOpenSSLError();
    }

    RSA_free(rsa);
    BIO_free_all(keybio);

    return decryptedText;
}

void RSAEncryption::handleOpenSSLError() {
    char buffer[120];
    ERR_error_string(ERR_get_error(), buffer);
    std::cerr << "OpenSSL Error: " << buffer << std::endl;
}
