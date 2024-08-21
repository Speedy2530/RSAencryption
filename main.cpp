#include "rsa_encryption.h"
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

// Function to encode binary data in Base64
std::string base64Encode(const std::string& binaryData) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Do not add newline
    bio = BIO_push(b64, bio);

    BIO_write(bio, binaryData.data(), binaryData.size());
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string base64Text(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);

    return base64Text;
}

int main() {
    RSAEncryption rsa;
    const std::string publicKeyFile = "keys/public_key.pem";
    const std::string privateKeyFile = "keys/private_key.pem";

    // Generate keys
    rsa.generateKeys(publicKeyFile, privateKeyFile);

    // Get the message to encrypt from the user
    std::string message;
    std::cout << "Enter the message to encrypt: ";
    std::getline(std::cin, message);

    std::cout << "\n";

    // Encrypt the message
    std::string encryptedMessage = rsa.encrypt(publicKeyFile, message);

    // Encode the encrypted message in Base64 for readability
    std::string encodedMessage = base64Encode(encryptedMessage);
    std::cout << "Encrypted (Base64): " << encodedMessage << std::endl;

    std::cout << "\n";

    // Decrypt the message
    std::string decryptedMessage = rsa.decrypt(privateKeyFile, encryptedMessage);
    std::cout << "Decrypted: " << decryptedMessage << std::endl;

    std::cout << "\n";

    return 0;
}