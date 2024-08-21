#include "rsa_encryption.h"
#include <iostream>

int main() {
    RSAEncryption rsa;
    const std::string publicKeyFile = "keys/public_key.pem";
    const std::string privateKeyFile = "keys/private_key.pem";

    // Generate keys
    rsa.generateKeys(publicKeyFile, privateKeyFile);

    // Encrypt a message
    std::string message = "Hello, World!";
    std::string encryptedMessage = rsa.encrypt(publicKeyFile, message);
    std::cout << "Encrypted: " << encryptedMessage << std::endl;

    // Decrypt the message
    std::string decryptedMessage = rsa.decrypt(privateKeyFile, encryptedMessage);
    std::cout << "Decrypted: " << decryptedMessage << std::endl;

    return 0;
}
