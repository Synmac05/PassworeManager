#include "CryptoModule.h"
#include <sodium.h>
#include <vector>
#include <stdexcept>
#include <iterator>

CryptoModule::CryptoModule() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }
}

std::vector<uint8_t> CryptoModule::encrypt(const std::string& masterPassword, const std::vector<uint8_t>& plaintext) {
    // Generate random salt
    std::vector<uint8_t> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());

    // Derive key using Argon2id
    std::vector<uint8_t> key(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(
        key.data(), key.size(),
        masterPassword.c_str(), masterPassword.length(),
        salt.data(),
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Key derivation failed");
    }

    // Generate random nonce
    std::vector<uint8_t> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    // Encrypt data
    std::vector<uint8_t> ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(
        ciphertext.data(),
        plaintext.data(), plaintext.size(),
        nonce.data(),
        key.data()) != 0) {
        throw std::runtime_error("Encryption failed");
    }

    // Combine components
    std::vector<uint8_t> packedData;
    packedData.reserve(salt.size() + nonce.size() + ciphertext.size());
    packedData.insert(packedData.end(), salt.begin(), salt.end());
    packedData.insert(packedData.end(), nonce.begin(), nonce.end());
    packedData.insert(packedData.end(), ciphertext.begin(), ciphertext.end());

    return packedData;
}

std::vector<uint8_t> CryptoModule::decrypt(const std::string& masterPassword, const std::vector<uint8_t>& packedData) {
    const size_t minSize = crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
    if (packedData.size() < minSize) {
        throw std::runtime_error("Invalid packed data format");
    }

    // Extract salt
    auto saltBegin = packedData.begin();
    auto saltEnd = saltBegin + crypto_pwhash_SALTBYTES;
    std::vector<uint8_t> salt(saltBegin, saltEnd);

    // Extract nonce
    auto nonceBegin = saltEnd;
    auto nonceEnd = nonceBegin + crypto_secretbox_NONCEBYTES;
    std::vector<uint8_t> nonce(nonceBegin, nonceEnd);

    // Extract ciphertext
    auto ciphertextBegin = nonceEnd;
    std::vector<uint8_t> ciphertext(ciphertextBegin, packedData.end());

    // Re-derive key
    std::vector<uint8_t> key(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(
        key.data(), key.size(),
        masterPassword.c_str(), masterPassword.length(),
        salt.data(),
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Key derivation failed");
    }

    // Decrypt data
    std::vector<uint8_t> plaintext(ciphertext.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(
        plaintext.data(),
        ciphertext.data(), ciphertext.size(),
        nonce.data(),
        key.data()) != 0) {
        throw std::runtime_error("Decryption failed: incorrect password or corrupted data");
    }

    return plaintext;
}