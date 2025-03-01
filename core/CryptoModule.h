#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>

class CryptoModule {
public:
    CryptoModule();
    std::vector<uint8_t> encrypt(const std::string& masterPassword, const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::string& masterPassword, const std::vector<uint8_t>& packedData);

private:
    void validateSodiumInit() const;
};