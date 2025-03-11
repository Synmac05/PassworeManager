#include "PassWordGen.h"
#include <sodium.h>
#include <stdexcept>

const std::string PasswordGenerator::basic_charset = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789";

const std::string PasswordGenerator::extended_charset = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!@#$%^&*()-_=+[]{}|;:,.<>?";

PasswordGenerator::PasswordGenerator(size_t length) 
    : length_(length)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }
}

std::string PasswordGenerator::generateBasic() const
{
    std::string password;
    password.reserve(length_);
    
    const auto& charset = basic_charset;
    const size_t charset_size = charset.size();
    
    //利用 libsodium: randombytes 生成随机密码
    for (size_t i = 0; i < length_; ++i) {
        uint32_t random_index = randombytes_uniform(charset_size);
        password += charset[random_index];
    }
    
    return password;
}

std::string PasswordGenerator::generateExtended() const
{
    std::string password;
    password.reserve(length_);
    
    const auto& charset = extended_charset;
    const size_t charset_size = charset.size();
    
    for (size_t i = 0; i < length_; ++i) {
        uint32_t random_index = randombytes_uniform(charset_size);
        password += charset[random_index];
    }
    
    return password;
}