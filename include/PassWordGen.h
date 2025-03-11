#pragma once
#include <string>
#include <cstddef>

class PasswordGenerator {
public:
    explicit PasswordGenerator(size_t length = 12);
    
    std::string generateBasic() const;    // 仅字母数字
    std::string generateExtended() const; // 包含特殊字符

private:
    size_t length_;
    
    static const std::string basic_charset;     // 大小写字母+数字
    static const std::string extended_charset;  // 原字符集
};