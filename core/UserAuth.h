#pragma once
#include <sqlite3.h>
#include <string>
#include <vector>
#include <stdexcept>

class UserAuth {
public:
    struct CodebookInfo {
        int id;
        std::string name;
        std::string created_time;
    };

    explicit UserAuth(const std::string& db_path = "UserAuth.db");
    ~UserAuth();

    bool Register(const std::string& username, const std::string& password);
    bool Login(const std::string& username, const std::string& password, 
              std::vector<CodebookInfo>& codebooks);
    
    sqlite3* GetDatabaseHandle() const { return db_; }

private:
    sqlite3* db_;

    bool CreateTables();
    bool CheckUserExists(const std::string& username);
    bool ValidatePassword(const std::string& password);
    std::string GenerateHash(const std::string& password);
    bool GetUserHash(const std::string& username, std::string& stored_hash);
    bool GetUserCodebooks(const std::string& username, std::vector<CodebookInfo>& codebooks);
};