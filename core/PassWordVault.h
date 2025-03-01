#pragma once
#include <sqlite3.h>
#include <vector>
#include <string>

class PasswordVault {
public:
    struct Codebook {
        int id;
        std::string name;
        std::string created_time;
    };

    struct PasswordEntry {
        int id;
        std::string address;
        std::string public_key;
        std::string encrypted_password;
        std::string notes;
        std::string created_time;
    };

    explicit PasswordVault(sqlite3* db);
    
    // 密码本操作
    bool CreateCodebook(const std::string& username, const std::string& name);
    bool DeleteCodebook(int codebook_id);
    std::vector<Codebook> GetUserCodebooks(const std::string& username);

    // 密码条目操作
    bool AddEntry(int codebook_id, 
                const std::string& address,
                const std::string& public_key,
                const std::string& encrypted_password,
                const std::string& notes = "");
    bool UpdateEntry(int entry_id,
                   const std::string& new_address,
                   const std::string& new_public_key,
                   const std::string& new_encrypted_password,
                   const std::string& new_notes);
    bool DeleteEntry(int entry_id);
    std::vector<PasswordEntry> GetEntries(int codebook_id, 
                                        const std::string& filter = "",
                                        int page = 0,
                                        int page_size = 50);

private:
    sqlite3* db_;

    bool BeginTransaction();
    bool CommitTransaction();
    bool RollbackTransaction();
    bool CheckCodebookExists(int codebook_id);
    bool ValidateCodebookName(const std::string& name);
};