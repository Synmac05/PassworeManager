#include "PassWordVault.h"
#include <stdexcept>
#include <algorithm>
#include <cstdint>
#include <regex>
using namespace std;

PasswordVault::PasswordVault(sqlite3* db) : db_(db) {
    if (!db_) {
        throw invalid_argument("Invalid database connection");
    }
}

bool PasswordVault::CreateCodebook(const string& username, const string& name) {
    if (!ValidateCodebookName(name)) {
        throw invalid_argument("密码本名称不合法！（仅允许数字，字母，汉字和常用符号）");
    }

    const char* sql = R"(
        INSERT INTO Codebook (username, codebook_name)
        VALUES (?, ?)
        ON CONFLICT(username, codebook_name) DO NOTHING
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw runtime_error("Prepare failed: " + string(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_STATIC);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool PasswordVault::DeleteCodebook(int codebook_id) {
    if (!CheckCodebookExists(codebook_id)) {
        return false;
    }

    if (!BeginTransaction()) {
        throw runtime_error("Failed to start transaction");
    }

    try {
        // 删除关联条目
        const char* deleteEntriesSql = "DELETE FROM PasswordEntry WHERE codebook_id = ?";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_, deleteEntriesSql, -1, &stmt, nullptr) != SQLITE_OK) {
            RollbackTransaction();
            throw runtime_error("Prepare failed: " + string(sqlite3_errmsg(db_)));
        }
        
        sqlite3_bind_int(stmt, 1, codebook_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            RollbackTransaction();
            throw runtime_error("Delete entries failed: " + string(sqlite3_errmsg(db_)));
        }
        sqlite3_finalize(stmt);

        // 删除密码本
        const char* deleteCodebookSql = "DELETE FROM Codebook WHERE codebook_id = ?";
        if (sqlite3_prepare_v2(db_, deleteCodebookSql, -1, &stmt, nullptr) != SQLITE_OK) {
            RollbackTransaction();
            throw runtime_error("Prepare failed: " + string(sqlite3_errmsg(db_)));
        }
        
        sqlite3_bind_int(stmt, 1, codebook_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            RollbackTransaction();
            throw runtime_error("Delete codebook failed: " + string(sqlite3_errmsg(db_)));
        }
        sqlite3_finalize(stmt);

        if (!CommitTransaction()) {
            throw runtime_error("Commit failed: " + string(sqlite3_errmsg(db_)));
        }
        return true;

    } catch (...) {
        RollbackTransaction();
        throw;
    }
}

int PasswordVault::GetCodebookId(const std::string& username, const std::string& codebookName)
{
    const char* sql = "SELECT codebook_id FROM Codebook WHERE username = ? AND codebook_name = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Prepare failed: " + std::string(sqlite3_errmsg(db_)));
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, codebookName.c_str(), -1, SQLITE_STATIC);
    
    int codebookId = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        codebookId = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return codebookId;
}

vector<PasswordVault::Codebook> PasswordVault::GetUserCodebooks(const string& username) const {
    const char* sql = R"(
        SELECT codebook_id, codebook_name, created_time
        FROM Codebook
        WHERE username = ?
        ORDER BY created_time DESC
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw runtime_error("Prepare failed: " + string(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    vector<Codebook> codebooks;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Codebook cb;
        cb.id = sqlite3_column_int(stmt, 0);
        cb.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        cb.created_time = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        codebooks.push_back(cb);
    }

    sqlite3_finalize(stmt);
    return codebooks;
}

bool PasswordVault::AddEntry(int codebook_id,
    const std::string& address,
    const std::vector<uint8_t>& encrypted_password,
    const std::string& notes)
{
    const std::vector<uint8_t>& public_key = {1};
    const char* sql = R"(
    INSERT INTO PasswordEntry 
    (codebook_id, address, public_key, encrypted_password, notes)
    VALUES (?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    throw std::runtime_error("Prepare failed: " + std::string(sqlite3_errmsg(db_)));
    }

    // 正确绑定二进制数据 [关键修改]
    sqlite3_bind_int(stmt, 1, codebook_id);
    sqlite3_bind_text(stmt, 2, address.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, public_key.data(), public_key.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, encrypted_password.data(), encrypted_password.size(), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, notes.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool PasswordVault::DeleteEntry(int entry_id) {
    if (!BeginTransaction()) {
        throw std::runtime_error("Failed to start transaction");
    }

    try {
        // 删除条目
        sqlite3_stmt* stmt;
        const char* sql = "DELETE FROM PasswordEntry WHERE entry_id = ?";
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Prepare failed: " + std::string(sqlite3_errmsg(db_)));
        }
        
        sqlite3_bind_int(stmt, 1, entry_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            RollbackTransaction();
            throw std::runtime_error("Delete entry failed: " + std::string(sqlite3_errmsg(db_)));
        }
        
        sqlite3_finalize(stmt);
        
        if (!CommitTransaction()) {
            throw std::runtime_error("Commit failed: " + std::string(sqlite3_errmsg(db_)));
        }
        
        return sqlite3_changes(db_) > 0;

    } catch (...) {
        RollbackTransaction();
        throw;
    }
}

vector<PasswordVault::PasswordEntry> PasswordVault::GetEntries(int codebook_id, 
                                                             const string& filter,
                                                             int page, 
                                                             int page_size) 
{
    const char* sql = R"(
        SELECT entry_id, address, public_key, encrypted_password, notes, created_time
        FROM PasswordEntry
        WHERE codebook_id = ? 
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw runtime_error("Prepare failed: " + string(sqlite3_errmsg(db_)));
    }

    string filter_pattern = "%" + filter + "%";
    int offset = page * page_size;

    sqlite3_bind_int(stmt, 1, codebook_id);
    sqlite3_bind_text(stmt, 2, filter_pattern.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, page_size);
    sqlite3_bind_int(stmt, 4, offset);

    vector<PasswordEntry> entries;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PasswordEntry entry;
        entry.id = sqlite3_column_int(stmt, 0);
        entry.address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        entry.public_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        const void* blob_data = sqlite3_column_blob(stmt, 3);
        int blob_size = sqlite3_column_bytes(stmt, 3);
        entry.encrypted_password.assign(static_cast<const unsigned char*>(blob_data), static_cast<const unsigned char*>(blob_data) + blob_size);
        entry.notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        entry.created_time = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        entries.push_back(entry);
    }

    sqlite3_finalize(stmt);
    return entries;
}

bool PasswordVault::UpdateEntry(int entry_id,
    const std::string& new_address,
    const std::string& new_public_key,
    const std::string& new_encrypted_password,
    const std::string& new_notes) 
{
    // 验证输入参数
    if (new_address.empty() || new_address.length() > 253) {
        throw std::invalid_argument("Address must be 1-253 characters");
    }
    if (new_public_key.empty() || new_public_key.length() > 4096) {
        throw std::invalid_argument("Public key is invalid");
    }
    if (new_encrypted_password.empty() || new_encrypted_password.length() > 512) {
        throw std::invalid_argument("Encrypted password is invalid");
    }

    const char* sql = R"(
        UPDATE PasswordEntry SET
        address = ?,
        public_key = ?,
        encrypted_password = ?,
        notes = ?
        WHERE entry_id = ?
        )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Prepare failed: " + std::string(sqlite3_errmsg(db_)));
    }

    // 绑定参数
    sqlite3_bind_text(stmt, 1, new_address.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, new_public_key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, new_encrypted_password.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, new_notes.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, entry_id);

    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    int rowsAffected = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    return success && (rowsAffected > 0);
}

// 事务处理方法
bool PasswordVault::BeginTransaction() {
    return sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool PasswordVault::CommitTransaction() {
    return sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool PasswordVault::RollbackTransaction() {
    return sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool PasswordVault::CheckCodebookExists(int codebook_id) {
    const char* sql = "SELECT 1 FROM Codebook WHERE codebook_id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw runtime_error("Prepare failed: " + string(sqlite3_errmsg(db_)));
    }
    
    sqlite3_bind_int(stmt, 1, codebook_id);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    
    return exists;
}

bool PasswordVault::ValidateCodebookName(const std::string& name) {
    if (name.empty() || name.size() > 100) return false;

    // 匹配规则：
    // 1. 允许的ASCII字符：字母、数字、下划线、连字符、常见符号
    // 2. 允许的中文字符：通过UTF-8的三字节编码范围进行匹配
    const std::regex pattern(
        R"(^([A-Za-z0-9_\-\@\$!%\*\#\?&]|[\xE4-\xE9][\x80-\xBF]{2}){1,100}$)"
    );

    return std::regex_match(name, pattern);
}