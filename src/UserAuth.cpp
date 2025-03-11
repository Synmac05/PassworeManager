#include "UserAuth.h"
#include <sodium.h>
#include <regex>
#include <algorithm>

UserAuth::UserAuth(const std::string& db_path) : db_(nullptr) {
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }
    
    if (sqlite3_open_v2(db_path.c_str(), &db_, 
                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                       nullptr) != SQLITE_OK) {
        throw std::runtime_error("Database open failed: " + std::string(sqlite3_errmsg(db_)));
    }
    
    if (!CreateTables()) {
        sqlite3_close_v2(db_);
        throw std::runtime_error("Table creation failed");
    }
}

UserAuth::~UserAuth() {
    if (db_) {
        sqlite3_close_v2(db_);
    }
}

bool UserAuth::CreateTables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS User (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS Codebook (
            codebook_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            codebook_name TEXT NOT NULL,
            created_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(username) REFERENCES User(username) ON DELETE CASCADE,
            UNIQUE(username, codebook_name)
        );
        
        CREATE TABLE IF NOT EXISTS PasswordEntry (
            entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            codebook_id INTEGER NOT NULL,
            created_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            address TEXT NOT NULL CHECK(length(address) <= 253),
            public_key BLOB NOT NULL CHECK(length(public_key) <= 4096),
            encrypted_password BLOB NOT NULL CHECK(length(encrypted_password) <= 512),
            notes TEXT CHECK(length(notes) <= 1024),
            FOREIGN KEY(codebook_id) REFERENCES Codebook(codebook_id) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_codebook ON PasswordEntry(codebook_id);
        PRAGMA foreign_keys = ON;
    )";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::string error = errMsg ? errMsg : "Unknown error";
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool UserAuth::Register(const std::string& username, const std::string& password) {
    if (username.empty() || username.length() > 50) {
        throw std::invalid_argument("Username must be 1-50 characters");
    }
    
    if (!ValidatePassword(password)) {
        throw std::invalid_argument("Password does not meet complexity requirements");
    }

    if (CheckUserExists(username)) {
        return false;
    }

    std::string hash = GenerateHash(password);
    
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO User (username, password_hash) VALUES (?, ?)";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Prepare statement failed: " + std::string(sqlite3_errmsg(db_)));
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_STATIC);

    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool UserAuth::Login(const std::string& username, const std::string& password, 
                   std::vector<CodebookInfo>& codebooks) {
    std::string stored_hash;
    if (!GetUserHash(username, stored_hash)) {
        return false;
    }
    
    if (crypto_pwhash_str_verify(stored_hash.c_str(),
                                password.c_str(),
                                password.length()) != 0) {
        return false;
    }
    
    return GetUserCodebooks(username, codebooks);
}

bool UserAuth::CheckUserExists(const std::string& username) {
    sqlite3_stmt* stmt;
    const char* sql = "SELECT 1 FROM User WHERE username = ?";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Prepare statement failed: " + std::string(sqlite3_errmsg(db_)));
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

bool UserAuth::ValidatePassword(const std::string& password) {
    std::regex pattern(R"((?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,32})");
    return std::regex_match(password, pattern);
}

std::string UserAuth::GenerateHash(const std::string& password) {
    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, password.c_str(), password.length(),
                         crypto_pwhash_OPSLIMIT_SENSITIVE,
                         crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        throw std::runtime_error("Password hashing failed");
    }
    return std::string(hash);
}

bool UserAuth::GetUserHash(const std::string& username, std::string& stored_hash) {
    sqlite3_stmt* stmt;
    const char* sql = "SELECT password_hash FROM User WHERE username = ?";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Prepare statement failed: " + std::string(sqlite3_errmsg(db_)));
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return false;
    }
    
    stored_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);
    return true;
}

bool UserAuth::GetUserCodebooks(const std::string& username, std::vector<CodebookInfo>& codebooks) {
    sqlite3_stmt* stmt;
    const char* sql = R"(
        SELECT codebook_id, codebook_name, created_time
        FROM Codebook
        WHERE username = ?
        ORDER BY created_time DESC
    )";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Prepare statement failed: " + std::string(sqlite3_errmsg(db_)));
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CodebookInfo info;
        info.id = sqlite3_column_int(stmt, 0);
        info.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        info.created_time = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        codebooks.push_back(info);
    }
    
    sqlite3_finalize(stmt);
    return true;
}