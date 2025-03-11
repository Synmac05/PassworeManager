#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QPlainTextEdit>
#include "PassWordVault.h"
#include "PassWordGen.h"
#include "CryptoModule.h"

class PasswordManagerWindow : public QWidget {
    Q_OBJECT
public:
    explicit PasswordManagerWindow(sqlite3* db, 
                                  const std::string& username,
                                  const std::string& masterPassword,
                                  int codebookId,
                                  QWidget* parent = nullptr);
    
private Q_SLOTS:
    void addEntry();
    void deleteEntry();
    void loadEntries();
    void copyPassword();
    void generatePassword(int length);
    void refreshEntries();
    void showPassword(int row, int column);

private:
    void setupUI();
    void showEvent(QShowEvent* event) override;

    PasswordVault vault;
    CryptoModule crypto_;
    PasswordGenerator generator;
    QTableWidget* entriesTable;
    QLineEdit* addressInput;
    QLineEdit* passwordInput;
    QPlainTextEdit* notesInput;
    
    const std::string masterPassword;
    const int currentCodebookId;
    std::vector<PasswordVault::PasswordEntry> entries;
};