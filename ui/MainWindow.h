#pragma once
#include <QWidget>
#include <QListWidget>
#include "PasswordVault.h"
#include "UserAuth.h"

class MainWindow : public QWidget
{
    Q_OBJECT
public:
    MainWindow(sqlite3* db, const std::string &username, const std::string &masterPassword, QWidget *parent = nullptr);
    sqlite3* GetDatabase() const { return db_; }

private Q_SLOTS:
    void addCodebook();
    void deleteCodebook();
    void openCodebook();

private:
    sqlite3* db_;
    std::string masterPassword_;
    PasswordVault vault;
    std::string user;
    QListWidget *codebookList;
    QString getOriginalName(const QString& displayText);
    void setupUI();
    void loadCodebooks();
};