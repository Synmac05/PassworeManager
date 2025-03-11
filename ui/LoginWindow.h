#pragma once
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include "UserAuth.h"

class LoginWindow : public QWidget
{
    Q_OBJECT
public:
    explicit LoginWindow(QWidget *parent = nullptr);
    std::string GetMasterPassword() const {return cachedMasterPassword;}

private Q_SLOTS:
    void handleLogin();
    void handleRegister();

private:
    QLineEdit *usernameInput;
    QLineEdit *passwordInput;
    UserAuth userAuth;
    std::string cachedMasterPassword;

    void setupUI();
    void showMainWindow(const QString &username);
};