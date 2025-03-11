#include "LoginWindow.h"
#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>

LoginWindow::LoginWindow(QWidget *parent) : QWidget(parent)
{
    setWindowTitle("密码管家 - 登录");
    setFixedSize(400, 300);
    setupUI();
}

void LoginWindow::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    QLabel *titleLabel = new QLabel("密码管理系统", this);
    titleLabel->setAlignment(Qt::AlignCenter);
    titleLabel->setStyleSheet("font-size: 24px; font-weight: bold; margin: 20px 0;");

    usernameInput = new QLineEdit(this);
    usernameInput->setPlaceholderText("用户名");
    usernameInput->setMaxLength(50);

    passwordInput = new QLineEdit(this);
    passwordInput->setPlaceholderText("密码（8-32位，必须包含大小写字母和数字）");
    passwordInput->setEchoMode(QLineEdit::Password);
    passwordInput->setMaxLength(32);

    QPushButton *loginBtn = new QPushButton("登录", this);
    QPushButton *registerBtn = new QPushButton("注册", this);

    connect(loginBtn, &QPushButton::clicked, this, &LoginWindow::handleLogin);
    connect(registerBtn, &QPushButton::clicked, this, &LoginWindow::handleRegister);

    QHBoxLayout *btnLayout = new QHBoxLayout();
    btnLayout->addWidget(loginBtn);
    btnLayout->addWidget(registerBtn);

    mainLayout->addWidget(titleLabel);
    mainLayout->addWidget(usernameInput);
    mainLayout->addWidget(passwordInput);
    mainLayout->addLayout(btnLayout);
}

void LoginWindow::handleLogin()
{
    QString username = usernameInput->text();
    QString password = passwordInput->text();

    std::vector<UserAuth::CodebookInfo> codebooks;
    if (userAuth.Login(username.toStdString(), password.toStdString(), codebooks)) {
        showMainWindow(username);
    } else {
        QMessageBox::warning(this, "登录失败", "用户名或密码错误");
    }
}

void LoginWindow::handleRegister()
{
    QString username = usernameInput->text();
    QString password = passwordInput->text();

    try {
        if (userAuth.Register(username.toStdString(), password.toStdString())) {
            QMessageBox::information(this, "注册成功", "请使用新账号登录");
        } else {
            QMessageBox::warning(this, "注册失败", "用户名已存在");
        }
    } catch (const std::exception &e) {
        QMessageBox::critical(this, "错误", QString("注册失败: ") + e.what());
    }
}

void LoginWindow::showMainWindow(const QString &username)
{
    sqlite3 *db = userAuth.GetDatabaseHandle();
    if (db) {
        MainWindow *mainWin = new MainWindow(db, username.toStdString(), this->cachedMasterPassword);
        mainWin->show();
        this->close();
    } else {
        QMessageBox::critical(this, "错误", "无法连接数据库");
    }
}