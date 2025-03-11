#include "PasswordManagerWindow.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QClipboard>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QToolBar>
#include <QFormLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QApplication>
#include <QTimer>
#include <regex>

PasswordManagerWindow::PasswordManagerWindow(sqlite3* db, 
                                           const std::string& username,
                                           const std::string& masterPassword,
                                           int codebookId,
                                           QWidget* parent)
    : QWidget(parent, Qt::Window),
      vault(db),
      masterPassword(masterPassword),
      currentCodebookId(codebookId) {
    setupUI();
    loadEntries();

    setMinimumSize(800, 600);
}

void PasswordManagerWindow::setupUI() {
    // 主布局
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(60, 40, 60, 40);
    
    // 条目表格
    entriesTable = new QTableWidget(this);
    entriesTable->setColumnCount(4);
    entriesTable->setHorizontalHeaderLabels({"地址", "创建时间", "密码", "备注"});
    entriesTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    entriesTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    entriesTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    entriesTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    entriesTable->horizontalHeader()->setMinimumSectionSize(150);
    
    // 操作工具栏
    QToolBar* toolbar = new QToolBar;
    QAction* addAction = toolbar->addAction("新增条目");
    QAction* deleteAction = toolbar->addAction("删除条目");
    QAction* copyAction = toolbar->addAction("复制密码");
    
    // 输入表单
    QFormLayout* form = new QFormLayout;
    addressInput = new QLineEdit;
    addressInput->setPlaceholderText("必填");
    passwordInput = new QLineEdit;
    passwordInput->setPlaceholderText("密码8-32位，必须包含大小写字母和数字");
    QPushButton* generateBtn = new QPushButton("生成");
    notesInput = new QPlainTextEdit;
    
    // 密码生成菜单
    QMenu* genMenu = new QMenu(this);
    genMenu->addAction("8位", [this]{ generatePassword(8); });
    genMenu->addAction("16位", [this]{ generatePassword(16); });
    genMenu->addAction("24位", [this]{ generatePassword(24); });
    genMenu->addAction("32位", [this]{ generatePassword(32); });
    generateBtn->setMenu(genMenu);
    
    // 组装UI
    QHBoxLayout* passLayout = new QHBoxLayout;
    passLayout->addWidget(passwordInput);
    passLayout->addWidget(generateBtn);
    
    form->addRow("服务地址:", addressInput);
    form->addRow("密码:", passLayout);
    form->addRow("备注:", notesInput);
    
    mainLayout->addWidget(toolbar);
    mainLayout->addWidget(entriesTable);
    mainLayout->addLayout(form);
    
    // 信号连接
    connect(addAction, &QAction::triggered, this, &PasswordManagerWindow::addEntry);
    connect(deleteAction, &QAction::triggered, this, &PasswordManagerWindow::deleteEntry);
    connect(copyAction, &QAction::triggered, this, &PasswordManagerWindow::copyPassword);
    connect(entriesTable, &QTableWidget::cellDoubleClicked, this, &PasswordManagerWindow::showPassword);
    connect(entriesTable, &QTableWidget::customContextMenuRequested, [this](const QPoint& pos){
        QMenu menu;
        menu.addAction("复制密码", this, &PasswordManagerWindow::copyPassword);
        menu.exec(entriesTable->viewport()->mapToGlobal(pos));
    });
}

void PasswordManagerWindow::loadEntries() {
    entriesTable->setRowCount(0);
    
    try {
        entries = vault.GetEntries(currentCodebookId);
        
        for (const auto& entry : entries) {
            std::vector<uint8_t> plaintext = crypto_.decrypt(
                masterPassword,
                entry.encrypted_password
            );
            
            int row = entriesTable->rowCount();
            entriesTable->insertRow(row);

            auto* addrItem = new QTableWidgetItem(QString::fromStdString(entry.address));
            entriesTable->setItem(row, 0, addrItem);
            entriesTable->setItem(row, 1, new QTableWidgetItem(
                QString::fromStdString(entry.created_time)));
            auto* pwdItem = new QTableWidgetItem("******");
            pwdItem->setFlags(pwdItem->flags() ^ Qt::ItemIsEditable);
            entriesTable->setItem(row, 2, pwdItem);
            entriesTable->setItem(row, 3, new QTableWidgetItem(
                QString::fromStdString(entry.notes)));
            entriesTable->item(row, 2)->setData(Qt::UserRole, 
                QByteArray(reinterpret_cast<const char*>(plaintext.data()), 
                plaintext.size()));
            entriesTable->item(row, 0)->setData(Qt::UserRole, entry.id);
        }
        
        entriesTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        entriesTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        entriesTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        entriesTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "加载错误", 
            QString("无法加载密码本条目:\n%1").arg(e.what()));
    }
}

void PasswordManagerWindow::generatePassword(int length) {
    try {
        // 每次生成都创建新实例
        PasswordGenerator gen(length);
        QString password = QString::fromStdString(gen.generateExtended());

        // 设置密码输入框的文本
        passwordInput->setText(password);

        // 自动复制到剪贴板
        QApplication::clipboard()->setText(password);

        passwordInput->setEchoMode(QLineEdit::Normal);
        QTimer::singleShot(2000, [this]{
            passwordInput->setEchoMode(QLineEdit::Password);
        });

    } catch (const std::exception& e) {
        QMessageBox::critical(this, "生成错误", 
                            QString("密码生成失败: %1").arg(e.what()));
    }
}

void PasswordManagerWindow::showEvent(QShowEvent* event) {
    QWidget::showEvent(event);
    
    // 首次显示时自动调整列宽
    entriesTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    entriesTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    
    // 密码字段保护
    for(int row = 0; row < entriesTable->rowCount(); ++row) {
        QTableWidgetItem* item = entriesTable->item(row, 1);
        item->setFlags(item->flags() ^ Qt::ItemIsEditable);
        item->setToolTip("双击显示密码（3秒后自动隐藏）");
    }

}

void PasswordManagerWindow::showPassword(int row, int column) {
    if (column == 2) {
        QTableWidgetItem* item = entriesTable->item(row, column);
        const std::vector<uint8_t> encrypted = entries[row].encrypted_password;
        std::vector<uint8_t> plaintext = crypto_.decrypt(masterPassword, encrypted);

        QString password = QString::fromUtf8(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        item->setText(password);

        // 3秒后隐藏密码
        QTimer::singleShot(3000, [item] {
            item->setText("******");
        });
    }
}

void PasswordManagerWindow::addEntry() {
    try {
        if (addressInput->text().isEmpty()) {
            throw std::runtime_error("服务地址不能为空");
        }
        
        // 加密密码
        const std::string plainPassword = passwordInput->text().toStdString();
        const std::vector<uint8_t> ciphertext = crypto_.encrypt(
            masterPassword,
            std::vector<uint8_t>(plainPassword.begin(), plainPassword.end())
        );
        
        // 创建新条目
        PasswordVault::PasswordEntry entry{
            .address = addressInput->text().toStdString(),
            .public_key = "N/A", // 根据实际情况实现
            .encrypted_password = ciphertext,
            .notes = notesInput->toPlainText().toStdString()
        };
        
        if(!std::regex_match(plainPassword, std::regex(R"((?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,32})"))){
            throw std::runtime_error("密码不符合复杂度要求");
        }

        if (vault.AddEntry(currentCodebookId, entry.address, entry.encrypted_password, entry.notes)) {
            refreshEntries();
            QMessageBox::information(this, "成功", "条目添加成功");

            addressInput->clear();
            passwordInput->clear();
            notesInput->clear();
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "错误", QString::fromStdString(e.what()));
    }
}

void PasswordManagerWindow::deleteEntry() {
    QModelIndexList selected = entriesTable->selectionModel()->selectedRows();
    if (selected.isEmpty()) return;

    try {
        int entryId = entriesTable->item(selected.first().row(), 0)->data(Qt::UserRole).toInt();
        if (vault.DeleteEntry(entryId)) {
            refreshEntries();
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "错误", QString("删除失败: %1").arg(e.what()));
    }
}

void PasswordManagerWindow::copyPassword() {
    QModelIndexList selected = entriesTable->selectionModel()->selectedRows();
    if (selected.isEmpty()) return;

    try {
        const int row = selected.first().row();
        const std::vector<uint8_t> encrypted = entries[row].encrypted_password;
        const std::vector<uint8_t> plaintext = crypto_.decrypt(masterPassword, encrypted);
        
        QApplication::clipboard()->setText(
            QString::fromUtf8(reinterpret_cast<const char*>(plaintext.data()), plaintext.size())
        );
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "错误", QString("复制失败: %1").arg(e.what()));
    }
}

void PasswordManagerWindow::refreshEntries() {
    entriesTable->setRowCount(0);
    loadEntries();
}