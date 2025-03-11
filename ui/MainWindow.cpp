#include "MainWindow.h"
#include "PasswordManagerWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QListWidgetItem>

MainWindow::MainWindow(sqlite3* db, const std::string &username, const std::string &masterPassword,  QWidget *parent)
    : db_(db), QWidget(parent), vault(db), user(username), masterPassword_(masterPassword)
{
    setWindowTitle("密码本管理 - " + QString::fromStdString(username));
    setMinimumSize(600, 400);
    setupUI();
    loadCodebooks();
}

void MainWindow::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    codebookList = new QListWidget(this);
    codebookList->setStyleSheet("QListWidget { font-size: 16px; }");

    QHBoxLayout *btnLayout = new QHBoxLayout();
    QPushButton *addBtn = new QPushButton("创建新的密码本", this);
    QPushButton *deleteBtn = new QPushButton("删除密码本", this);
    QPushButton *openBtn = new QPushButton("打开密码本", this);

    connect(addBtn, &QPushButton::clicked, this, &MainWindow::addCodebook);
    connect(deleteBtn, &QPushButton::clicked, this, &MainWindow::deleteCodebook);
    connect(openBtn, &QPushButton::clicked, this, &MainWindow::openCodebook);

    btnLayout->addWidget(addBtn);
    btnLayout->addWidget(deleteBtn);
    btnLayout->addWidget(openBtn);

    mainLayout->addWidget(codebookList);
    mainLayout->addLayout(btnLayout);
}

QString MainWindow::getOriginalName(const QString& displayText) 
{
    // 通过第一个换行符分割字符串
    int splitIndex = displayText.indexOf('\n');
    return splitIndex == -1 ? displayText : displayText.left(splitIndex).trimmed();
}

void MainWindow::loadCodebooks()
{
    codebookList->clear();
    auto codebooks = vault.GetUserCodebooks(user);
    for (const auto &cb : codebooks) {
        QListWidgetItem *item = new QListWidgetItem(
            QString("%1\n创建时间: %2").arg(cb.name.c_str()).arg(cb.created_time.c_str())
        );
        item->setData(Qt::UserRole, cb.id);  // 保留原有数据存储
        codebookList->addItem(item);
    }
}

void MainWindow::deleteCodebook()
{
    QListWidgetItem* selectedItem = codebookList->currentItem();
    if (!selectedItem) return;

    // 通过密码本名称获取codebook_id
    std::string codebookName = getOriginalName(selectedItem->text()).toStdString();
    int codebookId = vault.GetCodebookId(user, codebookName);

    if (codebookId == -1) {
        QMessageBox::warning(this, "错误", "未找到指定密码本");
        return;
    }

    try {
        if (vault.DeleteCodebook(codebookId)) {
            // 删除成功后从列表移除
            delete selectedItem;
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "删除失败", 
                            QString("数据库错误: %1").arg(e.what()));
    }
}

void MainWindow::addCodebook()
{
    bool ok;
    QString name = QInputDialog::getText(this, "创建新的密码本",
                                        "输入名字:", 
                                        QLineEdit::Normal,
                                        "", &ok);
    if (ok && !name.isEmpty()) {
        try {
            if (vault.CreateCodebook(user, name.toStdString())) {
                loadCodebooks();
            }
        } catch (const std::exception &e) {
            QMessageBox::critical(this, "Error!", QString("创建失败: ") + e.what());
        }
    }
}

void MainWindow::openCodebook()
{
    QListWidgetItem* selectedItem = codebookList->currentItem();
    if (!selectedItem) return;

    try {
        // 获取密码本ID（假设存储在item的data中）
        std::string codebookName = getOriginalName(selectedItem->text()).toStdString();
        int codebookId = vault.GetCodebookId(user, codebookName);

        // 创建新窗口时指定父对象，并设置为独立窗口
        PasswordManagerWindow *pmWindow = new PasswordManagerWindow(
            db_, 
            user, 
            masterPassword_,
            codebookId,
            nullptr  // 设置为独立顶级窗口
        );
        
        pmWindow->setAttribute(Qt::WA_DeleteOnClose); // 自动释放内存
        pmWindow->show();

    } catch (const std::exception& e) {
        QMessageBox::critical(this, "错误", QString("打开失败: %1").arg(e.what()));
    }
}
