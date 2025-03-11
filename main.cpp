#include "LoginWindow.h"
#include <QApplication>
#include <QStyleFactory>
#include <QFile>
#include <QMessageBox>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    // 设置全局样式
    QApplication::setStyle(QStyleFactory::create("Fusion"));
    
    // 加载样式表
    QFile styleFile(":/styles/style.qss");
    if (styleFile.open(QIODevice::ReadOnly)) {
        QString style = QLatin1String(styleFile.readAll());
        app.setStyleSheet(style);
        styleFile.close();
    }

    try {
        // 初始化界面
        LoginWindow loginWindow;
        loginWindow.show();
        
        return app.exec();
        
    } catch (const std::exception& e) {
        QMessageBox::critical(nullptr, "致命错误", 
                            QString("程序初始化失败: %1").arg(e.what()));
        return -1;
    }
}