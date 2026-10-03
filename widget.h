#ifndef WIDGET_H
#define WIDGET_H

#include <QByteArray>
#include <QList>
#include <QWidget>

QT_BEGIN_NAMESPACE
class QLabel;
class QTableWidget;
class QTreeWidget;
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = 0);
    ~Widget();

private:
    QLabel *m_label=nullptr;
    QTableWidget *m_table=nullptr; // 表格控件
    QTreeWidget *m_tree=nullptr; // 右边的协议分层树

    QByteArray m_data; // 整个文件的字节（点击时还要用)
    QList<int> m_packetStarts; // 每个包的"包数据"从文件的第几字节开始

};

#endif // WIDGET_H
