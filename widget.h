#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>

QT_BEGIN_NAMESPACE
class QLabel;
class QTableWidget;
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

};

#endif // WIDGET_H
