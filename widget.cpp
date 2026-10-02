#include "widget.h"
#include <QLabel>
#include <QVBoxLayout>
#include <QFile>
#include <QTableWidget> //表格类
#include <QTableWidgetItem> //表格里的一格
#include <QHeaderView> //表头相关
#include <QAbstractItemView> //下面要用它的常量（禁止编辑、整行选中）

static quint16 readU16(const QByteArray &d,int offset,bool littleEndian){
    if(offset+1>=d.size())
        return 0;

    const quint8 b0=static_cast<unsigned char>(d.at(offset));
    const quint8 b1=static_cast<unsigned char>(d.at(offset+1));

    // 根据大小端判断两个字节谁是高位谁是低位
    // | 是按位或：把2个字节拼起来
    if(littleEndian)
        return static_cast<quint16>(b0|(b1<<8)); // 小端：低位字节在前
    return static_cast<quint16>(b0<<8|b1); // 大端：高位字节在前
}

static quint32 readU32(const QByteArray &d,int offset,bool littleEndian){
    if(offset+3>=d.size())
        return 0;

    const quint8 b0=static_cast<unsigned char>(d.at(offset));
    const quint8 b1=static_cast<unsigned char>(d.at(offset+1));
    const quint8 b2=static_cast<unsigned char>(d.at(offset+2));
    const quint8 b3=static_cast<unsigned char>(d.at(offset+3));

    if(littleEndian)
        return static_cast<quint32>(b0|(b1<<8)|(b2<<16)|(b3<<24));
    return static_cast<quint32>((b0<<24)|(b1<<16)|(b2<<8)|b3);
}

Widget::Widget(QWidget *parent)
    : QWidget(parent)
{    
    resize(700,420);
    setWindowTitle(QStringLiteral("MyPktView"));

    m_label =new QLabel(this);
    m_label->setText(QStringLiteral("正在读取...."));

    m_table=new QTableWidget(this);

    m_table->setColumnCount(3); //要3列
    m_table->setHorizontalHeaderLabels(QStringList()
                                       <<QStringLiteral("序号")
                                       <<QStringLiteral("时间(秒)")
                                       <<QStringLiteral("长度(字节)"));

    // 隐藏最左边那列行号（1,2,3… 是自动的，不好看） vertical：垂直的
    m_table->verticalHeader()->setVisible(false);

    // 最后一列自动撑满  horizontal：水平的
    m_table->horizontalHeader()->setStretchLastSection(true);

    // 禁止用户双击改内容
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // 点一下选中整行
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);

    // 布局：不放进布局的控件会贴在左上角、还可能被别的控件盖住
    QVBoxLayout *layout=new QVBoxLayout(this);
    layout->addWidget(m_label);
    layout->addWidget(m_table);

    QFile file(QStringLiteral("E:/dsh_Cwork/PktView/samples/sample.pcap"));

    // QIODevice::ReadOnly = 只读模式
    if(!file.open(QIODevice::ReadOnly)){
        m_label->setText(QStringLiteral("打不开文件"));
        return ;
    }

    // readAll()：把整个文件读进内存，返回一串字节（QByteArray）
    // const：这个变量后面不再修改（好习惯，防止手误改坏）
    const QByteArray data=file.readAll();

    // 判断字节序 + 读版本号
    const unsigned char m0=static_cast<unsigned char>(data.at(0));
    const unsigned char m1=static_cast<unsigned char>(data.at(1));

    // 默认先假设文件是小端存储(目前只用前两个字节来判断)
    bool littleEndian=true;
    if(m0==0xd4&&m1==0xc3)
        littleEndian=true; // 魔数0xD4C3 → 文件为小端字节序
    else if(m0==0xa1&&m1==0xb2)
        littleEndian=false; // 魔数0xA1B2 → 文件为大端字节序
    else{
        m_label->setText(QStringLiteral("这不是pcap文件"));
        return ;
    }

    // pcap文件头：偏移4字节为主版本号、偏移6字节为次版本号，每个版本号占2字节
    const quint16 major=readU16(data,4,littleEndian);
    const quint16 minor=readU16(data,6,littleEndian);


    // 读一个包->填一行表格
    int row=0; // 已经填到第几行
    int offset=24; // 24  = 跳过文件头
    while(offset+16<=data.size()){
        // 记录头 16 字节：秒(4) 微秒(4) 长度(4) 原始长度(4)
        const quint32 sec=readU32(data,offset,littleEndian);
        const quint32 usec=readU32(data,offset+4,littleEndian);
        const quint32 len=readU32(data,offset+8,littleEndian);

        offset+=16; // 跳过包头

        if(len==0||offset+static_cast<int>(len)>data.size())
            break;

        m_table->insertRow(row);
        // m_table->setItem(行号, 列号, QTableWidgetItem对象)
        m_table->setItem(row,0,new QTableWidgetItem(QString::number(row+1))); // 序号
        m_table->setItem(row,1,new QTableWidgetItem(
                             QString::number(sec+usec/1000000.0,'f',6))); // 时间(秒)
        m_table->setItem(row,2,new QTableWidgetItem(QString::number(len))); // 长度

        offset+=static_cast<int>(len); //跳过这个包的数据，来到下一个包的开头
        ++row;

    }

    // 将版本号拼接成字符串展示到label上，%1、%2、%3会被arg依次替换
    m_label->setText(QStringLiteral("pcap版本%1.%2，文件里共有%3个包")
            .arg(major).arg(minor).arg(row));

}

Widget::~Widget()
{

}
