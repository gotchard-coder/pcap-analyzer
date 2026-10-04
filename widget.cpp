#include "widget.h"
#include <QLabel>
#include <QVBoxLayout>
#include <QFile>
#include <QTableWidget> //表格类
#include <QTableWidgetItem> //表格里的一格
#include <QHeaderView> //表头相关
#include <QAbstractItemView> //下面要用它的常量（禁止编辑、整行选中）
#include <QSplitter> //左右分栏
#include <QTreeWidget> // 树
#include <QTreeWidgetItem> // 树里的一项
#include <QPlainTextEdit> // 十六进制视图（只读的多行文本框）
#include <QFont> // 设置等宽字体
#include <QScrollBar> // 让十六进制视图的滚动条回到最上面

static quint16 readU16(const QByteArray &d,int offset,bool littleEndian){
    if(offset+2>d.size())
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
    if(offset+4>d.size())
        return 0;

    const quint8 b0=static_cast<unsigned char>(d.at(offset));
    const quint8 b1=static_cast<unsigned char>(d.at(offset+1));
    const quint8 b2=static_cast<unsigned char>(d.at(offset+2));
    const quint8 b3=static_cast<unsigned char>(d.at(offset+3));

    if(littleEndian)
        return static_cast<quint32>(b0|(b1<<8)|(b2<<16)|(b3<<24));
    return static_cast<quint32>((b0<<24)|(b1<<16)|(b2<<8)|b3);
}

// 把 6 个字节变成 "11:22:33:44:55:66" 这样的 MAC 地址文字
static QString macToString(const QByteArray &d,int offset){
    if(offset+6>d.size())
        return "";

    QStringList parts; // 用来存放6个分段，比如["11","22","33","44","55","66"]

    // MAC固定6字节，循环读6次
    for(int i=0;i<6;++i){
        // .arg( 要转的数字, 最小宽度, 进制, 填充字符 )
        parts<<QString("%1").arg(
                   static_cast<unsigned char>(d.at(offset+i)),
                   2, // 最少输出2个字符
                   16, // 进制：16进制
                   QLatin1Char('0') //不够两位前面补0，0x5 → "05"而不是"5"
                   );
    }
    // 把列表里6个字符串用 : 拼接在一起
    return parts.join(QLatin1Char(':'));
}

// 把 4 个字节变成 "192.168.1.5" 这样的 IPv4 地址文字
static QString ipv4ToString(const QByteArray &d,int offset){
    if(offset+4>d.size()) return "";

    return QString("%1.%2.%3.%4")
            .arg(static_cast<unsigned char>(d.at(offset)))
            .arg(static_cast<unsigned char>(d.at(offset+1)))
            .arg(static_cast<unsigned char>(d.at(offset+2)))
            .arg(static_cast<unsigned char>(d.at(offset+3)));
}

/**
 * @brief 解析DNS域名，支持【长度+字符串】普通段 + DNS压缩指针
 * @param d        整个数据包的原始字节数组（QByteArray）
 * @param start    域名开始的【全局字节下标】(在m_data里的位置)
 * @param dnsBase  DNS报文头部在m_data里的全局起始下标（压缩指针偏移是相对DNS报文开头）
 * @param endPos   输出参数(引用)：域名消耗完之后，下一个字段的全局下标
 * @return 拼接好的域名，例如 www.baidu.com
 */
static QString dnsName(const QByteArray &d, int start, int dnsBase, int &endPos)
{
    QString name;               // 保存最终拼接的域名
    int pos = start;            // 当前读取的全局下标
    endPos = start;             // 默认结束位置
    int jumps = 0;              // 指针跳转计数，防止恶意包死循环

    while (pos >= 0 && pos < d.size())
    {
        // 取出当前1字节
        const int len = static_cast<unsigned char>(d.at(pos));

        // 情况1：len == 0，域名正常结束（0x00终止符）
        if (len == 0)
        {
            // 没有发生指针跳转，终止符就是域名结尾
            if (jumps == 0)
                endPos = pos + 1;
            break;
        }

        // 情况2：最高两位是 11，代表【DNS压缩指针】（占2字节）
        if ((len & 0xC0) == 0xC0)
        {
            // 越界保护：指针需要2个字节，不够直接退出
            if (pos + 1 >= d.size())
                break;

            // 第一次碰到指针：域名只占用这2字节，下一个字段在指针之后
            if (jumps == 0)
                endPos = pos + 2;

            // 取出14位偏移：低6bit(来自第一字节) + 完整第二字节
            const int ptr = ((len & 0x3F) << 8) | static_cast<unsigned char>(d.at(pos + 1));
            jumps++;

            // 最多允许跳转8次，防止循环指针死循环
            if (jumps > 8)
                break;

            // 指针偏移是【相对于DNS报文头部】，要换算成全局下标
            pos = dnsBase + ptr;
            continue; // 跳到目标位置，继续读取域名
        }

        // 情况3：普通域名段，len为本段字符个数
        ++pos; // 跳过长度字节，pos指向文本开头
        // 越界防御
        if (pos + len > d.size())
            break;

        // 不是第一段域名，前面加小数点分隔
        if (!name.isEmpty())
            name += QLatin1Char('.');

        // 截取len个字节，转ASCII字符串拼接到域名
        name += QString::fromLatin1(d.mid(pos, len));

        // pos移动到下一段的长度字节位置
        pos += len;
    }

    return name;
}

// 把一段字节变成经典的"十六进制视图"文字（就是 Wireshark 下面那块）
// 生成的样子（每行 16 字节）：
// 0000  11 22 33 44 55 66 aa bb  cc dd ee 01 08 00 45 00   ."3DUf........E.
static QString hexDump(const QByteArray &d,int start,int len){
    QString text;
    // i = 这一行从第几字节开始；每行 16 个字节，所以一次 +16
    for(int i=0;i<len;i+=16){
        // ① 行首：这一行的起始偏移，4 位十六进制（0000、0010、0020……）
        //    .arg(值, 位数, 进制, 补位字符)
        text+=QString("%1 ").arg(i,4,16,QLatin1Char('0'));

        QString ascii; // 右边那一列 ASCII 文字
        for(int j=0;j<16;j++){ // 一行固定留 16 个字节的位置
            if(i+j<len){
                // ② 一个字节 = 2 位十六进制
                const unsigned char b=
                        static_cast<unsigned char>(d.at(start+i+j));
                text+=QString("%1 ").arg(b,2,16,QLatin1Char('0'));
                // ③ 顺手拼右边那列：能显示的字符照原样，
                //  不能显示的（0x00、换行这些控制符）用点代替
                ascii+=(b>=32&&b<127)?QLatin1Char(static_cast<char>(b))
                                    :QLatin1Char('.');
            }else{
                // 最后一行可能凑不满 16 字节，补 3 个空格，好让右边那列对齐
                text+=QStringLiteral("   ");
            }
            if(j==7)  // 第 8 个字节后面多空一格，眼睛好数（Wireshark 也这样）
                text+=QLatin1Char(' ');
        }
        // ④ 这一行拼完：一个空格 + ASCII 列 + 换行
        text+=QStringLiteral(" ")+ascii+QLatin1Char('\n');
    }

    return text;
}

Widget::Widget(QWidget *parent)
    : QWidget(parent)
{    
    resize(1000,420);
    setWindowTitle(QStringLiteral("MyPktView"));

    m_label =new QLabel(this);
    m_label->setText(QStringLiteral("正在读取...."));

    m_table=new QTableWidget(this);

    m_table->setColumnCount(6); //要6列
    m_table->setHorizontalHeaderLabels(QStringList()
                                       <<QStringLiteral("序号")
                                       <<QStringLiteral("时间(秒)")
                                       <<QStringLiteral("长度(字节)")
                                       <<QStringLiteral("源地址")
                                       <<QStringLiteral("目的地址")
                                       <<QStringLiteral("协议")
                                       );

    // 隐藏最左边那列行号（1,2,3… 是自动的，不好看） vertical：垂直的
    m_table->verticalHeader()->setVisible(false);

    // 最后一列自动撑满  horizontal：水平的
    m_table->horizontalHeader()->setStretchLastSection(true);

    // 禁止用户双击改内容
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // 点一下选中整行
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);

    // 右边：协议分层树
    m_tree=new QTreeWidget(this);
    m_tree->setColumnCount(2); // 两列：字段 / 值
    m_tree->setHeaderLabels(QStringList()
                            <<QStringLiteral("字段")<<QStringLiteral("值"));
    m_tree->header()->setStretchLastSection(true); // 表头最后一列自动拉伸，填满剩余空间

    // 右下角：十六进制视图
    m_hex=new QPlainTextEdit(this);
    m_hex->setReadOnly(true); // 只给看不给改
    // 必须用等宽字体：每个字符一样宽，字节才能排成整齐的格子（用默认字体就歪了）
    m_hex->setFont(QFont(QStringLiteral("Courier New"),9));
    // 不允许自动换行：一行太长就横向滚动；换行了就不好读了
    m_hex->setLineWrapMode(QPlainTextEdit::NoWrap);
    // 还没点表格时先给句提示，不然一片空白不知道是干嘛的
    m_hex->setPlainText(QStringLiteral("点击左边的表格，这里显示这个包的原始字节"));

    // 右边再上下分栏：上面协议树，下面十六进制
    // Qt::Vertical = 上下分（原来那个Horizontal是水平分，左右分）
    QSplitter *rightSplitter=new QSplitter(Qt::Vertical,this);
    rightSplitter->addWidget(m_tree);
    rightSplitter->addWidget(m_hex);
    rightSplitter->setStretchFactor(0,3); // 上面那半占 3 份高
    rightSplitter->setStretchFactor(1,2); // 下面那半占 2 份高

    // 左右分栏-水平模式（中间的竖线可以拖动）
    QSplitter *splitter=new QSplitter(Qt::Horizontal,this);
    splitter->addWidget(m_table);
    splitter->addWidget(rightSplitter); // ← 现在右边放的是"树 + 十六进制"整块
    splitter->setStretchFactor(0,3); // 左边占 3 份宽,0代表左
    splitter->setStretchFactor(1,2); // 右边占 2 份宽,1代表右

    // 布局：不放进布局的控件会贴在左上角、还可能被别的控件盖住
    QVBoxLayout *layout=new QVBoxLayout(this);
    layout->addWidget(m_label);
    layout->addWidget(splitter);

    // ============ 信号槽：把"点表格"接到"onTableClicked" ============
    // connect(谁发信号, 发什么信号, 谁来处理, 处理函数)
    //   m_table                  —— 发信号的控件（表格）
    //   &QTableWidget::cellClicked —— 发什么信号（某个单元格被点击）
    //   this                     —— 谁来处理（当前窗口）
    //   &Widget::onTableClicked  —— 用哪个函数处理
    connect(m_table,&QTableWidget::cellClicked,this,&Widget::onTableClicked);

    QFile file(QStringLiteral("E:/dsh_Cwork/PktView/samples/sample.pcap"));

    // QIODevice::ReadOnly = 只读模式
    if(!file.open(QIODevice::ReadOnly)){
        m_label->setText(QStringLiteral("打不开文件"));
        return ;
    }

    // readAll()：把整个文件读进内存，返回一串字节（QByteArray）
    // const：这个变量后面不再修改（好习惯，防止手误改坏）
    m_data=file.readAll(); // ← 存进成员变量（点击时还要用
    const QByteArray &data=m_data; // ← data 只是它的"别名"，下面代码不用改

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

    m_littleEndian=littleEndian; // 存起来，点击时要用

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

        // << 是 QList 的"追加"运算符：把 offset 加到列表末尾
        m_packetStarts<<offset; // 记住这个包的包数据从哪开始
        m_packetLens<<static_cast<int>(len); // 这个包有多长

        m_table->insertRow(row);
        // m_table->setItem(行号, 列号, QTableWidgetItem对象)
        m_table->setItem(row,0,new QTableWidgetItem(QString::number(row+1))); // 序号
        m_table->setItem(row,1,new QTableWidgetItem(
                             QString::number(sec+usec/1000000.0,'f',6))); // 时间(秒)
        m_table->setItem(row,2,new QTableWidgetItem(QString::number(len))); // 长度

        // 解析以太网头（14字节)+IPv4头，填地址
        if(len>=14){
            const int ethStart=offset;
            const QString dstMac=macToString(data,ethStart); // 偏移 0：目的 MAC
            const QString srcMac=macToString(data,ethStart+6); // 偏移 6：源 MAC

            // 以太网"类型"字段（偏移 12，占 2 字节） Ethernet 以太网
            //    ⚠️ 传 false：包里面的字段是大端（网络字节序）
            const quint16 ethType=readU16(data,ethStart+12,false);

            // 先默认显示mac
            QString srcText=srcMac;
            QString dstText=dstMac;

            // 先默认协议未知 protocol（协议）
            QString protoText=QStringLiteral("其他");

            // 如果是IPv4（类型=0x0800),再往下挖一层，改成显示IP
            if(ethType==0x0800&&len>=34){ // 14(以太网头) + 20(IP头) = 34
                const int ipStart=ethStart+14;
                srcText=ipv4ToString(data,ipStart+12);
                dstText=ipv4ToString(data,ipStart+16);

                //看 IP 头的"协议号"（偏移 9，1 字节）
                // 6=TCP、17=UDP、1=ICMP
                const int ipProto=static_cast<unsigned char>(data.at(ipStart+9));
                if(ipProto==6)
                    protoText=QStringLiteral("TCP");
                else if(ipProto==17)
                    protoText=QStringLiteral("UDP");
                else if(ipProto==1)
                    protoText=QStringLiteral("ICMP");
                else
                    protoText=QStringLiteral("IP %1").arg(ipProto);

                // TCP / UDP 有端口，读出来接到地址后面
                if(ipProto==6||ipProto==17){
                    // IP 首部长度不是固定的 20 字节！
                    // 它写在 IP 头的第 1 个字节的"低 4 位"里，单位是 4 字节：
                    //   & 0x0F  = 取低 4 位（按位与）
                    //   再 × 4  = 换算成字节数（通常是 20）(4 字节为单位)
                    const int ipHeaderLen=
                            (static_cast<unsigned char>(data.at(ipStart))&0x0F)*4;

                    const int transStart=ipStart+ipHeaderLen; // TCP/UDP 头紧跟在 IP 头后面

                    if(transStart+4<=data.size()){
                        // 端口各占2字节
                        const quint16 srcPort=readU16(data,transStart,false); // 偏移 0：源端口
                        const quint16 dstPort=readU16(data,transStart+2,false); // 偏移2：目的端口

                        // += 是"接到字符串后面"：把 IP 变成 "IP:端口"
                        srcText+=QStringLiteral(":%1").arg(srcPort);
                        dstText+=QStringLiteral(":%1").arg(dstPort);
                    }
                }

            }else if(ethType==0x0806){
                protoText=QStringLiteral("ARP"); // 非 IPv4（样例里是 ARP）
            }else{
                protoText=QString("0x%1").arg(ethType,4,16,QLatin1Char('0'));
            }

            m_table->setItem(row,3,new QTableWidgetItem(srcText)); // 第 3 列：源地址
            m_table->setItem(row,4,new QTableWidgetItem(dstText)); // 第 4 列：目的地址
            m_table->setItem(row,5,new QTableWidgetItem(protoText)); // 第5列：协议
        }




        offset+=static_cast<int>(len); //跳过这个包的数据，来到下一个包的开头
        ++row;

    }

    // 自动调整所有列的宽度，根据这一列里面内容的长短自适应
    m_table->resizeColumnsToContents();

    // 将版本号拼接成字符串展示到label上，%1、%2、%3会被arg依次替换
    m_label->setText(QStringLiteral("pcap版本%1.%2，文件里共有%3个包")
            .arg(major).arg(minor).arg(row));

}

void Widget::onTableClicked(int row)
{
    // 先清空树（每次点击都重新填）
    m_tree->clear();

    // 越界保护（万一row不对）
    if(row<0||row>=m_packetStarts.size()){
        return ;
    }

    // ★ 关键：第 row 个包的"包数据"从文件的第几字节开始
    //   这就是 5.1 里那句 m_packetStarts << offset; 存下来的东西
    const int pktStart=m_packetStarts.at(row);


    // ================= 第 1 层：以太网 II =================
    // 顶层节点（挂在树上）
    // QTreeWidgetItem(父节点, 每一列的文字)
    QTreeWidgetItem *ethItem=new QTreeWidgetItem(m_tree,QStringList()<<QStringLiteral("以太网II"));
    ethItem->setExpanded(true); // 默认展开

    const QString dstMac=macToString(m_data,pktStart);
    const QString srcMac=macToString(m_data,pktStart+6);

    // 子节点（挂在 ethItem 下面），两列：字段名 / 值
    new QTreeWidgetItem(ethItem, QStringList()
                        << QStringLiteral("源 MAC") << srcMac);
    new QTreeWidgetItem(ethItem, QStringList()
                        << QStringLiteral("目的 MAC") << dstMac);

    // 类型字段（偏移 12，2 字节，大端）
    const quint16 ethType=readU16(m_data,pktStart+12,false);
    QString typeText;
    if(ethType==0x0800)
        typeText=QStringLiteral("0x0800(IPv4)");
    else if(ethType==0x0806)
        typeText=QStringLiteral("0x0806(ARP)");
    else
        // 如果以太网类型不是 IPv4，也不是 ARP，就直接把原始十六进制数值展示出来
        typeText=QString("0x%1").arg(ethType,4,16,QLatin1Char('0'));

    new QTreeWidgetItem(ethItem,QStringList()
                        <<QStringLiteral("类型")<<typeText);

    // ================= 第 2 层：IPv4 =================
    // ① 先算出"这一包有多长"
    const int pktLen = m_packetLens.at(row);

    // 把整个包的字节填进右下角的十六进制视图
    // pktLen 是这个包的长度，从 pktStart 开始显示这么多字节
    // static_cast<int> 是因为 hexDump 要 int，而 pktLen 是 quint32（无符号）
    m_hex->setPlainText(hexDump(m_data,pktStart,static_cast<int>(pktLen)));
    m_hex->verticalScrollBar()->setValue(0); // 滚动条回到最上面（不然点新包还停在旧位置）

    // ② 只有"这个包是以太网里的 IPv4"才继续往下解析
    // 34 = 以太网头 14 + IP 头最小 20（比这短就不可能是完整 IPv4）
    if(ethType==0x0800&&pktLen>=34){
        const int ipStart=pktStart+14; // IP头从以太网（14字节）之后开始

        // ③ 建"IPv4"这个顶层节点，挂在树上
        QTreeWidgetItem *ipItem=new QTreeWidgetItem(m_tree);
        ipItem->setText(0,QStringLiteral("IPv4"));
        ipItem->setExpanded(true);

        // ④ 先把这一层要显示的字段都读出来
        //    IP 头第 1 个字节：高 4 位 = 版本，低 4 位 = 首部长度÷4
        //    & 0x0F 取出低 4 位，再 ×4 才是字节数（通常是 20）
        const int ipHeaderLen=(static_cast<unsigned char>(m_data.at(ipStart))&0x0F)*4;

        // 偏移2：总长度（2字节，大端)
        const quint16 totalLen=readU16(m_data,ipStart+2,false);

        // 偏移 8：TTL（1 字节）
        const int ttl=static_cast<unsigned char>(m_data.at(ipStart+8));

        // 偏移 9：协议号（1 字节）：6=TCP、17=UDP、1=ICMP
        const int ipProto=static_cast<unsigned char>(m_data.at(ipStart+9));

        // 偏移 12：源 IP  偏移 16：目的 IP
        const QString srcText=ipv4ToString(m_data,ipStart+12);
        const QString dstText=ipv4ToString(m_data,ipStart+16);

        // 把协议号变成文字
        QString protoText;
        if(ipProto==6) protoText=QStringLiteral("6(TCP)");
        else if(ipProto==17) protoText=QStringLiteral("17(UDP)");
        else if(ipProto==1) protoText=QStringLiteral("1(ICMP)");
        else protoText=QString::number(ipProto);

        // ⑤ 每个字段加一个子节点
        //    写法：new QTreeWidgetItem(父节点, 第0列文字, 第1列文字)
        new QTreeWidgetItem(ipItem,QStringList()
                            <<QStringLiteral("版本")<<QStringLiteral("4"));
        new QTreeWidgetItem(ipItem,QStringList()
                            <<QStringLiteral("首部长度")<<QStringLiteral("%1字节").arg(ipHeaderLen));
        new QTreeWidgetItem(ipItem,QStringList()
                            <<QStringLiteral("总长度")<<QStringLiteral("%1字节").arg(totalLen));
        new QTreeWidgetItem(ipItem,QStringList()
                            <<QStringLiteral("TTL")<<QString::number(ttl));
        new QTreeWidgetItem(ipItem,QStringList()
                            <<QStringLiteral("协议")<<protoText);
        new QTreeWidgetItem(ipItem,QStringList()
                            <<QStringLiteral("源IP")<<srcText);
        new QTreeWidgetItem(ipItem,QStringList()
                            <<QStringLiteral("目的IP")<<dstText);

        // ================= 第 3 层：TCP / UDP =================
        const int tranStart=ipStart+ipHeaderLen;

        // 只有 TCP(6) 和 UDP(17) 才有端口
        if(ipProto==6||ipProto==17){
            QTreeWidgetItem *transItem=new QTreeWidgetItem(m_tree);
            transItem->setText(0,ipProto==6?QStringLiteral("TCP"):QStringLiteral("UDP"));
            transItem->setExpanded(true);


            // 端口在传输层头的最前面：偏移 0 和偏移 2，各 2 字节（大端）
            const quint16 srcPort=readU16(m_data,tranStart,false);
            const quint16 dstPort=readU16(m_data,tranStart+2,false);

            new QTreeWidgetItem(transItem,QStringList()
                                <<QStringLiteral("源端口")
                                <<QString::number(srcPort)); // 将数字转成字符串
            new QTreeWidgetItem(transItem,QStringList()
                                <<QStringLiteral("目的端口")
                                <<QString::number(dstPort));

            // TCP 还有更多字段（UDP 没有这些）
            if(ipProto==6){
                // TCP额外校验：至少15字节
                if(tranStart + 15 <= m_data.size()){
                    // 偏移 4：序号（4 字节，大端）
                    const quint32 seq = readU32(m_data, tranStart + 4, false);

                    // 偏移 12：2 字节 = 数据偏移(高4位) + 保留(3位) + NS(1位) + 标志位(低8位)
                    // & 0x00FF 只留低 8 位，正好是 8 个经典标志
                    const quint16 flags = readU16(m_data, tranStart + 12, false) & 0x00FF;

                    // 偏移 14：窗口大小（2 字节）
                    const quint16 window = readU16(m_data, tranStart + 14, false);

                    // 标志位：一个 bit 表示一个标志，用 & 逐位检查
                    QStringList flagNames;                                      // 装"这一包有哪些标志"
                    if (flags & 0x01) flagNames << QStringLiteral("FIN");       // 第 0 位
                    if (flags & 0x02) flagNames << QStringLiteral("SYN");       // 第 1 位
                    if (flags & 0x04) flagNames << QStringLiteral("RST");       // 第 2 位
                    if (flags & 0x08) flagNames << QStringLiteral("PSH");       // 第 3 位
                    if (flags & 0x10) flagNames << QStringLiteral("ACK");       // 第 4 位
                    if (flags & 0x20) flagNames << QStringLiteral("URG");       // 第 5 位

                    new QTreeWidgetItem(transItem, QStringList()
                                        << QStringLiteral("序号") << QString::number(seq));
                    new QTreeWidgetItem(transItem, QStringList()
                                        << QStringLiteral("标志位") << flagNames.join(QStringLiteral(", ")));
                    new QTreeWidgetItem(transItem, QStringList()
                                        << QStringLiteral("窗口大小") << QString::number(window));
                }
            }


            // ================= 第 4 层：DNS =================
            // DNS 跑在 UDP 上，端口 53
            // DNS 查询（客户端 → DNS 服务器）||DNS 应答（DNS 服务器 → 客户端)
            if(ipProto==17&&(srcPort==53||dstPort==53)){
                // UDP 头是 8 字节（源端口2 目的端口2 长度2 校验和2）
                // UDP 头是 8 字节（源端口2 目的端口2 长度2 校验和2）
                const int dnsStart=tranStart+8;

                // DNS头部最少12字节
                if(dnsStart+12 <= m_data.size()){
                    QTreeWidgetItem *dnsItem=new QTreeWidgetItem(m_tree);
                    dnsItem->setText(0,QStringLiteral("DNS"));
                    dnsItem->setExpanded(true);

                    // DNS 头部 12 字节的排布：
                    //   偏移 0：事务 ID（2 字节）
                    //   偏移 2：标志（2 字节，最高位 = 0 查询 / 1 响应）
                    //   偏移 4：问题数（2 字节）
                    //   偏移 6：回答数（2 字节）
                    //   （偏移 8、10 是授权数、附加数，一般不用）
                    const quint16 txId    = readU16(m_data, dnsStart, false);       // 大端！
                    const quint16 flags   = readU16(m_data, dnsStart + 2, false);
                    const quint16 qdCount = readU16(m_data, dnsStart + 4, false);
                    const quint16 anCount = readU16(m_data, dnsStart + 6, false);

                    // 标志的最高位（bit15）是"这是查询还是响应"
                    //   0x8000 = 1000 0000 0000 0000 → & 之后非 0 就说明是"响应"
                    const QString typeText = (flags & 0x8000)
                            ? QStringLiteral("响应") : QStringLiteral("查询");

                    new QTreeWidgetItem(dnsItem, QStringList()
                                        << QStringLiteral("事务 ID")
                                        << QString("0x%1").arg(txId, 4, 16, QLatin1Char('0')));
                    new QTreeWidgetItem(dnsItem, QStringList()
                                        << QStringLiteral("类型") << typeText);
                    new QTreeWidgetItem(dnsItem, QStringList()
                                        << QStringLiteral("问题数") << QString::number(qdCount));
                    new QTreeWidgetItem(dnsItem, QStringList()
                                        << QStringLiteral("回答数") << QString::number(anCount));

                    // DNS问题段，紧跟DNS头部之后，偏移12
                    //pos 用来接住"查询名结束后的位置"，下一步解析回答记录要用
                    int pos=0;
                    // 调用域名解析函数，得到域名，pos返回域名读完的位置
                    QString qname=dnsName(m_data,dnsStart+12,dnsStart,pos);

                    new QTreeWidgetItem(dnsItem,QStringList()
                                        <<QStringLiteral("查询域名")<<qname);

                    // pos 是域名结束位置，查询名后面还跟着 2 个字段，各占 2 字节，先跳过：
                    //   查询类型 QTYPE ：1 = A（要 IPv4 地址）
                    //   查询类   QCLASS：1 = IN（互联网
                    pos+=4;

                    // ================= 回答区 =================
                    // anCount：DNS头部读出的回答记录数量，可能有多条
                    for(int i=0;i<anCount;i++)
                    {
                        // 越界防御：一条回答记录最少也要 10 字节
                        // （名字 2(不一定)+ 类型 2 + 类 2 + TTL 4 + 数据长度 2，数据可能为 0）
                        if(pos+10>m_data.size())
                            // 这里能用 break，因为我们正在 for 循环里面（break 只能跳循环或 switch）
                            break;

                        int nameEnd=0; // 接住"这个名字结束后的位置"，后面找字段全靠它
                        // 回答记录开头是域名，大概率是压缩指针指向查询域名
                        const QString anName=dnsName(m_data,pos,dnsStart,nameEnd);

                        // 名字后面是固定的 10 个字节，挨个读出来：
                        //    类型(2) 类(2) TTL(4) 数据长度(2)
                        const quint16 anType  = readU16(m_data, nameEnd,     false); // 1 = A 记录
                        const quint16 anClass = readU16(m_data, nameEnd + 2, false); // 1 = IN
                        const quint32 anTtl   = readU32(m_data, nameEnd + 4, false); // 能缓存多少秒
                        const quint16 rdLen   = readU16(m_data, nameEnd + 8, false); // 数据长度：A = 4

                        // 真正的数据（A 记录里就是 IP）紧跟在固定 10 字节之后
                        const int rdStart=nameEnd+10;

                        // 建一个"回答 N"节点挂在 DNS 下面
                        QTreeWidgetItem *ansItem=new QTreeWidgetItem(dnsItem);
                        ansItem->setText(0,QStringLiteral("回答 %1").arg(i+1));
                        ansItem->setExpanded(true);

                        new QTreeWidgetItem(ansItem,QStringList()
                                            <<QStringLiteral("名字")<<anName);

                        // 类型/类：认识的那几个显示成文字，不认识的直接显示数字
                        // 三目运算符： 条件 ? 条件真时的值 : 条件假时的值
                        new QTreeWidgetItem(ansItem, QStringList()
                                            << QStringLiteral("类型")
                                            << (anType == 1 ? QStringLiteral("A (1)")
                                                            : QString::number(anType)));
                        new QTreeWidgetItem(ansItem, QStringList()
                                            << QStringLiteral("类")
                                            << (anClass == 1 ? QStringLiteral("IN (1)")
                                                             : QString::number(anClass)));
                        new QTreeWidgetItem(ansItem, QStringList()
                                            << QStringLiteral("TTL")
                                            << QString("%1 秒").arg(anTtl));

                        //   A 记录的数据就是 4 个字节，正好是一个 IPv4 地址
                        //    先判断类型，是因为 DNS 还有很多别的类型（AAAA 是 IPv6、CNAME 是别名……），
                        //    它们的数据格式完全不一样，这一步只处理 A
                        if (anType == 1 && rdLen == 4)
                            new QTreeWidgetItem(ansItem, QStringList()
                                                << QStringLiteral("地址")
                                                << ipv4ToString(m_data, rdStart));
                        else
                            new QTreeWidgetItem(ansItem, QStringList()
                                                << QStringLiteral("数据")
                                                << QStringLiteral("(类型 %1，暂不解析)").arg(anType));

                        // rdStart + rdLen = 这条记录的结尾 = 下一条记录的"名字"开头
                        pos = rdStart + rdLen;
                    }
                }
            }
        }

    }

}

Widget::~Widget()
{

}
