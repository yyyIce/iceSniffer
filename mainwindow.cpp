#include "mainwindow.h"
#include "ui_mainwindow.h"

#pragma execution_character_set("utf-8")


#include <QMessageBox>
#include <QDebug>
#include <QDir>
#include <QDateTime>
#include <QFileDialog>
#include <QColor>


MainWindow:: MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui:: MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("iceSniffer");
    //this->setWindowIcon(QIcon("icon.png"));
    this->icesniff_get_dev_list();
    this->icesniff_init_ui();
    p_cnt = (p_count *)malloc(sizeof (p_count));
    cap_thread = NULL;

    m_Timer = new QTimer(this);   //计时器在start_cap中打开，在stop中停止，时间间隔为10s
    connect(m_Timer,SIGNAL(timeout()),this,SLOT(icesniff_draw_cnt_curve()));          //定时刷新曲线
    connect(this->ui->cbox_nic, SIGNAL(activated(int)),this, SLOT(icesniff_set_nic_mode()));  //下拉选择列表：获取当前选择网卡的编号
    connect(this->ui->btn_start, SIGNAL(clicked(bool)), this, SLOT(icesniff_start_cap()));    //开始按钮：根据捕获过滤条件抓包
    connect(this->ui->btn_stop, SIGNAL(clicked(bool)), this, SLOT(icesniff_stop_cap()));      //停止按钮：停止抓包
    connect(this->ui->btn_showfilter_apply,SIGNAL(clicked(bool)), this, SLOT(icesniff_show_filter())); //过滤按钮，按选择的显示规则显示数据包
    connect(this->ui->tw_cap_list, SIGNAL(cellClicked(int, int)), this, SLOT(icesniff_show_p_analysis(int, int))); //2个分析结果窗口：当选中数据包时显示分析信息
    connect(this->ui->actionsavefile, SIGNAL(triggered()), this, SLOT(icesniff_save_file()));   //菜单栏：文件->保存
    connect(this->ui->actionopenfile, SIGNAL(triggered()), this, SLOT(icesniff_open_file()));   //菜单栏：文件->打开
    connect(this->ui->actionexit, SIGNAL(triggered()), this, SLOT(icesniff_close()));           //菜单栏：文件->退出

}

MainWindow::~ MainWindow()
{
    delete ui;
}

void MainWindow::icesniff_init_ui()
{

    /* 将获取的设备列表填入下拉选择列表 */
    for(dev = alldevs; dev != NULL; dev = dev ->next)
    {
        if (dev->description){
            ui->cbox_nic->addItem(QString("%1").arg(dev->description));
            qDebug() << dev->description;
        }
    }

    //初始化显示过滤器下拉列表
    ui->cbox_showfilter->addItem(QString("不过滤"));
    ui->cbox_showfilter->addItem(QString("ARP only"));
    ui->cbox_showfilter->addItem(QString("UDP only"));
    ui->cbox_showfilter->addItem(QString("ICMP only"));
    ui->cbox_showfilter->addItem(QString("TCP only"));
    ui->cbox_showfilter->addItem(QString("HTTP only"));

    //初始化
    is_file_saved = false;
    row_cnt = 0;
    ui->btn_stop->setEnabled(false);
    ui->btn_showfilter_apply->setEnabled(true);

    ui->tw_cap_list->setColumnCount(6);
    ui->tw_cap_list->setHorizontalHeaderLabels(QStringList() << tr("序号") << tr("时间")
                                              << tr("源IP地址") << tr("目的IP地址")
                                               << tr("协议类型") << tr("长度"));
    //设置为单行选中
    ui->tw_cap_list->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置选择模式，即选择单行
    ui->tw_cap_list->setSelectionMode(QAbstractItemView::SingleSelection);
    //设置为禁止修改
    ui->tw_cap_list->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tw_cap_list->setColumnWidth(0, 100);
    ui->tw_cap_list->setColumnWidth(1, 200);
    ui->tw_cap_list->setColumnWidth(2, 210);
    ui->tw_cap_list->setColumnWidth(3, 210);
    ui->tw_cap_list->setColumnWidth(4, 100);
    ui->tw_cap_list->setColumnWidth(5, 100);
    //connect(ui->tw_cap_list, SIGNAL(cellClicked(int,int)), this, SLOT(showProtoTree(int,int)));

    ui->tw_cap_list->verticalHeader()->setVisible(false);    //隐藏列表头
    ui->tree_proto->setColumnCount(1);
    //设置协议解析窗口表头
    ui->tree_proto->setHeaderLabel(QString("协议分析"));
    ui->tree_proto->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tree_proto->header()->setStretchLastSection(false);

    x_time.append(0);
    y_tcp_cnt.append(0);
    y_arp_cnt.append(0);
    y_icmp_cnt.append(0);
    y_udp_cnt.append(0);
    y_http_cnt.append(0);
    //初始化分析曲线图
    ui->widget->xAxis->setLabel("时间(s)");
    //y轴的文字
    ui->widget->yAxis->setLabel("数据包数量(个)");
    //x轴范围
    ui->widget->xAxis->setRange(0,20);
    //y轴范围
    ui->widget->yAxis->setRange(0,100);

}

int MainWindow::icesniff_get_dev_list()
{
    int ret = 0;
    /* 获取本地机器设备列表 */
    if (pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        QMessageBox::warning(this, tr("iceSniffer"),tr("无法获取网卡"),QMessageBox::Ok);
        ret = -1;
    }
    /* 不再需要设备列表了，释放它 */
    //pcap_freealldevs(alldevs);
    return ret;
}

int MainWindow::icesniff_set_nic_mode()
{
    int i = 0, ret = 0;
    qDebug() << "Nic Index:" << ui->cbox_nic->currentIndex();
    nic_index = ui->cbox_nic->currentIndex();
    if(nic_index == 0){
        QMessageBox::warning(this, "warning", tr("请选择一个合适的网卡接口"), QMessageBox::Ok);
    }

    //pcap_freealldevs(alldevs);
    return ret;
}

int MainWindow::icesniff_create_dumpfile()
{
    //文件存储在./iceSniffer/pcap/目录下，命名为20200322184552.pcap


    QString current_path = QDir::currentPath();
    qDebug() << current_path;
    //检查路径是否存在
    QString dumpfile_dir_path = current_path + "//pcap";
    QDir dir(dumpfile_dir_path);
    if(!dir.exists())
    {
        //路径不存在则创建路径
        if(!dir.mkdir(dumpfile_dir_path))
        {
            QMessageBox::warning(this, "warning", tr("创建文件保存路径失败！"),QMessageBox::Ok);
            return -1;
        }
    }
    //设置数据包名
    QDateTime current_qtime = QDateTime::currentDateTime();   //获取当前时间
    QString current_time = current_qtime.toString("yyyyMMddhhmmss");  //将当前时间转换为指定格式
    QString file_name = current_path + "/" + current_time + ".pcap";
    std::string str_tmp = file_name.toStdString();
    snprintf(file_path, sizeof(file_path), "%s",str_tmp.c_str());

    qDebug()<<file_path;

    dumpfile =  pcap_dump_open(adhandle, file_path);
    if(dumpfile == NULL)
    {
        QMessageBox::warning(this, "warning", tr("脱机堆文件打开错误"), QMessageBox::Ok);
        return -1;
    }

}

int MainWindow::icesniff_start_cap_thread()
{
    int ret = 1;
    u_int netmask;
    struct bpf_program fcode;

    /* 检查数据链路层，为了简单，我们只考虑以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if(dev->addresses != NULL)
    {
        /* 获得接口第一个地址的掩码 */
        netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else
    {
        /* 如果接口没有地址，那么我们假设一个C类的掩码 */
        netmask=0xffffff;
    }

    //设置过滤器
    QString cap_filter_text = ui->le_cap_filter->text();
    //编译过滤器
    if(cap_filter_text == NULL){
        char filter[]="";
        if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )
        {
            QMessageBox::warning(this, "Sniff", tr("Unable to compile the packet filter. Check the syntax."), QMessageBox::Ok);
            /* 释放设备列表 */
            pcap_freealldevs(alldevs);
            return -1;
        }
    }
    else
    {
        char *filter = NULL;
        QByteArray ba = cap_filter_text.toLatin1();
        filter = ba.data();
        if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )
        {
            QMessageBox::warning(this, "Sniff", tr("过滤表达式不正确!"), QMessageBox::Ok);
            icesniff_reset();
            /* 释放设备列表 */
            pcap_freealldevs(alldevs);
            return -1;
        }
    }
    //设置过滤器
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        //fprintf(stderr,"\nError setting the filter.\n");
        icesniff_reset();
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //设置文件存储路径和文件名称
    if(icesniff_create_dumpfile() == -1)
    {
        icesniff_clear_lastcap_data();
        return -1;
    }
    /* 释放设备列表 */
    pcap_freealldevs(alldevs);

    //新建抓包线程实例
    cap_thread = new CapThread(adhandle, p_cnt, p_data_analysis_link, p_data_primitive_link, dumpfile);
    //设置连接，接收抓包线程发来的更新信号
    connect(cap_thread, SIGNAL(cap_thread_add_pkt_line(QString, QString, QString, QString, QString)),
            this, SLOT(icesniff_update_cap_list_view(QString, QString, QString, QString, QString)));
    connect(cap_thread, SIGNAL(cap_thread_update_statics()), this, SLOT(icesniff_update_p_cnt_view()));
    //开启线程
    cap_thread->start();
    return 1;
}

void MainWindow::icesniff_stop_cap()
{
    //设置按钮状态
    ui->btn_start->setEnabled(true);
    ui->btn_stop->setEnabled(false);
    ui->le_cap_filter->setEnabled(true);
    ui->btn_showfilter_apply->setEnabled(true);
    //当点击停止捕获按钮时开始菜单栏中的保存设置为可以点击
    //saveAction->setEnabled(true);
    //停止线程
    cap_thread->stop();
    cap_thread->quit();
    cap_thread->wait();
    //关闭winpcap会话句柄，并释放其资源
    m_Timer->stop();
    pcap_close(adhandle);
}

void MainWindow::icesniff_clear_lastcap_data()
{
    //清空分析数据，原始数据
    std::vector<p_data_analysis *>::iterator it;
    for(it = p_data_analysis_link.begin(); it != p_data_analysis_link.end(); it++)
    {
        free((*it)->eth_hdr);
        free((*it)->ip_hdr);
        free((*it)->arp_hdr);
        free((*it)->icmp_hdr);
        free((*it)->tcp_hdr);
        free((*it)->udp_hdr);
        free((*it)->app_hdr);
        free(*it);
    }
    p_data_analysis_vec().swap(p_data_analysis_link);
    std::vector<u_char *>::iterator kt;
    for(kt = p_data_primitive_link.begin(); kt != p_data_primitive_link.end(); kt++)
    {
        free(*kt);
    }

    p_data_primitive_vec().swap(p_data_primitive_link);

    cap_thread = NULL;

    memset(p_cnt, 0, sizeof (struct _p_count));

    //清空图形界面的捕获列表、协议分析、Hex
    ui->tw_cap_list->clearContents();
    ui->tw_cap_list->setRowCount(0);
    ui->tree_proto->clear();
    ui->te_hex->clear();
    //save_action = false;

    //清空曲线图相关数据
    x_time.clear();
    y_arp_cnt.clear();
    y_icmp_cnt.clear();
    y_udp_cnt.clear();
    y_tcp_cnt.clear();
    y_http_cnt.clear();
    draw_cnt = 0;
    x_time.append(0);
    y_arp_cnt.append(0);
    y_icmp_cnt.append(0);
    y_udp_cnt.append(0);
    y_tcp_cnt.append(0);
    y_http_cnt.append(0);
    x_l = 0;
    y_l = 0;
    x_r = 20;
    y_r = 100;

    icesniff_draw_cnt_curve();
}

int MainWindow::icesniff_save_cap_file(const QString &file_name)
{
    int ret = 0;
    QString cur_file = QString(file_path);
    if(cur_file.isEmpty())
    {
        return -1;
    }
    if(!QFile::copy(cur_file, file_name))
    {
        QMessageBox::warning(this, "warning", tr("文件保存失败！"),QMessageBox::Ok);
        return -1;
    }
    QMessageBox::warning(this, "warning", tr("文件保存成功！"),QMessageBox::Ok);
    is_file_saved = true;
    return ret;
}

void MainWindow::icesniff_start_cap()
{
    int i = 0;

    //如果list里边有数据，提示保存
    if(is_file_saved == false && row_cnt != 0)
    {
        int ret = 0;
        ret = QMessageBox::information(this, "iceSniffer", tr("是否保存此次捕获结果"), QMessageBox::Save, QMessageBox::Cancel);
        if(ret == QMessageBox::Save){
            QString file_name = QFileDialog::getSaveFileName(this,
                                                            tr("另存为"),
                                                            ".", tr("保存捕获数据(*.pcap)"));
            if(!file_name.isEmpty()){
                icesniff_save_cap_file(file_name);
            }
        }
        else if(ret == QMessageBox::Cancel){

        }
    }
    if(nic_index != 0) //如果没有选择
    {
        //开始前的上一次数据清理工作，存储结构体内容释放，捕捉列表和协议分析视图清空
        icesniff_clear_lastcap_data();
        //设置按钮是否可用
        ui->btn_start->setEnabled(false);
        ui->btn_stop->setEnabled(true);
        ui->btn_showfilter_apply->setEnabled(false);
        is_file_saved = false;
        ui->le_cap_filter->setEnabled(false);
        //重新获取网络接口信息
        if(icesniff_get_dev_list() < 0)
        {
            return;
        }

        //再次打开网络适配器
        for(dev = alldevs, i = 0; i < nic_index - 1 ;dev = dev->next, i++);
        if ( (adhandle = pcap_open(dev->name,          // 设备名
                                  65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                                  PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                                  1000,             // 读取超时时间
                                  NULL,             // 远程机器验证
                                  errbuf            // 错误缓冲池
                                  ) ) == NULL)
        {
            QMessageBox::warning(this, tr("iceSniffer"),tr("Winpcap isn't support it!"),QMessageBox::Ok);
            pcap_freealldevs(alldevs);
            return;
        }

        m_Timer->start(1000);
        //启动抓包线程
        if(icesniff_start_cap_thread() < 0)
        {
            return;
        }
    }
    else
    {
        icesniff_reset();
        QMessageBox::warning(this, "warning", tr("请选择网络适配器！"),QMessageBox::Ok);
    }


}

void MainWindow::icesniff_update_cap_list_view(QString time_stamp, QString src_ip_addr, QString dst_ip_addr, QString proto, QString p_len)
{
    //qDebug() <<"updating...";
    /*qDebug() << time_stamp << " * "
             << src_ip_addr << " * "
             << dst_ip_addr << " * "
             << proto << " * "
             << p_len;*/

    row_cnt = ui->tw_cap_list->rowCount();
    ui->tw_cap_list->insertRow(row_cnt);
    QString cap_seq = QString::number(row_cnt, 10);
    ui->tw_cap_list->setItem(row_cnt, 0, new QTableWidgetItem(cap_seq));
    ui->tw_cap_list->setItem(row_cnt, 1, new QTableWidgetItem(time_stamp));
    ui->tw_cap_list->setItem(row_cnt, 2, new QTableWidgetItem(src_ip_addr));
    ui->tw_cap_list->setItem(row_cnt, 3, new QTableWidgetItem(dst_ip_addr));
    ui->tw_cap_list->setItem(row_cnt, 4, new QTableWidgetItem(proto));
    ui->tw_cap_list->setItem(row_cnt, 5, new QTableWidgetItem(p_len));


    //添加滚动条
    if(row_cnt > 1)
    {
        ui->tw_cap_list->scrollToItem(ui->tw_cap_list->item(row_cnt,0), QAbstractItemView::PositionAtBottom);
    }
    //给不同协议附带不同的背景颜色

    QColor color;
    if(proto == "TCP" || proto == "HTTP"){
        color = QColor(228,255,199);
    }
    else if(proto == "UDP"){
        color = QColor(218,238,255);
    }
    else if(proto == "ARP"){
        color = QColor(250,240,215);
    }
    else if(proto == "ICMP"){
        color = QColor(252,224,255);
    }
    for(int i = 0; i < 6 ; i ++){
        ui->tw_cap_list->item(row_cnt,i)->setBackgroundColor(color);
    }
}

void MainWindow::icesniff_update_p_cnt_view()
{
    //更新统计数值
    ui->le_ip_cnt->setText(QString::number(p_cnt->cnt_ip));
    ui->le_arp_cnt->setText(QString::number(p_cnt->cnt_arp));
    ui->le_icmp_cnt->setText(QString::number(p_cnt->cnt_icmp));
    ui->le_udp_cnt->setText(QString::number(p_cnt->cnt_udp));
    ui->le_tcp_cnt->setText(QString::number(p_cnt->cnt_tcp));
    ui->le_http_cnt->setText(QString::number(p_cnt->cnt_http));
    ui->le_other_cnt->setText(QString::number(p_cnt->cnt_other));
    ui->le_sum_cnt->setText(QString::number(p_cnt->cnt_sum));

}

void MainWindow::icesniff_draw_cnt_curve()
{
    x_r = x_r + time_cnt;
    y_r = y_r + time_cnt * 3;
    x_time.append(x_time[draw_cnt++] + 1);
    y_arp_cnt.append(p_cnt->cnt_arp);
    y_icmp_cnt.append(p_cnt->cnt_icmp);
    y_udp_cnt.append(p_cnt->cnt_udp);
    y_tcp_cnt.append(p_cnt->cnt_tcp);
    y_http_cnt.append(p_cnt->cnt_http);
    //满100个点清空重绘
    if(draw_cnt == 100)
    {
        x_time.clear();
        y_arp_cnt.clear();
        y_icmp_cnt.clear();
        y_udp_cnt.clear();
        y_tcp_cnt.clear();
        y_http_cnt.clear();
        draw_cnt = 0;
        x_time.append(0);
        y_arp_cnt.append(0);
        y_icmp_cnt.append(0);
        y_udp_cnt.append(0);
        y_tcp_cnt.append(0);
        y_http_cnt.append(0);
        x_l = x_r;
        y_l = y_r;
        x_r = x_l + 100;
        y_r = y_l + 150;
    }
    //添加一条曲线
    ui->widget->addGraph();
    //x是曲线序号，添加的第一条是0，设置曲线颜色
    ui->widget->graph(0)->setPen(QPen(Qt::red));
    ui->widget->graph(0)->setData(x_time, y_arp_cnt);
    ui->widget->addGraph();
    ui->widget->graph(1)->setPen(QPen(Qt::magenta));
    ui->widget->graph(1)->setData(x_time, y_icmp_cnt);

    ui->widget->addGraph();
    ui->widget->graph(2)->setPen(QPen(Qt::blue));
    ui->widget->graph(2)->setData(x_time, y_udp_cnt);

    ui->widget->addGraph();
    ui->widget->graph(3)->setPen(QPen(Qt::green));
    ui->widget->graph(3)->setData(x_time, y_tcp_cnt);

    ui->widget->addGraph();
    ui->widget->graph(4)->setPen(QPen(Qt::darkCyan));
    ui->widget->graph(4)->setData(x_time, y_http_cnt);
    //x轴的文字
    ui->widget->xAxis->setLabel("时间(s)");
    //y轴的文字
    ui->widget->yAxis->setLabel("数据包数量(个)");
    //x轴范围
    ui->widget->xAxis->setRange(x_l, x_r);
    //y轴范围
    ui->widget->yAxis->setRange(y_l, y_r);
    //重绘,这个是实时绘图的关键
    ui->widget->replot();

}

void MainWindow::icesniff_show_p_analysis(int row, int column)
{

    //清空上一次点击存在的内容
    ui->tree_proto->clear();
    ui->te_hex->clear();

    //显示协议分析内容
    struct _p_data_analysis * mem_data = (struct _p_data_analysis *)p_data_analysis_link[row];

    QString str_curr;   //当前节点的值
    char buf[100];
    snprintf(buf,100 * sizeof(char), "%s","数据包分析");

    //建立根节点
    str_curr = QString(buf);
    QTreeWidgetItem * root = new QTreeWidgetItem(ui->tree_proto);
    root->setText(0, str_curr);


    //分析以太帧
    str_curr = "以太帧头部";
    QTreeWidgetItem * eth_node = new QTreeWidgetItem(root);
    eth_node->setText(0, str_curr);


    snprintf(buf, 100 * sizeof(char), "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->eth_hdr->src_addr[0], mem_data->eth_hdr->src_addr[1],
            mem_data->eth_hdr->src_addr[2], mem_data->eth_hdr->src_addr[3], mem_data->eth_hdr->src_addr[4], mem_data->eth_hdr->src_addr[5]);
    str_curr = "源MAC地址：" + QString(buf);
    QTreeWidgetItem * src_mac_node = new QTreeWidgetItem(eth_node);
    src_mac_node->setText(0, str_curr);

    snprintf(buf, 100 * sizeof(char), "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->eth_hdr->dst_addr[0], mem_data->eth_hdr->dst_addr[1],
            mem_data->eth_hdr->dst_addr[2], mem_data->eth_hdr->dst_addr[3], mem_data->eth_hdr->dst_addr[4], mem_data->eth_hdr->dst_addr[5]);
    str_curr = "目的MAC地址：" + QString(buf);
    QTreeWidgetItem * dst_mac_node = new QTreeWidgetItem(eth_node);
    dst_mac_node->setText(0, str_curr);

    snprintf(buf, 100 * sizeof(char), "类型：0x%04x", mem_data->eth_hdr->ether_type);
    str_curr = QString(buf);
    QTreeWidgetItem * eth_type_node = new QTreeWidgetItem(eth_node);
    eth_type_node->setText(0, str_curr);

    //分析arp数据包
    if(mem_data->eth_hdr->ether_type == 0x0806)
    {

        str_curr = "ARP报文头部";
        QTreeWidgetItem * arp_node = new QTreeWidgetItem(root);
        arp_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "硬件类型：0x%04x", mem_data->arp_hdr->hw_type);
        str_curr = QString(buf);
        QTreeWidgetItem * arp_hw_type_node = new QTreeWidgetItem(arp_node);
        arp_hw_type_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "协议类型：0x%04x", mem_data->arp_hdr->proto_type);
        str_curr = QString(buf);
        QTreeWidgetItem * arp_proto_type_node = new QTreeWidgetItem(arp_node);
        arp_proto_type_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "硬件地址长度：%d", mem_data->arp_hdr->hw_addr_len);
        str_curr = QString(buf);
        QTreeWidgetItem * arp_hw_addr_len_node = new QTreeWidgetItem(arp_node);
        arp_hw_addr_len_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "协议地址长度：%d", mem_data->arp_hdr->proto_addr_len);
        str_curr = QString(buf);
        QTreeWidgetItem * arp_proto_addr_len_node = new QTreeWidgetItem(arp_node);
        arp_proto_addr_len_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "操作码：%d", mem_data->arp_hdr->opcode);
        str_curr = QString(buf);
        QTreeWidgetItem * arp_opcode_node = new QTreeWidgetItem(arp_node);
        arp_opcode_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "发送端MAC地址：%02x-%02x-%02x-%02x-%02x-%02x", mem_data->arp_hdr->src_hw_addr[0], mem_data->arp_hdr->src_hw_addr[1],
                mem_data->arp_hdr->src_hw_addr[2], mem_data->arp_hdr->src_hw_addr[3], mem_data->arp_hdr->src_hw_addr[4], mem_data->arp_hdr->src_hw_addr[5]);
        str_curr = QString(buf);
        QTreeWidgetItem * arp_src_mac_node = new QTreeWidgetItem(arp_node);
        arp_src_mac_node->setText(0, str_curr);

        snprintf(buf,100 * sizeof(char) ,"发送端IP地址：%d.%d.%d.%d", mem_data->arp_hdr->src_proto_addr[0], mem_data->arp_hdr->src_proto_addr[1],
                mem_data->arp_hdr->src_proto_addr[2], mem_data->arp_hdr->src_proto_addr[3]);
        str_curr = QString(buf);
        QTreeWidgetItem *arp_src_ip_node = new QTreeWidgetItem(arp_node);
        arp_src_ip_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "接收端MAC地址：%02x-%02x-%02x-%02x-%02x-%02x", mem_data->arp_hdr->dst_hw_addr[0], mem_data->arp_hdr->dst_hw_addr[1],
                mem_data->arp_hdr->dst_hw_addr[2], mem_data->arp_hdr->dst_hw_addr[3], mem_data->arp_hdr->dst_hw_addr[4], mem_data->arp_hdr->dst_hw_addr[5]);
        str_curr = QString(buf);
        QTreeWidgetItem * arp_dst_mac_node = new QTreeWidgetItem(arp_node);
        arp_dst_mac_node->setText(0, str_curr);

        snprintf(buf,100 * sizeof(char) ,"接收端IP地址：%d.%d.%d.%d", mem_data->arp_hdr->dst_proto_addr[0], mem_data->arp_hdr->dst_proto_addr[1],
                mem_data->arp_hdr->dst_proto_addr[2], mem_data->arp_hdr->dst_proto_addr[3]);
        str_curr = QString(buf);
        QTreeWidgetItem *arp_dst_ip_node = new QTreeWidgetItem(arp_node);
        arp_dst_ip_node->setText(0, str_curr);

    }
    if(mem_data->eth_hdr->ether_type == 0x0800)
    {
        str_curr = "IPv4报文头部";
        QTreeWidgetItem * ipv4_node = new QTreeWidgetItem(root);
        ipv4_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "版本：%d", IP_V(mem_data->ip_hdr));
        str_curr = QString(buf);
        QTreeWidgetItem * ip_version_node = new QTreeWidgetItem(ipv4_node);
        ip_version_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "首部长度：%d", IP_HL(mem_data->ip_hdr));
        str_curr = QString(buf);
        QTreeWidgetItem * ip_hlen_node = new QTreeWidgetItem(ipv4_node);
        ip_hlen_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "服务类型：%d", mem_data->ip_hdr->diffserv);
        str_curr = QString(buf);
        QTreeWidgetItem * ip_tos_node = new QTreeWidgetItem(ipv4_node);
        ip_tos_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "总长度：%d", mem_data->ip_hdr->total_len);
        str_curr = QString(buf);
        QTreeWidgetItem * ip_total_len_node = new QTreeWidgetItem(ipv4_node);
        ip_total_len_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "标识：0x%04x", mem_data->ip_hdr->ident);
        str_curr = QString(buf);
        QTreeWidgetItem * ip_ident_node = new QTreeWidgetItem(ipv4_node);
        ip_ident_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "标志(Reserved Fragment Flag)：%d", (mem_data->ip_hdr->flags_and_frag_offset & IP_RF) >> 15);
        str_curr = QString(buf);
        QTreeWidgetItem * ip_flag_rf_node = new QTreeWidgetItem(ipv4_node);
        ip_flag_rf_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "标志(Reserved Fragment Flag)：%d", (mem_data->ip_hdr->flags_and_frag_offset & IP_DF) >> 14);
        str_curr = QString(buf);
        QTreeWidgetItem * ip_flag_df_node = new QTreeWidgetItem(ipv4_node);
        ip_flag_df_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "标志(Reserved Fragment Flag)：%d", (mem_data->ip_hdr->flags_and_frag_offset & IP_MF) >> 13);
        str_curr = QString(buf);
        QTreeWidgetItem * ip_flag_mf_node = new QTreeWidgetItem(ipv4_node);
        ip_flag_mf_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "段偏移：%d", mem_data->ip_hdr->flags_and_frag_offset & IP_OFFMASK);
        str_curr = QString(buf);
        QTreeWidgetItem * ip_offset_node = new QTreeWidgetItem(ipv4_node);
        ip_offset_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "生存期：%d", mem_data->ip_hdr->ttl);
        str_curr = QString(buf);
        QTreeWidgetItem * ip_ttl_node = new QTreeWidgetItem(ipv4_node);
        ip_ttl_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "协议号：%d", mem_data->ip_hdr->proto);
        str_curr = QString(buf);
        QTreeWidgetItem * ip_proto_node = new QTreeWidgetItem(ipv4_node);
        ip_proto_node->setText(0, str_curr);

        snprintf(buf, 100 * sizeof(char), "首部校验和：0x%04x", mem_data->ip_hdr->hdr_checksum);
        str_curr = QString(buf);
        QTreeWidgetItem * ip_hchecksum_node = new QTreeWidgetItem(ipv4_node);
        ip_hchecksum_node->setText(0, str_curr);

        snprintf(buf,100 * sizeof(char) ,"%d.%d.%d.%d", mem_data->ip_hdr->src_ip_addr[0], mem_data->ip_hdr->src_ip_addr[1],
                mem_data->ip_hdr->src_ip_addr[2], mem_data->ip_hdr->src_ip_addr[3]);
        str_curr = "源IP地址：" + QString(buf);
        QTreeWidgetItem *ip_src_ip_node = new QTreeWidgetItem(ipv4_node);
        ip_src_ip_node->setText(0, str_curr);

        snprintf(buf,100 * sizeof(char) ,"%d.%d.%d.%d", mem_data->ip_hdr->dst_ip_addr[0], mem_data->ip_hdr->dst_ip_addr[1],
                mem_data->ip_hdr->dst_ip_addr[2], mem_data->ip_hdr->dst_ip_addr[3]);
        str_curr = "目的IP地址：" + QString(buf);
        QTreeWidgetItem *ip_dst_ip_node = new QTreeWidgetItem(ipv4_node);
        ip_dst_ip_node->setText(0, str_curr);

        //分析ICMP数据包
        if(mem_data->ip_hdr->proto == PROTO_ICMP)
        {
            str_curr = "ICMP报文头部";
            QTreeWidgetItem * icmp_node = new QTreeWidgetItem(root);
            icmp_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "类型：%d", mem_data->icmp_hdr->type);
            str_curr = QString(buf);
            QTreeWidgetItem * icmp_type_node = new QTreeWidgetItem(icmp_node);
            icmp_type_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "代码：%d", mem_data->icmp_hdr->code);
            str_curr = QString(buf);
            QTreeWidgetItem * icmp_code_node = new QTreeWidgetItem(icmp_node);
            icmp_code_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "校验和：0x%04x", mem_data->icmp_hdr->checksum);
            str_curr = QString(buf);
            QTreeWidgetItem * icmp_checksum_node = new QTreeWidgetItem(icmp_node);
            icmp_checksum_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "标识：0x%04x", mem_data->icmp_hdr->identi);
            str_curr = QString(buf);
            QTreeWidgetItem * icmp_identi_node = new QTreeWidgetItem(icmp_node);
            icmp_identi_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "序号：0x%04x", mem_data->icmp_hdr->seq);
            str_curr = QString(buf);
            QTreeWidgetItem * icmp_seq_node = new QTreeWidgetItem(icmp_node);
            icmp_seq_node->setText(0, str_curr);
        }

        //分析UDP数据包
        else if(mem_data->ip_hdr->proto == PROTO_UDP)
        {
            str_curr = "UDP报文头部";
            QTreeWidgetItem * udp_node = new QTreeWidgetItem(root);
            udp_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "源端口：%d", mem_data->udp_hdr->src_port);
            str_curr = QString(buf);
            QTreeWidgetItem * udp_src_node = new QTreeWidgetItem(udp_node);
            udp_src_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "目的端口：%d", mem_data->udp_hdr->dst_port);
            str_curr = QString(buf);
            QTreeWidgetItem * udp_dst_node = new QTreeWidgetItem(udp_node);
            udp_dst_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "总长度：%d", mem_data->udp_hdr->len);
            str_curr = QString(buf);
            QTreeWidgetItem * udp_len_node = new QTreeWidgetItem(udp_node);
            udp_len_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "校验和：0x%04x", mem_data->udp_hdr->checksum);
            str_curr = QString(buf);
            QTreeWidgetItem * udp_checksum_node = new QTreeWidgetItem(udp_node);
            udp_checksum_node->setText(0, str_curr);
        }

        //分析TCP数据包
        if(mem_data->ip_hdr->proto == PROTO_TCP)
        {
            str_curr = "TCP报文头部";
            QTreeWidgetItem * tcp_node = new QTreeWidgetItem(root);
            tcp_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "源端口：%d", mem_data->tcp_hdr->src_port);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_src_node = new QTreeWidgetItem(tcp_node);
            tcp_src_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "目的端口：%d", mem_data->tcp_hdr->dst_port);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_dst_node = new QTreeWidgetItem(tcp_node);
            tcp_dst_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "序列号：0x%08x", mem_data->tcp_hdr->seq_no);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_seq_no_node = new QTreeWidgetItem(tcp_node);
            tcp_seq_no_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "确认号：0x%08x", mem_data->tcp_hdr->ack_no);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_ack_no_node = new QTreeWidgetItem(tcp_node);
            tcp_ack_no_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "首部长度：%d bytes (%d)", TH_OFF(mem_data->tcp_hdr) * 4, TH_OFF(mem_data->tcp_hdr));
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_hlen_node = new QTreeWidgetItem(tcp_node);
            tcp_hlen_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "FLAG：0x%02x", mem_data->tcp_hdr->res_and_flags);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_flags_node = new QTreeWidgetItem(tcp_node);
            tcp_flags_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "CWR: %d", (mem_data->tcp_hdr->res_and_flags & TH_CWR) >> 7);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_cwr_node = new QTreeWidgetItem(tcp_node);
            tcp_cwr_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "ECE: %d", (mem_data->tcp_hdr->res_and_flags & TH_ECE) >> 6);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_ece_node = new QTreeWidgetItem(tcp_node);
            tcp_ece_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "URG: %d", (mem_data->tcp_hdr->res_and_flags & TH_URG) >> 5);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_urg_node = new QTreeWidgetItem(tcp_node);
            tcp_urg_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "ACK: %d", (mem_data->tcp_hdr->res_and_flags & TH_ACK) >> 4);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_ack_node = new QTreeWidgetItem(tcp_node);
            tcp_ack_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "PUSH: %d", (mem_data->tcp_hdr->res_and_flags & TH_PUSH) >> 3);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_push_node = new QTreeWidgetItem(tcp_node);
            tcp_push_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "RST: %d", (mem_data->tcp_hdr->res_and_flags & TH_RST) >> 2);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_rst_node = new QTreeWidgetItem(tcp_node);
            tcp_rst_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "SYN: %d", (mem_data->tcp_hdr->res_and_flags & TH_SYN) >> 1);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_syn_node = new QTreeWidgetItem(tcp_node);
            tcp_syn_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "FIN: %d", (mem_data->tcp_hdr->res_and_flags & TH_FIN));
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_fin_node = new QTreeWidgetItem(tcp_node);
            tcp_fin_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "窗口大小：%d", mem_data->tcp_hdr->window);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_window_node = new QTreeWidgetItem(tcp_node);
            tcp_window_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "校验和：0x%04x", mem_data->tcp_hdr->checksum);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_checksum_node = new QTreeWidgetItem(tcp_node);
            tcp_checksum_node->setText(0, str_curr);

            snprintf(buf, 100 * sizeof(char), "紧急指针：%d", mem_data->tcp_hdr->urgent_ptr);
            str_curr = QString(buf);
            QTreeWidgetItem * tcp_urgent_node = new QTreeWidgetItem(tcp_node);
            tcp_urgent_node->setText(0, str_curr);

            //分析HTTP报文头部
            if(mem_data->isHttp == true)
            {
                str_curr = QString("HTTP报文头部");
                QTreeWidgetItem *http_node = new QTreeWidgetItem(root);
                http_node->setText(0, str_curr);

                QString content = "";
                u_char *httpps = mem_data->app_hdr;

                qDebug() << QString(*httpps) << QString(*(httpps + 1)) << QString(*(httpps + 2)) << endl;

                u_char *httpps2 = NULL;

                const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
                for(int i = 0 ; i < 4 ; i ++){
                    httpps2 = (u_char *)strstr((char *)httpps,token[i]);
                    if(httpps2){
                        break;
                    }
                }
                int size = mem_data->httpsize - (httpps2 - httpps);

                for(int i = 0 ; i < size; i++){
                    if(httpps2[i] == 0x0d){
                        //如果到达http正文结尾
                        if(httpps2[i+1] == 0x0a && httpps2[i+2] == 0x0d && httpps2[i+3] == 0x0a){
                            content += "\\r\\n";
                            http_node->addChild(new QTreeWidgetItem(http_node,QStringList(content)));
                            http_node->addChild(new QTreeWidgetItem(http_node,QStringList("\\r\\n")));
                            break;
                        }
                        else if(httpps2[i+1] == 0x0a){
                            http_node->addChild(new QTreeWidgetItem(http_node,QStringList(content + "\\r\\n")));
                            content = "";
                            i ++;
                            continue;
                        }
                    }
                    content += httpps2[i];
                }
                http_node->addChild(new QTreeWidgetItem(http_node,QStringList("(Data)(Data)")));
            }
        }
    }

    //显示协议HEX形式的内容
    u_char *print_data = (u_char *)p_data_primitive_link[row];
    int print_len = mem_data->len;
    icesniff_show_hex_content(print_data, print_len);
}

void MainWindow::icesniff_show_hex_content(u_char * print_data, int print_len)
{
    QString temp_num,temp_char;
    QString oneline;
    int i;
    temp_char = "  ";
    oneline = "";
    //格式化输出每一行 ： 行号 HEX 字符
    for(i = 0 ; i < print_len ; i ++){
        if(i % 16 == 0){
            //输出行号
            oneline += temp_num.sprintf("%04x  ",i);
        }
        oneline += temp_num.sprintf("%02x ",print_data[i]);
        if(isprint(print_data[i])){     //判断是否为可打印字符
            temp_char += print_data[i];
        }
        else{
            temp_char += ".";      //无法打印就输出.
        }
        if((i+1)%16 == 0){
            ui->te_hex->append(oneline + temp_char);
            temp_char = "  ";
            oneline = "";
        }
    }
    i %= 16;
    for(; i < 16 ; i ++){
        oneline += "   ";
    }
    ui->te_hex->append(oneline + temp_char);
}

void MainWindow::icesniff_show_filter()
{
    //先显示所有的行
    for(int i = 0; i <= row_cnt; i++)
    {
        ui->tw_cap_list->setRowHidden(i, false);
    }
    //再过滤
    show_filter_index = ui->cbox_showfilter->currentIndex();
    qDebug() << show_filter_index;
    if (row_cnt != 0)
    {
        switch (show_filter_index)
        {
        case 0:break;
        //ARP
        case 1:
            for(int i = 0; i <= row_cnt; i++ )
            {
                QString tmp = ui->tw_cap_list->item(i,4)->text();
                if(tmp !=QString::fromLocal8Bit("ARP"))
                {
                    ui->tw_cap_list->setRowHidden(i,true);
                }
            }
            break;
        //UDP
        case 2:
            for(int i = 0; i <= row_cnt; i++ )
            {
                QString tmp = ui->tw_cap_list->item(i,4)->text();
                if(tmp !=QString::fromLocal8Bit("UDP"))
                {
                    ui->tw_cap_list->setRowHidden(i,true);
                }
            }
            break;
        //ICMP
        case 3:
            for(int i = 0; i <= row_cnt; i++ )
            {
                QString tmp = ui->tw_cap_list->item(i,4)->text();
                if(tmp !=QString::fromLocal8Bit("ICMP"))
                {
                    ui->tw_cap_list->setRowHidden(i,true);
                }
            }
            break;
        //TCP
        case 4:
            for(int i = 0; i <= row_cnt; i++ )
            {
                QString tmp = ui->tw_cap_list->item(i,4)->text();
                if(tmp !=QString::fromLocal8Bit("TCP"))
                {
                    ui->tw_cap_list->setRowHidden(i,true);
                }
            }
            break;
        //HTTP
        case 5:
            for(int i = 0; i <= row_cnt; i++ )
            {
                QString tmp = ui->tw_cap_list->item(i,4)->text();
                if(tmp !=QString::fromLocal8Bit("HTTP"))
                {
                    ui->tw_cap_list->setRowHidden(i,true);
                }
            }
            break;
        default:break;
        }
    }

}


void MainWindow::icesniff_reset()
{
    ui->btn_start->setEnabled(true);
    ui->btn_stop->setEnabled(false);
    ui->btn_showfilter_apply->setEnabled(true);
    ui->le_cap_filter->setEnabled(true);
    //save_action = false;
}

void MainWindow::icesniff_save_file()
{
    QString file_name = QFileDialog::getSaveFileName(this,
                                                    tr("另存为"),
                                                    ".", tr("保存捕获数据(*.pcap)"));
    if(!file_name.isEmpty()){
        icesniff_save_cap_file(file_name);
    }
}

void MainWindow::icesniff_open_file()
{
    //在打开前，如果list里边有数据，提示保存
    if(is_file_saved == false && row_cnt != 0)
    {
        int ret = 0;
        ret = QMessageBox::information(this, "iceSniffer", tr("是否保存此次捕获结果"), QMessageBox::Save, QMessageBox::Cancel);
        if(ret == QMessageBox::Save){
            QString file_name = QFileDialog::getSaveFileName(this,
                                                            tr("另存为"),
                                                            ".", tr("保存捕获数据(*.pcap)"));
            if(!file_name.isEmpty()){
                icesniff_save_cap_file(file_name);
            }
        }
        else if(ret == QMessageBox::Cancel){

        }
    }
    //如果三个视图内有数据，清空
    icesniff_clear_lastcap_data();

    //打开文件
    pcap_t *fp;
    char source[PCAP_BUF_SIZE];
    //获取要打开文件的文件名
    QString open_file_name = QFileDialog::getOpenFileName(this, tr("打开文件"), ".", "Sniffer pkt(*.pcap)");
    std::string file_str = open_file_name.toStdString();
    const char *open_str = file_str.c_str();
    if(pcap_createsrcstr(source,           //源字符串
                         PCAP_SRC_FILE,    //要打开的文件
                         NULL,             //远程主机
                         NULL,             //远程主机端口
                         open_str,          //我们要打开的文件名
                         errbuf
                         ) != 0)
    {
        QMessageBox::warning(this, "warning", tr("未打开任何文件!"), QMessageBox::Ok);
        return;
    }
    /* 打开捕获文件, 现场捕获是pcap_open_live*/
    if ( (fp= pcap_open(source,             // 设备名
                        65536,              // 要捕捉的数据包的部分
                                            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                         PCAP_OPENFLAG_PROMISCUOUS,     // 混杂模式
                         1000,              // 读取超时时间
                         NULL,              // 远程机器验证
                         errbuf             // 错误缓冲池
                         ) ) == NULL)
    {
         QMessageBox::warning(this, "warning", tr("无法打开文件！"), QMessageBox::Ok);
         return;
    }
    //新建抓包线程实例
    cap_thread = new CapThread(fp, p_cnt, p_data_analysis_link, p_data_primitive_link, NULL);
    //设置连接，接收抓包线程发来的更新信号
    connect(cap_thread, SIGNAL(cap_thread_add_pkt_line(QString, QString, QString, QString, QString)),
            this, SLOT(icesniff_update_cap_list_view(QString, QString, QString, QString, QString)));
    connect(cap_thread, SIGNAL(cap_thread_update_statics()), this, SLOT(icesniff_update_p_cnt_view()));
    //开启线程
    cap_thread->start();
}

void MainWindow::icesniff_close()
{
    this->close();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    //如果list里边有数据，提示保存
    if(is_file_saved == false && row_cnt != 0)
    {
        int ret = 0;
        ret = QMessageBox::information(this, "iceSniffer", tr("是否保存此次捕获结果"), QMessageBox::Save, QMessageBox::Cancel);
        if(ret == QMessageBox::Save){
            QString file_name = QFileDialog::getSaveFileName(this,
                                                            tr("另存为"),
                                                            ".", tr("保存捕获数据(*.pcap)"));
            if(!file_name.isEmpty()){
                icesniff_save_cap_file(file_name);
            }
        }
        else if(ret == QMessageBox::Cancel){

        }
    }
    //如果三个视图内有数据，清空
    icesniff_clear_lastcap_data();
    x_time.clear();
    y_arp_cnt.clear();
    y_icmp_cnt.clear();
    y_udp_cnt.clear();
    y_tcp_cnt.clear();
    y_http_cnt.clear();
}
