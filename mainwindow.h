#ifndef MAINWINDOW_H
#define MAINWINDOW_H


#include <QMainWindow>

#define HAVE_REMOTE
#include "pcap.h"
#include "remote-ext.h"
#include "qcustomplot.h"
#include <capthread.h>



QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class  MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    pcap_if_t *alldevs;   //所有设备列表
    pcap_if_t *dev;       //设备索引，第i个设备
    pcap_t *adhandle;
    int nic_index = 0;    //当前选择的网卡索引
    int show_filter_index = 0;  //当前选择的显示过滤条件索引
    char errbuf[PCAP_ERRBUF_SIZE];

    char file_path[512];     //临时数据包保存路径
    pcap_dumper_t *dumpfile;

    p_count * p_cnt;         //数据包统计信息
    CapThread *cap_thread;    //抓包线程

    p_data_analysis_vec p_data_analysis_link;  //数据包分析信息
    p_data_primitive_vec p_data_primitive_link;//数据包原始信息
    int row_cnt;             //表格行数
    bool is_file_saved;      //文件是否保存

    int time_cnt = 1;      //曲线坐标范围更新计数器
    int x_l = 0;
    int x_r = 20;
    int y_l = 0;
    int y_r = 100;
    int draw_cnt = 0;
    QTimer* m_Timer;
    QVector<double> x_time;
    QVector<double> y_arp_cnt;
    QVector<double> y_icmp_cnt;
    QVector<double> y_udp_cnt;
    QVector<double> y_tcp_cnt;
    QVector<double> y_http_cnt;

    void icesniff_init_ui();          //初始化界面
     int icesniff_get_dev_list();     //获取当前选取的设备索引
     MainWindow(QWidget *parent = nullptr);
    ~ MainWindow();

private slots:

     int icesniff_set_nic_mode();      //打开并设置网卡
     void icesniff_start_cap();        //开始抓包
     void icesniff_stop_cap();         //停止抓包
     void icesniff_update_cap_list_view(QString time_stamp, QString src_ip_addr, QString dst_ip_addr, QString proto, QString p_len);//更新显示抓包列表
     void icesniff_show_p_analysis(int row, int column); //查看数据包分析结果
     void icesniff_open_file();         //打开文件
     void icesniff_save_file();         //保存文件
     void icesniff_close();             //退出
     void icesniff_update_p_cnt_view(); //更新统计页面
     void icesniff_show_filter();       //按过滤条件显示捕获后的数据包
     void icesniff_draw_cnt_curve();    //绘制数据包数量动态曲线

private:
    Ui:: MainWindow *ui;
    int icesniff_start_cap_thread();    //启动抓包线程
    int icesniff_create_dumpfile();     //临时保存数据包文件
    void icesniff_clear_lastcap_data(); //清空上次抓包数据，释放空间
    int icesniff_save_cap_file(const QString &file_name);  //保存抓包文件
    void icesniff_show_hex_content(u_char * print_data, int print_len);  //格式化数据包为16进制形式
    void icesniff_reset();              //还原各控件到未抓包状态
    void closeEvent(QCloseEvent *event);  //重载close_event，释放内存，防止程序退出后仍有阻塞线程


};
#endif // MAINWINDOW_H
