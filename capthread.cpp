#include "capthread.h"
#include <QTextStream>
#include <QDebug>

//冒号后相当于初始化这两个参数：p_data_analysis_link = p_data_analysis_vector
CapThread::CapThread(pcap_t *adhandle, p_count * p_cnt, p_data_analysis_vec &p_data_analysis_vector, p_data_primitive_vec &p_data_primitive_vector, pcap_dumper_t *dumpfile):
    p_data_analysis_link(p_data_analysis_vector),p_data_primitive_link(p_data_primitive_vector)
{
    stopped = false;
    this->adhandle = adhandle;
    this->p_cnt = p_cnt;
    this->dumpfile = dumpfile;
}

void CapThread::run()
{
    int res = 0;
    struct tm *ltime;
    time_t local_tv_sec;
    char timestr[16];
    struct pcap_pkthdr *header = NULL;
    const u_char *pkt_data = NULL;
    u_char *primitive_data = NULL;

    while(stopped != true && (res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        if(res == 0)
        {
            /* 超时时间到 */
            qDebug() << res;
            continue;
        }

        //初始化一个临时变量data_analysis，用于存储数据包分析结果

        struct _p_data_analysis * data_analysis = (struct _p_data_analysis*)malloc(sizeof(struct _p_data_analysis));
        data_analysis->isHttp = false;
        memset(data_analysis, 0, sizeof(_p_data_analysis));

        data_analysis->len = header->len;
        //进行数据包分析
        //qDebug()<<"analysing...";
        PcapAnalysisUtils *analysis_res = new PcapAnalysisUtils;
        if(analysis_res->p_analyze_ether(pkt_data, data_analysis, p_cnt) < 0)
        {
            continue;  //分析不了则跳过
        }

        //保存数据包
        if(dumpfile != NULL){
            pcap_dump((u_char *)dumpfile, header, pkt_data);
        }

        p_data_analysis_link.push_back(data_analysis);      //将数据包分析结果存入分析结果存储容器

        primitive_data = (u_char *)malloc(header->len * sizeof(u_char));
        memcpy(primitive_data, pkt_data, header->len);
        p_data_primitive_link.push_back(primitive_data);    //将原始数据包信息存入原始数据包存储容器

        emit cap_thread_update_statics();                   //发出更新统计信息的信号

        //获得表格各项的数据
        //获得数据包时间戳
        local_tv_sec = header->ts.tv_sec;     //秒
        ltime = localtime(&local_tv_sec);     //返回指向local_tb_sec的指针
        data_analysis->time[0] = ltime->tm_year + 1900;
        data_analysis->time[1] = ltime->tm_mon + 1;
        data_analysis->time[2] = ltime->tm_mday;
        data_analysis->time[3] = ltime->tm_hour;
        data_analysis->time[4] = ltime->tm_min;
        data_analysis->time[5] = ltime->tm_sec;
        QString time_stamp;
        QTextStream(&time_stamp) << data_analysis->time[0] << "-" << data_analysis->time[1] << "-" << data_analysis->time[2]
                                                << " " << data_analysis->time[3] << ":" << data_analysis->time[4]
                                                << ":" << data_analysis->time[5];

        char * buf = (char *)malloc(80 * sizeof (char));
        //获得源IP地址
        QString src_ip_addr;
        if(data_analysis->eth_hdr->ether_type == 0x0806)  //ARP
        {
            snprintf(buf, 80 * sizeof (char),"%d.%d.%d.%d", data_analysis->arp_hdr->src_proto_addr[0], data_analysis->arp_hdr->src_proto_addr[1],
                    data_analysis->arp_hdr->src_proto_addr[2], data_analysis->arp_hdr->src_proto_addr[3]);
            src_ip_addr = QString(QLatin1String(buf));
        }
        else if(data_analysis->eth_hdr->ether_type == 0x0800) //IP
        {
            snprintf(buf,80 * sizeof (char),"%d.%d.%d.%d", data_analysis->ip_hdr->src_ip_addr[0], data_analysis->ip_hdr->src_ip_addr[1],
                    data_analysis->ip_hdr->src_ip_addr[2], data_analysis->ip_hdr->src_ip_addr[3]);
            src_ip_addr = QString(QLatin1String(buf));
        }

        //获得目的IP地址
        QString dst_ip_addr;
        if(data_analysis->eth_hdr->ether_type == 0x0806)  //ARP
        {
            snprintf(buf, 80 * sizeof (char),"%d.%d.%d.%d", data_analysis->arp_hdr->dst_proto_addr[0], data_analysis->arp_hdr->dst_proto_addr[1],
                    data_analysis->arp_hdr->dst_proto_addr[2], data_analysis->arp_hdr->dst_proto_addr[3]);
            dst_ip_addr = QString(QLatin1String(buf));
        }
        else if(data_analysis->eth_hdr->ether_type == 0x0800) //IP
        {
            snprintf(buf, 80 * sizeof (char),"%d.%d.%d.%d", data_analysis->ip_hdr->dst_ip_addr[0], data_analysis->ip_hdr->dst_ip_addr[1],
                    data_analysis->ip_hdr->dst_ip_addr[2], data_analysis->ip_hdr->dst_ip_addr[3]);
            dst_ip_addr = QString(QLatin1String(buf));
        }

        //获得协议名
        QString proto_name = QString(data_analysis->p_type);
        //获得数据包长度
        QString p_len = QString::number(data_analysis->len);

        //发出更新表格的信号
        //qDebug() << "emit update";
        /*qDebug() << time_stamp << " - "
                 << src_ip_addr << " - "
                 << dst_ip_addr << " - "
                 << proto_name << " - "
                 << p_len;*/
        emit cap_thread_add_pkt_line(time_stamp, src_ip_addr, dst_ip_addr, proto_name, p_len);
        free(buf);
    }
}

void CapThread::stop()
{
    QMutexLocker locker(&cap_thread_stop_lock);
    stopped = true;
}
