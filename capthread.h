#ifndef CAPTHREAD_H
#define CAPTHREAD_H
#include <QThread>
#include <QMutex>
#include <pcapanalysisutils.h>
#include <protocol.h>

class CapThread:public QThread
{
    Q_OBJECT
public:
    CapThread(pcap_t *adhandle, p_count * p_cnt, p_data_analysis_vec &p_data_analysis_vector, p_data_primitive_vec &p_data_primitive_vector, pcap_dumper_t *dumpfile);
    void stop();
protected:
    void run();
private:
    QMutex cap_thread_stop_lock;
    volatile bool stopped;
    pcap_t *adhandle;
    p_count *p_cnt;
    p_data_analysis_vec  &p_data_analysis_link;
    p_data_primitive_vec &p_data_primitive_link;
    pcap_dumper_t *dumpfile;
signals:
    void cap_thread_add_pkt_line(QString time_stamp, QString src_ip_addr, QString dst_ip_addr, QString proto, QString p_len);
    void cap_thread_update_statics();

};

#endif // CAPTHREAD_H
