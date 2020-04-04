#ifndef PCAPANALYSISUTILS_H
#define PCAPANALYSISUTILS_H
#include <protocol.h>

#define HAVE_REMOTE
#include <pcap.h>
#include <remote-ext.h>



class PcapAnalysisUtils
{
public:
    int p_analyze_ether(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt);
    int p_analyze_ip(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt);
    int p_analyze_arp(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt);
    int p_analyze_tcp(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt);
    int p_analyze_udp(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt);
    int p_analyze_icmp(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt);
    int p_analyze_igmpv1(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt);
    int p_analyze_igmpv2(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt);
    int p_analyze_igmpv3(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt);
    PcapAnalysisUtils();
private:
    const u_char *p_init_addr;
};

#endif // PCAPANALYSISUTILS_H
