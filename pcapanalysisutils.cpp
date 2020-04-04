#include "pcapanalysisutils.h"
#include <QDebug>
#pragma comment(lib,"ws2_32.lib")

PcapAnalysisUtils::PcapAnalysisUtils()
{

}

int PcapAnalysisUtils::p_analyze_ether(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt)
{
    int ret = 0;
    p_init_addr = pkt;
    struct _ethernet_h * eth_h = (struct _ethernet_h*)pkt;
    data_analysis->eth_hdr = (struct _ethernet_h *)malloc(sizeof(struct _ethernet_h));
    if(data_analysis->eth_hdr == NULL)
    {
        qDebug() << "申请以太网头部空间失败";
        return -1;
    }
    //按以太帧格式解析以太网帧头部
    for(int i = 0; i < 6; i++)
    {
        data_analysis->eth_hdr->dst_addr[i] = eth_h->dst_addr[i];
        data_analysis->eth_hdr->src_addr[i] = eth_h->src_addr[i];
    }
    p_cnt->cnt_sum++;
    data_analysis->eth_hdr->ether_type = ntohs(eth_h->ether_type);

    //解析网络层协议
    switch(data_analysis->eth_hdr->ether_type)
    {
        case PROTO_IP:
            ret = p_analyze_ip((u_char *)pkt + 14, data_analysis, p_cnt);
            break;
        case PROTO_ARP:
            ret = p_analyze_arp((u_char *)pkt + 14, data_analysis, p_cnt);
            break;
        default:
            p_cnt->cnt_other++;
            ret = -1;
            break;
    }
    return ret;
}


int PcapAnalysisUtils::p_analyze_ip(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt)
{
    int ret = 0;
    struct _ip_h *ip_h = (struct _ip_h*)pkt;
    data_analysis->ip_hdr = (struct _ip_h *)malloc(sizeof(struct _ip_h));
    if(data_analysis->ip_hdr == NULL)
    {
        qDebug() << "申请IP头部空间失败";
        return -1;
    }
    p_cnt->cnt_ip++;
    data_analysis->ip_hdr->version_and_ihl = ip_h->version_and_ihl;
    data_analysis->ip_hdr->diffserv = ip_h->diffserv;
    data_analysis->ip_hdr->total_len = ntohs(ip_h->total_len);
    data_analysis->ip_hdr->ident = ntohs(ip_h->ident);
    data_analysis->ip_hdr->flags_and_frag_offset = ntohs(ip_h->flags_and_frag_offset);
    data_analysis->ip_hdr->ttl = ip_h->ttl;
    data_analysis->ip_hdr->proto = ip_h->proto;
    data_analysis->ip_hdr->hdr_checksum = ntohs(ip_h->hdr_checksum);

    for(int i = 0; i < 4; i++)
    {
        data_analysis->ip_hdr->src_ip_addr[i] = ip_h->src_ip_addr[i];
        data_analysis->ip_hdr->dst_ip_addr[i] = ip_h->dst_ip_addr[i];
    }

    u_int ip_h_len = IP_HL(data_analysis->ip_hdr) * 4;

    //解析传输层协议
    switch(data_analysis->ip_hdr->proto)
    {
        case PROTO_ICMP:
            ret = p_analyze_icmp((u_char *)ip_h + ip_h_len, data_analysis, p_cnt);
            break;
        case PROTO_TCP:
            ret = p_analyze_tcp((u_char *)ip_h + ip_h_len, data_analysis, p_cnt);
            break;
        case PROTO_UDP:
            ret = p_analyze_udp((u_char *)ip_h + ip_h_len, data_analysis, p_cnt);
            break;
        default:
            p_cnt->cnt_other++;
            ret = -1;
            break;
    }
    return ret;
}


int PcapAnalysisUtils::p_analyze_arp(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt)
{
    int ret = 0;
    struct _arp_h * arp_h = (struct _arp_h *)pkt;
    data_analysis->arp_hdr = (struct _arp_h *)malloc(sizeof(struct _arp_h));

    if(data_analysis->arp_hdr == NULL)
    {
        qDebug() << "申请ARP头部空间失败";
        return -1;
    }

    data_analysis->arp_hdr->hw_type = ntohs(arp_h->hw_type);
    data_analysis->arp_hdr->proto_type = ntohs(arp_h->proto_type);
    data_analysis->arp_hdr->hw_addr_len = arp_h->hw_addr_len;
    data_analysis->arp_hdr->proto_addr_len = arp_h->proto_addr_len;
    data_analysis->arp_hdr->opcode = ntohs(arp_h->opcode);

    for(int i = 0; i < 6; i++)
    {
        if(i < 4)
        {
            data_analysis->arp_hdr->dst_proto_addr[i] = arp_h->dst_proto_addr[i];
            data_analysis->arp_hdr->src_proto_addr[i] = arp_h->src_proto_addr[i];
        }
        data_analysis->arp_hdr->src_hw_addr[i] = arp_h->src_hw_addr[i];
        data_analysis->arp_hdr->dst_hw_addr[i] = arp_h->dst_hw_addr[i];
    }

    snprintf(data_analysis->p_type, sizeof(data_analysis->p_type), "%s", "ARP");
    p_cnt->cnt_arp++;
    return 1;
}

int PcapAnalysisUtils::p_analyze_icmp(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt)
{
    struct _icmp_h * icmp_h = (struct _icmp_h *)pkt;
    data_analysis->icmp_hdr = (struct _icmp_h *)malloc(sizeof(struct _icmp_h));
    if(data_analysis->icmp_hdr == NULL)
    {
        qDebug() << "申请ICMP头部空间失败";
        return -1;
    }

    data_analysis->icmp_hdr->type = icmp_h->type;
    data_analysis->icmp_hdr->code = icmp_h->code;
    data_analysis->icmp_hdr->checksum = icmp_h->checksum;
    data_analysis->icmp_hdr->identi = ntohs(icmp_h->identi);
    data_analysis->icmp_hdr->seq = ntohs(icmp_h->seq);
    snprintf(data_analysis->p_type, sizeof(data_analysis->p_type), "%s", "ICMP");
    p_cnt->cnt_icmp++;
    return 1;
}

int PcapAnalysisUtils::p_analyze_tcp(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt)
{
    struct _tcp_h * tcp_h = (struct _tcp_h *)pkt;
    data_analysis->tcp_hdr = (struct _tcp_h *)malloc(sizeof (struct _tcp_h));
    if(data_analysis->tcp_hdr == NULL)
    {
        qDebug() << "申请TCP头部空间失败";
        return -1;
    }
    p_cnt->cnt_tcp++;
    data_analysis->tcp_hdr->src_port = ntohs(tcp_h->src_port);
    data_analysis->tcp_hdr->dst_port = ntohs(tcp_h->dst_port);
    data_analysis->tcp_hdr->seq_no = ntohl(tcp_h->seq_no);
    data_analysis->tcp_hdr->ack_no = ntohl(tcp_h->ack_no);
    data_analysis->tcp_hdr->hdr_len_and_res = tcp_h->hdr_len_and_res;
    data_analysis->tcp_hdr->res_and_flags = tcp_h->res_and_flags;
    data_analysis->tcp_hdr->window = ntohs(tcp_h->window);
    data_analysis->tcp_hdr->checksum = ntohs(tcp_h->checksum);
    data_analysis->tcp_hdr->urgent_ptr = ntohs(tcp_h->urgent_ptr);

    if(data_analysis->tcp_hdr->src_port == 80 || data_analysis->tcp_hdr->dst_port == 80)
    {
        u_char *http_data = (u_char *)tcp_h + TH_OFF(tcp_h) * 4;
        const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
        u_char *http_h;

        for(int i = 0 ; i < 4 ; i ++){
            http_h = (u_char *)strstr((char *)http_data,token[i]);
            if(http_h){

                p_cnt->cnt_http++;
                strcpy(data_analysis->p_type, "HTTP");
                data_analysis->isHttp = true;
                qDebug() << "debug info: find a http packet!" << endl;

                int size = data_analysis->len - ((u_char *)http_data - p_init_addr);

                qDebug() << "size: " + size << endl;

                data_analysis->httpsize = size;
                data_analysis->app_hdr = (u_char *)malloc(size * sizeof(u_char));
                for(int j = 0; j < size; j++){
                    data_analysis->app_hdr[j] = http_data[j];
                }

                return 1;
            }
        }
        snprintf(data_analysis->p_type, sizeof(data_analysis->p_type), "%s", "HTTP");
    }
    else
    {
        snprintf(data_analysis->p_type, sizeof(data_analysis->p_type), "%s", "TCP");
        p_cnt->cnt_tcp++;
    }
    return 1;
}


int PcapAnalysisUtils::p_analyze_udp(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt)
{
    struct _udp_h * udp_h = (struct _udp_h *)pkt;
    data_analysis->udp_hdr = (struct _udp_h *)malloc(sizeof (struct _udp_h));
    if(data_analysis->udp_hdr == NULL)
    {
        qDebug() << "申请UDP头部空间失败";
        return -1;
    }

    data_analysis->udp_hdr->src_port = ntohs(udp_h->src_port);
    data_analysis->udp_hdr->dst_port = ntohs(udp_h->dst_port);
    data_analysis->udp_hdr->len = ntohs(udp_h->len);
    data_analysis->udp_hdr->checksum = ntohs(udp_h->checksum);

    snprintf(data_analysis->p_type, sizeof(data_analysis->p_type), "%s", "UDP");
    p_cnt->cnt_udp++;
    return 1;
}

int PcapAnalysisUtils::p_analyze_igmpv1(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt)
{
    return 0;
}
int PcapAnalysisUtils::p_analyze_igmpv2(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt)
{
    return 0;
}
int PcapAnalysisUtils::p_analyze_igmpv3(const u_char * pkt, p_data_analysis * data_analysis, p_count * p_cnt)
{
    return 0;
}
