#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <vector>
#include <iostream>
#include <WinSock2.h>
#include <windows.h>

#define PROTO_IP 0x0800
#define PROTO_ARP 0x0806
#define PROTO_ICMP 1
#define PROTO_IGMP 2
#define PROTO_TCP 6
#define PROTO_UDP 17

#define ETHERNET_SIZE 14

typedef struct _ethernet_h
{
    u_char dst_addr[6];                 //6个字节，目标MAC地址
    u_char src_addr[6];                 //6个字节，源MAC地址
    u_short ether_type;                 //2个字节，数据帧类型
}ethernet_h;

typedef  struct _ip_h
{
    u_char    version_and_ihl;          //协议版本和报头长度
    u_char    diffserv;                 //服务类型
    u_short   total_len;                //数据包长度
    u_short   ident;                    //标识
    u_short   flags_and_frag_offset;    //标志位和帧偏移

#define IP_RF 0x8000                    //reservedfragment flag
#define IP_DF 0x4000                    //don't fragment flag
#define IP_MF 0x2000                    //more fragment flag
#define IP_OFFMASK 0x1fff               //mask for fragment offset bits

    u_char    ttl;                      //存活时间
    u_char proto;               //协议号
    u_short   hdr_checksum;             //首部校验和
    u_char    src_ip_addr[4];           //源地址
    u_char    dst_ip_addr[4];           //目的地址

}ip_h;

#define IP_HL(ip)       ((ip)->version_and_ihl & 0x0f)   //得到后4位，即报文的首部长度
#define IP_V(ip)        (((ip)->version_and_ihl) >> 4)   //得到协议版本

typedef  struct _arp_h
{
    u_short hw_type;                   //硬件类型
    u_short proto_type;         //协议类型
    u_char hw_addr_len;               //硬件地址长度
    u_char proto_addr_len;            //协议地址长度
    u_short opcode;                   //操作字段
    u_char src_hw_addr[6];            //发送端以太网地址
    u_char src_proto_addr[4];         //发送端IP地址
    u_char dst_hw_addr[6];            //接收端以太网地址
    u_char dst_proto_addr[4];         //接收端IP地址

}arp_h;

typedef struct _tcp_h
{
    u_short src_port;                 //源端口号
    u_short dst_port;                 //目的端口号
    u_int   seq_no;                   //序列号
    u_int   ack_no;                   //确认序列号
    u_char  hdr_len_and_res;          //首部长度和保留位

#define TH_OFF(th) (((th)->hdr_len_and_res & 0xf0) >> 4)   //得到前4位，即包首部长度

#define TH_FIN 0X01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0X80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

    u_char  res_and_flags;            //保留2位和6个标志位
    u_short window;                   //窗口大小
    u_short checksum;                 //校验和
    u_short urgent_ptr;               //紧急指针

}tcp_h;

typedef struct _udp_h
{
    u_short src_port;                //源端口
    u_short dst_port;                //目的端口
    u_short len;                     //UDP数据包长度
    u_short checksum;                //UDP数据包校验和
}udp_h;

typedef struct _icmp_h
{
    u_char type;           //类型，0或0
    u_char code;           //代码
    u_short checksum;      //校验和
    u_short identi;        //标志符
    u_short seq;           //序号
}icmp_h;

//各类数据包计数
typedef struct _p_count
{
    int cnt_ip;
    int cnt_arp;
    int cnt_tcp;
    int cnt_udp;
    int cnt_icmp;
    int cnt_igmp;
    int cnt_http;
    int cnt_other;
    int cnt_sum;
}p_count;

//数据包的分析结构
typedef struct _p_data_analysis
{
    char p_type[8];                   //包类型
    int time[6];                      //时间戳
    int len;                          //长度

    struct _ethernet_h *eth_hdr;      //以太网帧头
    struct _arp_h *arp_hdr;           //arp包头
    struct _ip_h *ip_hdr;             //ip包头
    struct _icmp_h *icmp_hdr;         //icmp包头
    struct _udp_h *udp_hdr;           //udp包头
    struct _tcp_h *tcp_hdr;           //tcp包头
    u_char* app_hdr;                  //应用层包头
    bool isHttp = false;
    int httpsize;
}p_data_analysis;


typedef std::vector<p_data_analysis *> p_data_analysis_vec;    //p:packet，该容器用于存储数据包分析结果
typedef std::vector<u_char *> p_data_primitive_vec;            //该容器用于存储原始数据包

#endif // PROTOCOL_H

