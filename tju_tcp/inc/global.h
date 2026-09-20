#ifndef _GLOBAL_H_
#define _GLOBAL_H_

/* ---- RDT 相关 ---- */
#define MSS          1375                    // 接近 MAX_DLEN，减少报文数
#define SNDBUF_SIZE  (512 * 1024)            // 发送缓冲 / 窗口上限(字节)
#define RCVBUF_SIZE  (512 * 1024)
#define MAX_OOO      256                     // 乱序段最多缓存多少个
#define RTO_MIN      80000L                  // 80ms
#define RTO_MAX      1000000L                // 1s，避免退避后长时间不重传
#define RTO_CHECK_US 5000L                   // 5ms 检查一次
#define MY_MIN(a,b)  ((a) < (b) ? (a) : (b))

#define MAX_RETRANSMIT_COUNT 4
#define RTO_INITIAL 200000

/* 零窗口 persist 探测（5.4.4）：探测间隔的指数增长上限 */
#define PERSIST_MAX_US 60000000L

/* 尾段探测的最小间隔（RFC 8985 RACK-TLP 思路）：
   在途只剩最老那一段时提前重发一次，避免为了一段（或它的 ACK）干等 RTO */
#define TLP_PROBE_MIN_US 30000L

#define MAX_INFLIGHT (SNDBUF_SIZE / MSS + 8)

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "global.h"
#include <pthread.h>
#include <sys/select.h>
#include <arpa/inet.h>

// 单位是byte
#define SIZE32 4
#define SIZE16 2
#define SIZE8  1

// 一些Flag
#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2
#define TRUE 1
#define FALSE 0

// 定义最大包长 防止IP层分片
#define MAX_DLEN 1375 	// 最大包内数据长度
#define MAX_LEN 1400 	// 最大包长度

// TCP socket 状态定义
#define CLOSED 0
#define LISTEN 1
#define SYN_SENT 2
#define SYN_RECV 3
#define ESTABLISHED 4
#define FIN_WAIT_1 5
#define FIN_WAIT_2 6
#define CLOSE_WAIT 7
#define CLOSING 8
#define LAST_ACK 9
#define TIME_WAIT 10

// TCP 拥塞控制状态
#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1
#define FAST_RECOVERY 2

// TCP 接受窗口大小
#define TCP_RECVWN_SIZE 32*MAX_DLEN // 比如最多放32个满载数据包

struct tju_tcp;
typedef struct {
    uint32_t        seq;
    int             len;
    int             retrans;      // 该段是否被重传过(Karn 用)
    struct timeval  send_time;
} inflight_seg_t;
// TCP 发送窗口
// 注释的内容如果想用就可以用 不想用就删掉 仅仅提供思路和灵感
typedef struct {
    char     buf[SNDBUF_SIZE];   // 环形发送缓冲，索引 = seq % SNDBUF_SIZE
    uint32_t base;               // 最老未确认字节 seq
    uint32_t nextseq;            // 下一个待发送字节 seq
    uint32_t end;                // 已缓冲数据的末尾 seq
    uint32_t wnd;                // 当前发送窗口(字节)
    uint32_t peer_wnd;           // 对端通告窗口

    int      dup_ack;            // 连续重复 ACK 计数
    uint32_t last_ack;           // 上次收到的 ack

    // 新增：拥塞控制参数
    uint32_t cwnd;               // 拥塞窗口
    uint32_t ssthresh;           // 慢启动阈值

    // RTT / RTO (RFC793 3.7)
    long     srtt;               // -1 表示还没测到
    long     rttvar;
    long     rto;
    int      retrans;            // 当前 base 段是否被重传过(Karn 用)
    struct timeval seg_send_time;// base 段最近一次(首次)发送时间
    inflight_seg_t inflight[MAX_INFLIGHT];
    int n_inflight;
    int      in_fast_recovery;
    uint32_t recover_seq;        // NewReno: 进入恢复时的 nextseq

    // 零窗口 persist（5.4.4）：对端通告窗口为 0 时，靠探测报文打破死锁
    int             in_persist;      // 是否处于零窗口探测状态
    long            persist_backoff; // 当前探测间隔(us)，每次翻倍
    struct timeval  persist_time;    // 上次发探测(或进入 persist)的时间
    int             in_tlp;          // 本次在途是否已经发过尾段探测（RFC8985 思路）
} sender_window_t;

typedef struct {
    uint32_t expect_seq;         // 期望收到的下一个字节 seq

    struct {                     // 乱序缓存
        uint32_t seq;
        int      len;
        int      valid;
        char     data[MSS];
    } ooo[MAX_OOO];
} receiver_window_t;

// TCP 窗口 每个建立了连接的TCP都包括发送和接受两个窗口
typedef struct {
	sender_window_t* wnd_send;
  	receiver_window_t* wnd_recv;
} window_t;

typedef struct {
	uint32_t ip;
	uint16_t port;
} tju_sock_addr;


// TJU_TCP 结构体 保存TJU_TCP用到的各种数据
typedef struct tju_tcp{
	int state; // TCP的状态

	tju_sock_addr bind_addr; // 存放bind和listen时该socket绑定的IP和端口
	tju_sock_addr established_local_addr; // 存放建立连接后 本机的 IP和端口
	tju_sock_addr established_remote_addr; // 存放建立连接后 连接对方的 IP和端口

	pthread_mutex_t send_lock; // 发送数据锁
	char* sending_buf; // 发送数据缓存区
	int sending_len; // 发送数据缓存长度

	pthread_mutex_t recv_lock; // 接收数据锁
	char* received_buf; // 接收数据缓存区
	int received_len; // 接收数据缓存长度
    int received_cap;

	pthread_cond_t wait_cond; // 可以被用来唤醒recv函数调用时等待的线程
	    pthread_cond_t accept_cond; // 服务端 accept 等待新连接完成的条件变量

	    window_t window; // 发送和接受窗口

	    uint32_t seq;                 // 我的当前序号
	    uint32_t ack;                 // 可选：期望的对端序号
	    struct tju_tcp* listen_sock;      // ★ 服务端 new_conn 回指父监听 socket
	    struct tju_tcp* completed_conn;   // 服务端：已完成三次握手的连接，供 accept 使用

	/* 新增：用于可靠传输和重传控制 */
    uint32_t last_sent_seq;       // 最后一次发送的包的起始序列号
    uint32_t last_sent_ack;       // 最后一次发送的包的 ACK 号
    uint16_t last_sent_flags;     // 最后一次发送的标志位 (SYN, ACK, etc.)
    uint16_t last_sent_src_port;  // 源端口
    uint16_t last_sent_dst_port;  // 目的端口
    
    int retransmit_count;         // 当前未确认包的重传次数
    int max_retransmit;           // 最大重传次数
    struct timeval last_send_time; // 最后一次发送未确认数据的时间
    
    // 用于区分当前是在等待连接建立 (SYN/ACK) 还是等待数据 ACK
    // 0: 无等待, 1: 等待连接建立, 2: 等待数据 ACK
    int wait_type; 
	pthread_cond_t send_cond;

} tju_tcp_t;

#endif