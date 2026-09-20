#ifndef _TRACE_H_
#define _TRACE_H_

#include <stdint.h>

/*
 * 事件 trace 模块（格式遵循《Trace文件记录说明》）
 *
 * 设计要点：
 *   1. 协议线程只做"格式化 + memcpy 进内存环形队列"，这条路径上绝不做文件 I/O；
 *      落盘由独立的写线程批量 write() 完成，写文件时不持有队列锁。
 *   2. 队列满时丢弃该行并计数，绝不阻塞协议线程（宁可丢日志，不能拖慢协议）。
 *   3. 编译时加 -DTRACE_DISABLE 可整体关闭（做 A/B 对照实验，验证 trace 不影响性能）。
 *
 * 日志文件（每次启动覆盖）：
 *   server 端 -> /vagrant/tju_tcp/test/server.event.trace
 *   client 端 -> /vagrant/tju_tcp/test/client.event.trace
 *   目录不可写时退化为当前工作目录（便于在宿主机本地调试）。
 *
 * 行格式：[utctimestamp] [event] [info]
 *   utctimestamp : 13 位整数，UTC 时间戳，单位微秒
 *   event        : SEND / RECV / CWND / RWND / SWND / RTTS / DELV
 *   size 类字段单位都是 byte（= 段数 * 1375）
 */

void trace_init(void);      /* 进程启动时调用一次：选文件名、O_TRUNC 覆盖、起写线程 */
void trace_shutdown(void);  /* 正常退出前调用：写完剩余记录并关闭文件 */

/* SEND / RECV：发送或收到一个 packet 时记录，length 是 payload 长度（字节） */
void trace_send(uint32_t seq, uint32_t ack, int flag, int length);
void trace_recv(uint32_t seq, uint32_t ack, int flag, int length);

/* CWND：拥塞窗口发生变化时记录。type: 0 慢启动 1 拥塞避免 2 快速重传 3 超时 */
void trace_cwnd(int type, uint32_t size, uint32_t ssthresh);

/* RWND：接收方可用缓冲区大小（本端将要通告的窗口）发生变化时记录 */
void trace_rwnd(uint32_t size);

/* SWND：发送窗口（实际发送上限 min(cwnd, rwnd)）发生变化时记录 */
void trace_swnd(uint32_t size);

/* RTTS：RTT 估计值发生变化时记录，四个参数单位都是毫秒 */
void trace_rtts(double sample_ms, double est_ms, double dev_ms, double timeout_ms);

/* DELV：接收窗口把按序数据交付给接收缓冲区时记录 */
void trace_delv(uint32_t seq, int size);

#endif
