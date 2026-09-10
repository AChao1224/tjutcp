#include "tju_tcp.h"

/*
创建 TCP socket 
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t* tju_socket(){
    tju_tcp_t* sock = (tju_tcp_t*)malloc(sizeof(tju_tcp_t));
    sock->state = CLOSED;
    
    pthread_mutex_init(&(sock->send_lock), NULL);
    sock->sending_buf = NULL;
    sock->sending_len = 0;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    sock->received_buf = NULL;
    sock->received_len = 0;
    
    if(pthread_cond_init(&sock->wait_cond, NULL) != 0){
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    sock->window.wnd_send = NULL;
    sock->window.wnd_recv = NULL;

    return sock;
}

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr){
    sock->bind_addr = bind_addr;
    return 0;
}

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
注册该socket到内核的监听socket哈希表
*/
int tju_listen(tju_tcp_t* sock){
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    listen_socks[hashval] = sock;
    return 0;
}

/*
接受连接 
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
tju_tcp_t* tju_accept(tju_tcp_t* listen_sock){
    tju_tcp_t* new_conn = (tju_tcp_t*)malloc(sizeof(tju_tcp_t));
    memcpy(new_conn, listen_sock, sizeof(tju_tcp_t));

    tju_sock_addr local_addr, remote_addr;
    /*
     这里涉及到TCP连接的建立
     正常来说应该是收到客户端发来的SYN报文
     从中拿到对端的IP和PORT
     换句话说 下面的处理流程其实不应该放在这里 应该在tju_handle_packet中
    */ 
    remote_addr.ip = inet_network("172.17.0.2");  //具体的IP地址
    remote_addr.port = 5678;  //端口

    local_addr.ip = listen_sock->bind_addr.ip;  //具体的IP地址
    local_addr.port = listen_sock->bind_addr.port;  //端口

    new_conn->established_local_addr = local_addr;
    new_conn->established_remote_addr = remote_addr;

    // 这里应该是经过三次握手后才能修改状态为ESTABLISHED
    new_conn->state = ESTABLISHED;

    // 将新的conn放到内核建立连接的socket哈希表中
    int hashval = cal_hash(local_addr.ip, local_addr.port, remote_addr.ip, remote_addr.port);
    established_socks[hashval] = new_conn;

    // 如果new_conn的创建过程放到了tju_handle_packet中 那么accept怎么拿到这个new_conn呢
    // 在linux中 每个listen socket都维护一个已经完成连接的socket队列
    // 每次调用accept 实际上就是取出这个队列中的一个元素
    // 队列为空,则阻塞 
    return new_conn;
}


/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr){

    sock->established_remote_addr = target_addr;

    tju_sock_addr local_addr;
    local_addr.ip = inet_network("172.17.0.2");
    local_addr.port = 5678; // 连接方进行connect连接的时候 内核中是随机分配一个可用的端口
    sock->established_local_addr = local_addr;

    int hashval = cal_hash(local_addr.ip, local_addr.port, target_addr.ip, target_addr.port);

    sock->state = SYN_SENT;

    sock->seq = 100;

    char* msg = create_packet_buf(
    local_addr.port,     // 源端口：客户端端口
    target_addr.port,    // 目的端口：服务端 1234
    sock->seq,           // 我的初始序号
    0,                   // SYN 阶段 ack 无意义（还没收到对端序号）
    DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
    SYN_FLAG_MASK,       // 标志位带 SYN
    0, 0,
    NULL, 0              // 无数据
    );

    established_socks[hashval] = sock;
    sendToLayer3(msg,DEFAULT_HEADER_LEN);

    while(sock->state != ESTABLISHED){
        pthread_cond_wait(&sock->wait_cond,&sock->send_lock);
    }

    return 0;
}

int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    // 这里当然不能直接简单地调用sendToLayer3
    char* data = malloc(len);
    memcpy(data, buffer, len);

    char* msg;
    uint32_t seq = 464;
    uint16_t plen = DEFAULT_HEADER_LEN + len;

    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, 0, 
              DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, data, len);

    sendToLayer3(msg, plen);
    
    return 0;
}
int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    while(sock->received_len<=0){
        // 阻塞
    }

    while(pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

    int read_len = 0;
    if (sock->received_len >= len){ // 从中读取len长度的数据
        read_len = len;
    }else{
        read_len = sock->received_len; // 读取sock->received_len长度的数据(全读出来)
    }

    memcpy(buffer, sock->received_buf, read_len);

    if(read_len < sock->received_len) { // 还剩下一些
        char* new_buf = malloc(sock->received_len - read_len);
        memcpy(new_buf, sock->received_buf + read_len, sock->received_len - read_len);
        free(sock->received_buf);
        sock->received_len -= read_len;
        sock->received_buf = new_buf;
    }else{
        free(sock->received_buf);
        sock->received_buf = NULL;
        sock->received_len = 0;
    }
    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

    return 0;
}

int tju_handle_packet(tju_tcp_t* sock, char* pkt){
    uint8_t flags = get_flags(pkt);
    //客户端收到SYN-ACK
    if(sock->state == SYN_SENT && (flags & SYN_FLAG_MASK) && (flags & ACK_FLAG_MASK)){
        sock->ack = get_seq(pkt)+1;
    
        char* msg = create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            sock->seq + 1,          // x + 1
            sock->ack,              // y + 1
            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
            ACK_FLAG_MASK,
            0, 0, NULL, 0
        );
        sendToLayer3(msg, DEFAULT_HEADER_LEN);
        pthread_mutex_lock(&sock->send_lock);
        sock->state = ESTABLISHED;
        pthread_cond_signal(&sock->wait_cond);
        pthread_mutex_unlock(&sock->send_lock);
        return 0;
    }
    if (sock->state == LISTEN && (flags & SYN_FLAG_MASK)) {

        tju_tcp_t* new_conn = tju_socket();

        // 2. 四元组地址
        new_conn->established_local_addr  = sock->bind_addr;
        new_conn->established_remote_addr.ip   = inet_network("172.17.0.2");
        new_conn->established_remote_addr.port = get_src(pkt);

        // 3. 状态与序号
        new_conn->state = SYN_RECV;
        new_conn->seq   = 200;
        new_conn->ack   = get_seq(pkt) + 1;
        new_conn->listen_sock = sock;

        // 4. 登记到 established_socks（否则客户端第三次 ACK 回来时找不到）
        int hashval = cal_hash(
            new_conn->established_local_addr.ip,
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.ip,
            new_conn->established_remote_addr.port
        );
        established_socks[hashval] = new_conn;

        // 5. 回 SYN-ACK：SYN 和 ACK 两位同时点亮
        char* msg = create_packet_buf(
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.port,
            new_conn->seq,
            new_conn->ack,
            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
            SYN_FLAG_MASK | ACK_FLAG_MASK, 
            0, 0, NULL, 0
        );
        sendToLayer3(msg, DEFAULT_HEADER_LEN);

        return 0;
    }
    if (sock->state == SYN_RECV && (flags & ACK_FLAG_MASK)) {
       pthread_mutex_lock(&sock->listen_sock->send_lock);
       sock->state = ESTABLISHED;
       sock->listen_sock->completed_conn = sock;
       pthread_cond_signal(&sock->listen_sock->wait_cond);
       pthread_mutex_unlock(&sock->listen_sock->send_lock);
       return 0;
    }    
    return 0;

}

int tju_close (tju_tcp_t* sock){
    return 0;
}