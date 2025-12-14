//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#ifndef __IKCP_H__
#define __IKCP_H__

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>


//=====================================================================
// 32BIT INTEGER DEFINITION 
// 32位int和uint的定义
//=====================================================================
#ifndef __INTEGER_32_BITS__
#define __INTEGER_32_BITS__
#if defined(_WIN64) || defined(WIN64) || defined(__amd64__) || \
	defined(__x86_64) || defined(__x86_64__) || defined(_M_IA64) || \
	defined(_M_AMD64)
	typedef unsigned int ISTDUINT32;
	typedef int ISTDINT32;
#elif defined(_WIN32) || defined(WIN32) || defined(__i386__) || \
	defined(__i386) || defined(_M_X86)
	typedef unsigned long ISTDUINT32;
	typedef long ISTDINT32;
#elif defined(__MACOS__)
	typedef UInt32 ISTDUINT32;
	typedef SInt32 ISTDINT32;
#elif defined(__APPLE__) && defined(__MACH__)
	#include <sys/types.h>
	typedef u_int32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#elif defined(__BEOS__)
	#include <sys/inttypes.h>
	typedef u_int32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#elif (defined(_MSC_VER) || defined(__BORLANDC__)) && (!defined(__MSDOS__))
	typedef unsigned __int32 ISTDUINT32;
	typedef __int32 ISTDINT32;
#elif defined(__GNUC__)
	#include <stdint.h>
	typedef uint32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#else 
	typedef unsigned long ISTDUINT32; 
	typedef long ISTDINT32;
#endif
#endif


//=====================================================================
// Integer Definition
// 各种整数的定义
//=====================================================================
#ifndef __IINT8_DEFINED
#define __IINT8_DEFINED
typedef char IINT8;
#endif

#ifndef __IUINT8_DEFINED
#define __IUINT8_DEFINED
typedef unsigned char IUINT8;
#endif

#ifndef __IUINT16_DEFINED
#define __IUINT16_DEFINED
typedef unsigned short IUINT16;
#endif

#ifndef __IINT16_DEFINED
#define __IINT16_DEFINED
typedef short IINT16;
#endif

#ifndef __IINT32_DEFINED
#define __IINT32_DEFINED
typedef ISTDINT32 IINT32;
#endif

#ifndef __IUINT32_DEFINED
#define __IUINT32_DEFINED
typedef ISTDUINT32 IUINT32;
#endif

#ifndef __IINT64_DEFINED
#define __IINT64_DEFINED
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef __int64 IINT64;
#else
typedef long long IINT64;
#endif
#endif

#ifndef __IUINT64_DEFINED
#define __IUINT64_DEFINED
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef unsigned __int64 IUINT64;
#else
typedef unsigned long long IUINT64;
#endif
#endif

#ifndef INLINE
#if defined(__GNUC__)

#if (__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1))
#define INLINE         __inline__ __attribute__((always_inline))
#else
#define INLINE         __inline__
#endif

#elif (defined(_MSC_VER) || defined(__BORLANDC__) || defined(__WATCOMC__))
#define INLINE __inline
#else
#define INLINE 
#endif
#endif

#if (!defined(__cplusplus)) && (!defined(inline))
#define inline INLINE
#endif


//=====================================================================
// QUEUE DEFINITION
// 队列的定义                                                  
//=====================================================================
#ifndef __IQUEUE_DEF__
#define __IQUEUE_DEF__
// 队列的定义，类似一个双向链表
struct IQUEUEHEAD {
	struct IQUEUEHEAD *next, *prev;
};

typedef struct IQUEUEHEAD iqueue_head;


//---------------------------------------------------------------------
// queue init                                                         
//---------------------------------------------------------------------
#define IQUEUE_HEAD_INIT(name) { &(name), &(name) }
#define IQUEUE_HEAD(name) \
	struct IQUEUEHEAD name = IQUEUE_HEAD_INIT(name)

// 初始化队列，将next和prev都指向自己
#define IQUEUE_INIT(ptr) ( \
	(ptr)->next = (ptr), (ptr)->prev = (ptr))

// 获取成员在结构体中的偏移
#define IOFFSETOF(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

// 将指向结构体中成员的指针还原成执行结构体的指针
#define ICONTAINEROF(ptr, type, member) ( \
		(type*)( ((char*)((type*)ptr)) - IOFFSETOF(type, member)) )

// 将队列节点指针转换成结构体指针
#define IQUEUE_ENTRY(ptr, type, member) ICONTAINEROF(ptr, type, member)


//---------------------------------------------------------------------
// queue operation    
// 队列操作，这个队列有一个头结点head用于管理队列，并且使用双向链表构造的是一个环状队列              
//---------------------------------------------------------------------
// 在队列头增加节点
#define IQUEUE_ADD(node, head) ( \
	(node)->prev = (head), (node)->next = (head)->next, \
	(head)->next->prev = (node), (head)->next = (node))

// 在队列尾增加节点
#define IQUEUE_ADD_TAIL(node, head) ( \
	(node)->prev = (head)->prev, (node)->next = (head), \
	(head)->prev->next = (node), (head)->prev = (node))

// 删除p和n之间的节点
#define IQUEUE_DEL_BETWEEN(p, n) ((n)->prev = (p), (p)->next = (n))

// 删除节点
#define IQUEUE_DEL(entry) (\
	(entry)->next->prev = (entry)->prev, \
	(entry)->prev->next = (entry)->next, \
	(entry)->next = 0, (entry)->prev = 0)

// 删除节点，并且将删除的节点初始化
#define IQUEUE_DEL_INIT(entry) do { \
	IQUEUE_DEL(entry); IQUEUE_INIT(entry); } while (0)

// 队列是否为空
#define IQUEUE_IS_EMPTY(entry) ((entry) == (entry)->next)

#define iqueue_init		IQUEUE_INIT
#define iqueue_entry	IQUEUE_ENTRY
#define iqueue_add		IQUEUE_ADD
#define iqueue_add_tail	IQUEUE_ADD_TAIL
#define iqueue_del		IQUEUE_DEL
#define iqueue_del_init	IQUEUE_DEL_INIT
#define iqueue_is_empty IQUEUE_IS_EMPTY

#define IQUEUE_FOREACH(iterator, head, TYPE, MEMBER) \
	for ((iterator) = iqueue_entry((head)->next, TYPE, MEMBER); \
		&((iterator)->MEMBER) != (head); \
		(iterator) = iqueue_entry((iterator)->MEMBER.next, TYPE, MEMBER))

#define iqueue_foreach(iterator, head, TYPE, MEMBER) \
	IQUEUE_FOREACH(iterator, head, TYPE, MEMBER)

// 遍历队列节点
#define iqueue_foreach_entry(pos, head) \
	for( (pos) = (head)->next; (pos) != (head) ; (pos) = (pos)->next )
	
// 将队列拆分成两个
#define __iqueue_splice(list, head) do {	\
		iqueue_head *first = (list)->next, *last = (list)->prev; \
		iqueue_head *at = (head)->next; \
		(first)->prev = (head), (head)->next = (first);		\
		(last)->next = (at), (at)->prev = (last); }	while (0)

// 将队列拆分成两个
#define iqueue_splice(list, head) do { \
	if (!iqueue_is_empty(list)) __iqueue_splice(list, head); } while (0)

#define iqueue_splice_init(list, head) do {	\
	iqueue_splice(list, head);	iqueue_init(list); } while (0)


#ifdef _MSC_VER
#pragma warning(disable:4311)
#pragma warning(disable:4312)
#pragma warning(disable:4996)
#endif

#endif


//---------------------------------------------------------------------
// BYTE ORDER & ALIGNMENT
//---------------------------------------------------------------------
#ifndef IWORDS_BIG_ENDIAN
    #ifdef _BIG_ENDIAN_
        #if _BIG_ENDIAN_
            #define IWORDS_BIG_ENDIAN 1
        #endif
    #endif
    #ifndef IWORDS_BIG_ENDIAN
        #if defined(__hppa__) || \
            defined(__m68k__) || defined(mc68000) || defined(_M_M68K) || \
            (defined(__MIPS__) && defined(__MIPSEB__)) || \
            defined(__ppc__) || defined(__POWERPC__) || defined(_M_PPC) || \
            defined(__sparc__) || defined(__powerpc__) || \
            defined(__mc68000__) || defined(__s390x__) || defined(__s390__)
            #define IWORDS_BIG_ENDIAN 1
        #endif
    #endif
    #ifndef IWORDS_BIG_ENDIAN
        #define IWORDS_BIG_ENDIAN  0
    #endif
#endif

#ifndef IWORDS_MUST_ALIGN
	#if defined(__i386__) || defined(__i386) || defined(_i386_)
		#define IWORDS_MUST_ALIGN 0
	#elif defined(_M_IX86) || defined(_X86_) || defined(__x86_64__)
		#define IWORDS_MUST_ALIGN 0
	#elif defined(__amd64) || defined(__amd64__)
		#define IWORDS_MUST_ALIGN 0
	#else
		#define IWORDS_MUST_ALIGN 1
	#endif
#endif


//=====================================================================
// SEGMENT 传输分片
//=====================================================================
struct IKCPSEG
{
	struct IQUEUEHEAD node; 	// 链表节点，用于挂到各种队列中（snd_buf、rcv_buf…）
	IUINT32 conv;				// 会话ID（会话唯一标识）
	IUINT32 cmd;				// KCP命令类型（IKCP_CMD_PUSH / ACK / WASK / WINS）
	IUINT32 frg;				// 分片序号（最后一个分片为0；如果整个消息只有一个分片，也为0）
	IUINT32 wnd;				// 对端剩余窗口大小
	IUINT32 ts;					// 本段发送时的时间戳
	IUINT32 sn;					// 段序号（sequence number）
	IUINT32 una;				// 对端已收到的最小未确认序号
	IUINT32 len;				// 数据长度
	IUINT32 resendts;			// 下一次重传的时间戳（定时器）
	IUINT32 rto;				// 本段的RTO（重传超时）
	IUINT32 fastack;			// 对该段的fastack次数（快速重传相关）
	IUINT32 xmit;				// 本段发送次数（超过一定次数认为链路死亡）
	char data[1];				// 真实数据存放起点（变长，最后一个字段）
};


//---------------------------------------------------------------------
// IKCPCB
//---------------------------------------------------------------------
struct IKCPCB
{
	//conv: 会话号（一个 kcp 对象一个 conv）, mtu: 最大传输单元 (默认 1400), mss: 每段最大分片大小，每段最大分片大小（mtu - overhead），state: 当前状态（0 正常）
	IUINT32 conv, mtu, mss, state;
	// snd_una：最早未确认的发送序号 (unacknowledged)， snd_nxt：下一个待发送的序号， rcv_nxt：下一个期望接收的序号
	IUINT32 snd_una, snd_nxt, rcv_nxt;
	// ts_recent：最近一次收到的对端时间戳，ts_lastack：最近一次ack的时间戳， ssthresh：拥塞控制慢启动门限（默认值较大）
	IUINT32 ts_recent, ts_lastack, ssthresh;
	// rx_rttval: RTT 波动值 (RTTVAR), rx_srtt: 平滑 RTT (SRTT), rx_rto: 当前RTO（动态计算）, rx_minrto: 最小 RTO（默认 100ms，nodelay 时 = 30ms）
	IINT32 rx_rttval, rx_srtt, rx_rto, rx_minrto;
	// snd_wnd: 发送窗口大小（默认 32）, rcv_wnd: 接收窗口大小（默认 128）, rmt_wnd: 对端通告的窗口大小, cwnd: 拥塞窗口大小，prboe： 探测标志（用于询问窗口）
	IUINT32 snd_wnd, rcv_wnd, rmt_wnd, cwnd, probe;
	// current: 当前时间（在 ikcp_update 输入), interval: flush 最小间隔（默认100ms，可通过nodelay设置）,ts_flush: 下次flush的时间点, xmit: 总发送次数统计（全局）
	IUINT32 current, interval, ts_flush, xmit;
	// nrcv_buf：rcv_buf队列长度， nsnd_buf：snd_buf 队列长度
	IUINT32 nrcv_buf, nsnd_buf;
	// nrcv_que： cv_queue 队列长度（完全有序可交付），nsnd_que：snd_queue 队列长度（等待进入发送缓冲区）
	IUINT32 nrcv_que, nsnd_que;
	// nodelay: nodelay 模式（1 = 更低延迟）, updated: 是否已经调用过 update（内部标记）
	IUINT32 nodelay, updated;
	// ts_probe: 窗口探测下次时间, probe_wait: 下次探测等待时间
	IUINT32 ts_probe, probe_wait;
	// dead_link: xmit超过this即认为连接死亡, incr: cwnd增长值（拥塞控制）
	IUINT32 dead_link, incr;
	// 待发送队列
	struct IQUEUEHEAD snd_queue;
	// 可交付队列
	struct IQUEUEHEAD rcv_queue;
	// 已发送但未ack的发送缓存
	struct IQUEUEHEAD snd_buf;
	// 收到但乱序的段
	struct IQUEUEHEAD rcv_buf;
	//  ack列表（ts + sn）
	IUINT32 *acklist;
	// ack数目
	IUINT32 ackcount;
	// ack列表的容量
	IUINT32 ackblock;

	// 用户传入的参数
	void *user;
	// 发送缓存（用于组包）
	char *buffer;
	// 快速重传阈值
	int fastresend;
	// fastack上限（默认 5）
	int fastlimit;
	// nocwnd: 禁用拥塞控制模式 , stream: 流模式（表现像 TCP，合并分片）
	int nocwnd, stream;
	// 日志配置
	int logmask;
	// 底层 UDP 发送函数
	int (*output)(const char *buf, int len, struct IKCPCB *kcp, void *user);
	// 日志回调（可忽略）
	void (*writelog)(const char *log, struct IKCPCB *kcp, void *user);
};


typedef struct IKCPCB ikcpcb;

#define IKCP_LOG_OUTPUT			1
#define IKCP_LOG_INPUT			2
#define IKCP_LOG_SEND			4
#define IKCP_LOG_RECV			8
#define IKCP_LOG_IN_DATA		16
#define IKCP_LOG_IN_ACK			32
#define IKCP_LOG_IN_PROBE		64
#define IKCP_LOG_IN_WINS		128
#define IKCP_LOG_OUT_DATA		256
#define IKCP_LOG_OUT_ACK		512
#define IKCP_LOG_OUT_PROBE		1024
#define IKCP_LOG_OUT_WINS		2048

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------
// interface
//---------------------------------------------------------------------

// create a new kcp control object, 'conv' must equal in two endpoint
// from the same connection. 'user' will be passed to the output callback
// output callback can be setup like this: 'kcp->output = my_udp_output'
/* 创建一个 kcp 控制块
 * conv: 会话号（双端需一致）
 * user: 用户指针，会在output回调时回传（比如 socket）
 */
ikcpcb* ikcp_create(IUINT32 conv, void *user);

// release kcp control object
/* 释放 kcp 控制块 */
void ikcp_release(ikcpcb *kcp);

// set output callback, which will be invoked by kcp
/* 设置输出回调（更方便） */
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len, 
	ikcpcb *kcp, void *user));

// user/upper level recv: returns size, returns below zero for EAGAIN
// 用户层/上层的接收，返回大小，如果需要再一次接收会返回小于0的值
int ikcp_recv(ikcpcb *kcp, char *buffer, int len);

// user/upper level send, returns below zero for error
// 用户层/上层的发送，如果出错，返回值小于0
int ikcp_send(ikcpcb *kcp, const char *buffer, int len);

// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec. 
// 更新状态（每隔 10 毫秒到 100 毫秒重复调用），或者您可以询问 ikcp_check 何时再次调用它（无需调用ikcp_input/_send）。'current' - 当前时间戳（毫秒）。
void ikcp_update(ikcpcb *kcp, IUINT32 current);

// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current);

// when you received a low level packet (eg. UDP packet), call it
/* 输入底层 UDP 收到的数据（必须在收到 UDP 包时调用）：
 * data: UDP数据指针
 * size: 大小
 * 返回值: 0 = 成功（常用）
 *
 * 说明: 本函数会解析KCP头、生成ACK、填充rcv_buf/rcv_queue。
 */
int ikcp_input(ikcpcb *kcp, const char *data, long size);

// flush pending data
/* 强制冲刷发送队列（立即组包并通过output发出） */
void ikcp_flush(ikcpcb *kcp);

// check the size of next message in the recv queue
int ikcp_peeksize(const ikcpcb *kcp);

// change MTU size, default is 1400
// 修改MTU的大小，默认为1400
int ikcp_setmtu(ikcpcb *kcp, int mtu);

// set maximum window size: sndwnd=32, rcvwnd=32 by default
// 设置最大的窗口大小：默认是发送窗口：32，接收窗口：32
int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd);

// get how many packet is waiting to be sent
// 得到多少个包等待发送
int ikcp_waitsnd(const ikcpcb *kcp);

// fastest: ikcp_nodelay(kcp, 1, 20, 2, 1)
// nodelay: 0:disable(default), 1:enable
// interval: internal update timer interval in millisec, default is 100ms 
// resend: 0:disable fast resend(default), 1:enable fast resend
// nc: 0:normal congestion control(default), 1:disable congestion control
/* 快速模式：ikcp_nodelay(kcp, 1, 20, 2, 1)
 * nodelya：0：禁用，1：启用
 * interval：内部更新的时间间隔，以毫秒为单位，默认是100毫秒
*/
int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc);


void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...);

// setup allocator
// 设置分配器
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*));

// read conv
// 读取conv
IUINT32 ikcp_getconv(const void *ptr);


#ifdef __cplusplus
}
#endif

#endif


