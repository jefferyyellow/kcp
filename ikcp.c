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
#include "ikcp.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#define IKCP_FASTACK_CONSERVE

//=====================================================================
// KCP BASIC
//=====================================================================
const IUINT32 IKCP_RTO_NDL = 30;		// no delay min rto
const IUINT32 IKCP_RTO_MIN = 100;		// normal min rto
const IUINT32 IKCP_RTO_DEF = 200;
const IUINT32 IKCP_RTO_MAX = 60000;
const IUINT32 IKCP_CMD_PUSH = 81;		// cmd: push data ：数据
const IUINT32 IKCP_CMD_ACK  = 82;		// cmd: ack ：确认
const IUINT32 IKCP_CMD_WASK = 83;		// cmd: window probe (ask) 窗口探测
const IUINT32 IKCP_CMD_WINS = 84;		// cmd: window size (tell) 窗口大小
const IUINT32 IKCP_ASK_SEND = 1;		// need to send IKCP_CMD_WASK
const IUINT32 IKCP_ASK_TELL = 2;		// need to send IKCP_CMD_WINS
const IUINT32 IKCP_WND_SND = 32;
const IUINT32 IKCP_WND_RCV = 128;       // must >= max fragment size
const IUINT32 IKCP_MTU_DEF = 1400;
const IUINT32 IKCP_ACK_FAST	= 3;
const IUINT32 IKCP_INTERVAL	= 100;
const IUINT32 IKCP_OVERHEAD = 24;
const IUINT32 IKCP_DEADLINK = 20;
const IUINT32 IKCP_THRESH_INIT = 2;
const IUINT32 IKCP_THRESH_MIN = 2;
const IUINT32 IKCP_PROBE_INIT = 7000;		// 7 secs to probe window size
const IUINT32 IKCP_PROBE_LIMIT = 120000;	// up to 120 secs to probe window
const IUINT32 IKCP_FASTACK_LIMIT = 5;		// max times to trigger fastack


//---------------------------------------------------------------------
// encode / decode 编码和解码
//---------------------------------------------------------------------

/* encode 8 bits unsigned int */
static inline char *ikcp_encode8u(char *p, unsigned char c)
{
	*(unsigned char*)p++ = c;
	return p;
}

/* decode 8 bits unsigned int */
static inline const char *ikcp_decode8u(const char *p, unsigned char *c)
{
	*c = *(unsigned char*)p++;
	return p;
}

/* encode 16 bits unsigned int (lsb) */
static inline char *ikcp_encode16u(char *p, unsigned short w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (w & 255);
	*(unsigned char*)(p + 1) = (w >> 8);
#else
	memcpy(p, &w, 2);
#endif
	p += 2;
	return p;
}

/* decode 16 bits unsigned int (lsb) */
static inline const char *ikcp_decode16u(const char *p, unsigned short *w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*w = *(const unsigned char*)(p + 1);
	*w = *(const unsigned char*)(p + 0) + (*w << 8);
#else
	memcpy(w, p, 2);
#endif
	p += 2;
	return p;
}

/* encode 32 bits unsigned int (lsb) */
static inline char *ikcp_encode32u(char *p, IUINT32 l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (unsigned char)((l >>  0) & 0xff);
	*(unsigned char*)(p + 1) = (unsigned char)((l >>  8) & 0xff);
	*(unsigned char*)(p + 2) = (unsigned char)((l >> 16) & 0xff);
	*(unsigned char*)(p + 3) = (unsigned char)((l >> 24) & 0xff);
#else
	memcpy(p, &l, 4);
#endif
	p += 4;
	return p;
}

/* decode 32 bits unsigned int (lsb) */
static inline const char *ikcp_decode32u(const char *p, IUINT32 *l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*l = *(const unsigned char*)(p + 3);
	*l = *(const unsigned char*)(p + 2) + (*l << 8);
	*l = *(const unsigned char*)(p + 1) + (*l << 8);
	*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else 
	memcpy(l, p, 4);
#endif
	p += 4;
	return p;
}

// 取最小值
static inline IUINT32 _imin_(IUINT32 a, IUINT32 b) {
	return a <= b ? a : b;
}

// 取最大值
static inline IUINT32 _imax_(IUINT32 a, IUINT32 b) {
	return a >= b ? a : b;
}

static inline IUINT32 _ibound_(IUINT32 lower, IUINT32 middle, IUINT32 upper) 
{
	return _imin_(_imax_(lower, middle), upper);
}

static inline long _itimediff(IUINT32 later, IUINT32 earlier) 
{
	return ((IINT32)(later - earlier));
}

//---------------------------------------------------------------------
// manage segment
//---------------------------------------------------------------------
typedef struct IKCPSEG IKCPSEG;

static void* (*ikcp_malloc_hook)(size_t) = NULL;
static void (*ikcp_free_hook)(void *) = NULL;

// internal malloc
static void* ikcp_malloc(size_t size) {
	if (ikcp_malloc_hook) 
		return ikcp_malloc_hook(size);
	return malloc(size);
}

// internal free
static void ikcp_free(void *ptr) {
	if (ikcp_free_hook) {
		ikcp_free_hook(ptr);
	}	else {
		free(ptr);
	}
}

// redefine allocator
// 重定向分配和释放函数
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*))
{
	ikcp_malloc_hook = new_malloc;
	ikcp_free_hook = new_free;
}

// allocate a new kcp segment
// 分配新的片
static IKCPSEG* ikcp_segment_new(ikcpcb *kcp, int size)
{
	return (IKCPSEG*)ikcp_malloc(sizeof(IKCPSEG) + size);
}

// delete a segment
// 删除新的片
static void ikcp_segment_delete(ikcpcb *kcp, IKCPSEG *seg)
{
	ikcp_free(seg);
}

// write log
// 写入日志
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...)
{
	char buffer[1024];
	va_list argptr;
	if ((mask & kcp->logmask) == 0 || kcp->writelog == 0) return;
	va_start(argptr, fmt);
	vsprintf(buffer, fmt, argptr);
	va_end(argptr);
	kcp->writelog(buffer, kcp, kcp->user);
}

// check log mask
// 检查日志掩码
static int ikcp_canlog(const ikcpcb *kcp, int mask)
{
	if ((mask & kcp->logmask) == 0 || kcp->writelog == NULL) return 0;
	return 1;
}

// output segment
// 发送分片
static int ikcp_output(ikcpcb *kcp, const void *data, int size)
{
	assert(kcp);
	assert(kcp->output);
	if (ikcp_canlog(kcp, IKCP_LOG_OUTPUT)) {
		ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size);
	}
	if (size == 0) return 0;
	return kcp->output((const char*)data, size, kcp, kcp->user);
}

// output queue
// 打印整个队列
void ikcp_qprint(const char *name, const struct IQUEUEHEAD *head)
{
#if 0
	const struct IQUEUEHEAD *p;
	printf("<%s>: [", name);
	for (p = head->next; p != head; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		printf("(%lu %d)", (unsigned long)seg->sn, (int)(seg->ts % 10000));
		if (p->next != head) printf(",");
	}
	printf("]\n");
#endif
}


//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
ikcpcb* ikcp_create(IUINT32 conv, void *user)
{
	ikcpcb *kcp = (ikcpcb*)ikcp_malloc(sizeof(struct IKCPCB));
	if (kcp == NULL) return NULL;
	kcp->conv = conv;
	kcp->user = user;
	kcp->snd_una = 0;
	kcp->snd_nxt = 0;
	kcp->rcv_nxt = 0;
	kcp->ts_recent = 0;
	kcp->ts_lastack = 0;
	kcp->ts_probe = 0;
	kcp->probe_wait = 0;
	kcp->snd_wnd = IKCP_WND_SND;
	kcp->rcv_wnd = IKCP_WND_RCV;
	kcp->rmt_wnd = IKCP_WND_RCV;
	kcp->cwnd = 0;
	kcp->incr = 0;
	kcp->probe = 0;
	kcp->mtu = IKCP_MTU_DEF;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	kcp->stream = 0;

	kcp->buffer = (char*)ikcp_malloc((kcp->mtu + IKCP_OVERHEAD) * 3);
	if (kcp->buffer == NULL) {
		ikcp_free(kcp);
		return NULL;
	}

	iqueue_init(&kcp->snd_queue);
	iqueue_init(&kcp->rcv_queue);
	iqueue_init(&kcp->snd_buf);
	iqueue_init(&kcp->rcv_buf);
	kcp->nrcv_buf = 0;
	kcp->nsnd_buf = 0;
	kcp->nrcv_que = 0;
	kcp->nsnd_que = 0;
	kcp->state = 0;
	kcp->acklist = NULL;
	kcp->ackblock = 0;
	kcp->ackcount = 0;
	kcp->rx_srtt = 0;
	kcp->rx_rttval = 0;
	kcp->rx_rto = IKCP_RTO_DEF;
	kcp->rx_minrto = IKCP_RTO_MIN;
	kcp->current = 0;
	kcp->interval = IKCP_INTERVAL;
	kcp->ts_flush = IKCP_INTERVAL;
	kcp->nodelay = 0;
	kcp->updated = 0;
	kcp->logmask = 0;
	kcp->ssthresh = IKCP_THRESH_INIT;
	kcp->fastresend = 0;
	kcp->fastlimit = IKCP_FASTACK_LIMIT;
	kcp->nocwnd = 0;
	kcp->xmit = 0;
	kcp->dead_link = IKCP_DEADLINK;
	kcp->output = NULL;
	kcp->writelog = NULL;

	return kcp;
}


//---------------------------------------------------------------------
// release a new kcpcb
//---------------------------------------------------------------------
void ikcp_release(ikcpcb *kcp)
{
	assert(kcp);
	if (kcp) {
		IKCPSEG *seg;
		while (!iqueue_is_empty(&kcp->snd_buf)) {
			seg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_buf)) {
			seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->snd_queue)) {
			seg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_queue)) {
			seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		if (kcp->buffer) {
			ikcp_free(kcp->buffer);
		}
		if (kcp->acklist) {
			ikcp_free(kcp->acklist);
		}

		kcp->nrcv_buf = 0;
		kcp->nsnd_buf = 0;
		kcp->nrcv_que = 0;
		kcp->nsnd_que = 0;
		kcp->ackcount = 0;
		kcp->buffer = NULL;
		kcp->acklist = NULL;
		ikcp_free(kcp);
	}
}


//---------------------------------------------------------------------
// set output callback, which will be invoked by kcp
// 设置发送的回调，kcp调用的函数
//---------------------------------------------------------------------
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len,
	ikcpcb *kcp, void *user))
{
	kcp->output = output;
}


//---------------------------------------------------------------------
// user/upper level recv: returns size, returns below zero for EAGAIN
// 用户/上层的接收：返回大小，如果返回值小于0，需要再次
//---------------------------------------------------------------------
int ikcp_recv(ikcpcb *kcp, char *buffer, int len)
{
	struct IQUEUEHEAD *p;
	int ispeek = (len < 0)? 1 : 0;
	int peeksize;
	int recover = 0;
	IKCPSEG *seg;
	assert(kcp);
	// 可以交付的队列为0，直接返回-1
	if (iqueue_is_empty(&kcp->rcv_queue))
		return -1;

	if (len < 0) len = -len;
	// 获得数据大小
	peeksize = ikcp_peeksize(kcp);

	// 没有数据
	if (peeksize < 0) 
		return -2;

	// 缓冲区不够长度
	if (peeksize > len) 
		return -3;

	// 接收到的片段队列已经超过接收窗口了
	if (kcp->nrcv_que >= kcp->rcv_wnd)
		recover = 1;

	// merge fragment
	// 合并片段
	for (len = 0, p = kcp->rcv_queue.next; p != &kcp->rcv_queue; ) {
		int fragment;
		seg = iqueue_entry(p, IKCPSEG, node);
		p = p->next;
		// 将接收列表中片段的数据拷进去
		if (buffer) {
			memcpy(buffer, seg->data, seg->len);
			buffer += seg->len;
		}

		len += seg->len;
		fragment = seg->frg;

		if (ikcp_canlog(kcp, IKCP_LOG_RECV)) {
			ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=%lu", (unsigned long)seg->sn);
		}
		// 分片节点从队列中删除
		if (ispeek == 0) {
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
			kcp->nrcv_que--;
		}
		// 包结束了
		if (fragment == 0) 
			break;
	}

	assert(len == peeksize);

	// move available data from rcv_buf -> rcv_queue
	// 从收到，但是乱序的队列中，如果已经有序了，可以加到可以交付队列中
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
		seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
		// 如果是想要接收的片，加入到可交付队列中去
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

	// fast recover
	// 快速恢复
	if (kcp->nrcv_que < kcp->rcv_wnd && recover) {
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		// 准备在ikcp_flush 中向远程发送IKCP_CMD_WINS以告知我的窗口大小
		kcp->probe |= IKCP_ASK_TELL;
	}

	return len;
}


//---------------------------------------------------------------------
// peek data size
// 取数据
//---------------------------------------------------------------------
int ikcp_peeksize(const ikcpcb *kcp)
{
	struct IQUEUEHEAD *p;
	IKCPSEG *seg;
	int length = 0;

	assert(kcp);

	if (iqueue_is_empty(&kcp->rcv_queue)) return -1;

	// 取可交付队列首节点
	seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
	// 如果没有后续的片了，已经完整了，返回大小
	if (seg->frg == 0) return seg->len;

	// 整个包没有收完
	if (kcp->nrcv_que < seg->frg + 1) return -1;

	// 遍历整个交付列表，直到一个完整的包，最后一个分片的frg为0，表示是一个完整的包了
	for (p = kcp->rcv_queue.next; p != &kcp->rcv_queue; p = p->next) {
		seg = iqueue_entry(p, IKCPSEG, node);
		length += seg->len;
		if (seg->frg == 0) break;
	}
	// 返回长度
	return length;
}


//---------------------------------------------------------------------
// user/upper level send, returns below zero for error
// 用户/上层的发送，如果出现错误就返回0
//---------------------------------------------------------------------
int ikcp_send(ikcpcb *kcp, const char *buffer, int len)
{
	IKCPSEG *seg;
	int count, i;
	int sent = 0;

	assert(kcp->mss > 0);
	if (len < 0) return -1;

	// append to previous segment in streaming mode (if possible)
	// 流模式
	if (kcp->stream != 0) {
		// 发送队列不为空
		if (!iqueue_is_empty(&kcp->snd_queue)) {
			// 发送队列末节点
			IKCPSEG *old = iqueue_entry(kcp->snd_queue.prev, IKCPSEG, node);
			// 如果小于最大分片大小
			if (old->len < kcp->mss) {
				int capacity = kcp->mss - old->len;
				int extend = (len < capacity)? len : capacity;
				// 创建一个新的分片
				seg = ikcp_segment_new(kcp, old->len + extend);
				assert(seg);
				if (seg == NULL) {
					return -2;
				}
				// 加到末尾，并且将原来分片的数据拷贝进新的分片
				iqueue_add_tail(&seg->node, &kcp->snd_queue);
				memcpy(seg->data, old->data, old->len);
				// 尾部加上现在的数据
				if (buffer) {
					memcpy(seg->data + old->len, buffer, extend);
					buffer += extend;
				}
				seg->len = old->len + extend;
				seg->frg = 0;
				len -= extend;
				// 删除老的分片节点
				iqueue_del_init(&old->node);
				ikcp_segment_delete(kcp, old);
				sent = extend;
			}
		}
		// 直接加载尾部了
		if (len <= 0) {
			return sent;
		}
	}

	// 计算需要几个分配
	if (len <= (int)kcp->mss) count = 1;
	else count = (len + kcp->mss - 1) / kcp->mss;

	// 如果超过发送窗口
	if (count >= (int)IKCP_WND_RCV) {
		if (kcp->stream != 0 && sent > 0) 
			return sent;
		return -2;
	}

	if (count == 0) count = 1;

	// fragment
	// 分片，加入到发送列表
	for (i = 0; i < count; i++) {
		int size = len > (int)kcp->mss ? (int)kcp->mss : len;
		seg = ikcp_segment_new(kcp, size);
		assert(seg);
		if (seg == NULL) {
			return -2;
		}
		if (buffer && len > 0) {
			memcpy(seg->data, buffer, size);
		}
		seg->len = size;
		seg->frg = (kcp->stream == 0)? (count - i - 1) : 0;
		iqueue_init(&seg->node);
		iqueue_add_tail(&seg->node, &kcp->snd_queue);
		kcp->nsnd_que++;
		if (buffer) {
			buffer += size;
		}
		len -= size;
		sent += size;
	}

	return sent;
}


//---------------------------------------------------------------------
// parse ack
// 更新rtt和rto
//---------------------------------------------------------------------
static void ikcp_update_ack(ikcpcb *kcp, IINT32 rtt)
{
	IINT32 rto = 0;
	// 根据单个包的rtt，计算全局波动的rtt和平滑的rtt
	if (kcp->rx_srtt == 0) {
		kcp->rx_srtt = rtt;
		kcp->rx_rttval = rtt / 2;
	}	else {
		long delta = rtt - kcp->rx_srtt;
		if (delta < 0) delta = -delta;
		kcp->rx_rttval = (3 * kcp->rx_rttval + delta) / 4;
		kcp->rx_srtt = (7 * kcp->rx_srtt + rtt) / 8;
		if (kcp->rx_srtt < 1) kcp->rx_srtt = 1;
	}
	// 计算全局的RTO
	rto = kcp->rx_srtt + _imax_(kcp->interval, 4 * kcp->rx_rttval);
	kcp->rx_rto = _ibound_(kcp->rx_minrto, rto, IKCP_RTO_MAX);
}

// 重置最早未确认的包
static void ikcp_shrink_buf(ikcpcb *kcp)
{
	struct IQUEUEHEAD *p = kcp->snd_buf.next;
	// 如果还有没确认的分片，最早未确认的分片，就是未确认队列首节点的序列号
	if (p != &kcp->snd_buf) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		kcp->snd_una = seg->sn;
	}	else {
		// 如果所有发送的分片都已经确认，那么最早未确认的分片，就是下一次要发的分片
		kcp->snd_una = kcp->snd_nxt;
	}
}

// 分析ack
static void ikcp_parse_ack(ikcpcb *kcp, IUINT32 sn)
{
	struct IQUEUEHEAD *p, *next;
	// 检测序列号的有效性，已经确认过的，或者比没发的序列号还大，都是不可用的序列号
	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
		return;

	// 遍历未确认的队列
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		// 找到了，表示已经确认，将对应的节点删除
		if (sn == seg->sn) {
			iqueue_del(p);
			ikcp_segment_delete(kcp, seg);
			kcp->nsnd_buf--;
			break;
		}
		if (_itimediff(sn, seg->sn) < 0) {
			break;
		}
	}
}

// 将序列号比una小的节点都从未确认列表中删除
static void ikcp_parse_una(ikcpcb *kcp, IUINT32 una)
{
	struct IQUEUEHEAD *p, *next;
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		// 如果序列号小于una，删除
		if (_itimediff(una, seg->sn) > 0) {
			iqueue_del(p);
			ikcp_segment_delete(kcp, seg);
			kcp->nsnd_buf--;
		}	else {
			break;
		}
	}
}

// 快速Ack分析
// ----------------------------------------------------------------------------
// 根据peer传来的ack/sn，统计那些“被跳过的包”
// 用于KCP的fast retransmit 机制（快速重传）
// 
// 原理：
//   如果收到 ACK(sn)，说明 sn 之前的包都已经被 peer 收到了。
//   那么snd_buf里那些序号<sn、但没有被 ack 的包，都被“间接确认”(fast-ack)
//   fastack++ 到一定次数 => 触发快速重传，而不是等超时RTO。
// 
// 触发前提：必须是在snd_una~snd_nxt范围内的sn，
// 否则ack/sn是过期的或非法的。
// ----------------------------------------------------------------------------
static void ikcp_parse_fastack(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	struct IQUEUEHEAD *p, *next;
	// 检测序列号的有效性
	// sn < snd_una 说明已经被确认了，不需要处理
    // sn >= snd_nxt 说明是未来的包，也不能处理
	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
		return;

	// 遍历未确认列表
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (_itimediff(sn, seg->sn) < 0) {
			break;
		}
		else if (sn != seg->sn) {
		#ifndef IKCP_FASTACK_CONSERVE
			seg->fastack++;
		#else
			if (_itimediff(ts, seg->ts) >= 0)
				seg->fastack++;
		#endif
		}
	}
}


//---------------------------------------------------------------------
// ack append
// KCP 的 ACK 不是即时发出的，而是暂存到 acklist，在下一次 ikcp_flush 时一起打包发送。
// 这个函数就是：向acklist追加一个新的 (sn, ts) 对。
//---------------------------------------------------------------------
static void ikcp_ack_push(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	// 新的 ACK 数量 = 当前数 + 1
	IUINT32 newsize = kcp->ackcount + 1;
	IUINT32 *ptr;

	// 如果当前 acklist 空间不足，需要扩容
	if (newsize > kcp->ackblock) {
		IUINT32 *acklist;
		IUINT32 newblock;

		// 以8为起点，每次*2扩容，直到能放下newsize
        // =>确保 amortized 扩容开销低（2 的幂次）
		for (newblock = 8; newblock < newsize; newblock <<= 1);
		// 每个 ack 需要两个整数：sn和ts
		acklist = (IUINT32*)ikcp_malloc(newblock * sizeof(IUINT32) * 2);

		if (acklist == NULL) {
			assert(acklist != NULL);
			abort();
		}

		// 如果旧acklist存在，把旧数据拷贝过来
		if (kcp->acklist != NULL) {
			IUINT32 x;
			for (x = 0; x < kcp->ackcount; x++) {
				acklist[x * 2 + 0] = kcp->acklist[x * 2 + 0];
				acklist[x * 2 + 1] = kcp->acklist[x * 2 + 1];
			}
			ikcp_free(kcp->acklist);
		}
		// 替换成新acklist
		kcp->acklist = acklist;
		kcp->ackblock = newblock;
	}
	// ptr 指向新增的位置：每个 ACK包含sn和ts
	ptr = &kcp->acklist[kcp->ackcount * 2];
	ptr[0] = sn;
	ptr[1] = ts;
	//ACK数量加一
	kcp->ackcount++;
}

// 获取第p个的ack的序列化和时间
static void ikcp_ack_get(const ikcpcb *kcp, int p, IUINT32 *sn, IUINT32 *ts)
{
	if (sn) sn[0] = kcp->acklist[p * 2 + 0];
	if (ts) ts[0] = kcp->acklist[p * 2 + 1];
}


//---------------------------------------------------------------------
// parse data，解析收到的数据片段
//---------------------------------------------------------------------
void ikcp_parse_data(ikcpcb *kcp, IKCPSEG *newseg)
{
	struct IQUEUEHEAD *p, *prev;
	IUINT32 sn = newseg->sn;
	int repeat = 0;
	// 1) 检查 sn 是否落在接收窗口 [rcv_nxt, rcv_nxt + rcv_wnd)
	// 如果 sn >= rcv_nxt + rcv_wnd ：超出窗口（未来的包）
    // 如果 sn <  rcv_nxt         ：已经收到或过期（旧包）
	if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) >= 0 ||
		_itimediff(sn, kcp->rcv_nxt) < 0) {
		// 不可接受的包，直接丢弃
		ikcp_segment_delete(kcp, newseg);
		return;
	}
    // 2) 将newseg插入到rcv_buf，但要保持rcv_buf按sn从大到小排序
    // -------------------------------------------------------------
    // 从 rcv_buf 的尾向头遍历，rcv_buf是乱序接收缓存。
    // 由于尾部是序号最大的，所以从尾遍历更快
	for (p = kcp->rcv_buf.prev; p != &kcp->rcv_buf; p = prev) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		prev = p->prev;
		if (seg->sn == sn) {
			repeat = 1;
			break;
		}
		if (_itimediff(sn, seg->sn) > 0) {
			break;
		}
	}
	// 不是重复的，插入到合适的位置
	if (repeat == 0) {
		iqueue_init(&newseg->node);
		iqueue_add(&newseg->node, p);
		kcp->nrcv_buf++;
	}	else {
		// 重复的分片，直接删除
		ikcp_segment_delete(kcp, newseg);
	}

#if 0
	ikcp_qprint("rcvbuf", &kcp->rcv_buf);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

	// move available data from rcv_buf -> rcv_queue
	// 检查收到但乱序的分片中，是否有可以交付的分片
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
		IKCPSEG *seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
		// 是否是正好有序的包
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
			// 加入到可交付队列中
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

#if 0
	ikcp_qprint("queue", &kcp->rcv_queue);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

#if 1
//	printf("snd(buf=%d, queue=%d)\n", kcp->nsnd_buf, kcp->nsnd_que);
//	printf("rcv(buf=%d, queue=%d)\n", kcp->nrcv_buf, kcp->nrcv_que);
#endif
}


//---------------------------------------------------------------------
// input data
// 处理从底层UDP收到的KCPsegment，将其拆解并更新发送、接收状态。
// 本函数不会直接发送数据，只更新状态，以及将接收到的 PUSH 数据
// 放入rcv_buf/rcv_queue
//---------------------------------------------------------------------
int ikcp_input(ikcpcb *kcp, const char *data, long size)
{
	 // 记录处理之前的最早未确认序号
	IUINT32 prev_una = kcp->snd_una;
	IUINT32 maxack = 0, latest_ts = 0;
	// 是否看到至少一个 ACK
	int flag = 0;

	if (ikcp_canlog(kcp, IKCP_LOG_INPUT)) {
		ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", (int)size);
	}

	if (data == NULL || (int)size < (int)IKCP_OVERHEAD) return -1;

	while (1) {
		IUINT32 ts, sn, len, una, conv;
		IUINT16 wnd;
		IUINT8 cmd, frg;
		IKCPSEG *seg;
		// 小于包头，直接跳出
		if (size < (int)IKCP_OVERHEAD) break;

		// 解析conv
		data = ikcp_decode32u(data, &conv);
		if (conv != kcp->conv) return -1;

		// kcp包头
		// 命令类型：ACK/PUSH/WASK/WINS
		data = ikcp_decode8u(data, &cmd);
		// 分片标记（0 表示最后一个）
		data = ikcp_decode8u(data, &frg);
		// 对端的接收窗口大小 rmt_wnd
		data = ikcp_decode16u(data, &wnd);
		// 对端发送该包的时间戳（用于 RTT）
		data = ikcp_decode32u(data, &ts);
		// 该包的序号
		data = ikcp_decode32u(data, &sn);
		// 对端已收到（未确认序号）
		data = ikcp_decode32u(data, &una);
		// 数据长度（可能为 0）
		data = ikcp_decode32u(data, &len);

		size -= IKCP_OVERHEAD;
		// 分片有问题，直接返回
		if ((long)size < (long)len || (int)len < 0) return -2;
		
		// 过滤非法命令
		if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS) 
			return -3;
		
		// 远端的窗口大小
		kcp->rmt_wnd = wnd;
		// ----------------------------------------------------------
        // UNA 处理：把 snd_buf 中 sn < una 的 segment 标记为确认
        // ----------------------------------------------------------
		ikcp_parse_una(kcp, una);
		// 缩小 snd_buf：删除已经确认的segment
		ikcp_shrink_buf(kcp);
        // ----------------------------------------------------------
        // 处理 ACK segment：这是 KCP 性能关键
        // ---------------------------------------------------------
		if (cmd == IKCP_CMD_ACK) {
			// RTT 更新：只有当前时间 >= ts 才有效
			if (_itimediff(kcp->current, ts) >= 0) {
				ikcp_update_ack(kcp, _itimediff(kcp->current, ts));
			}
			// 标记某个sn已经被确认，从 snd_buf 删除
			ikcp_parse_ack(kcp, sn);
			ikcp_shrink_buf(kcp);

			// 记录最大的 sn 和最新的 ts，用于fastack
			if (flag == 0) {
				flag = 1;
				maxack = sn;
				latest_ts = ts;
			}	else {
				if (_itimediff(sn, maxack) > 0) {
				#ifndef IKCP_FASTACK_CONSERVE
					maxack = sn;
					latest_ts = ts;
				#else
					if (_itimediff(ts, latest_ts) > 0) {
						maxack = sn;
						latest_ts = ts;
					}
				#endif
				}
			}
			// 在日志中打印 ack 信息
			if (ikcp_canlog(kcp, IKCP_LOG_IN_ACK)) {
				ikcp_log(kcp, IKCP_LOG_IN_ACK, 
					"input ack: sn=%lu rtt=%ld rto=%ld", (unsigned long)sn, 
					(long)_itimediff(kcp->current, ts),
					(long)kcp->rx_rto);
			}
		}
		// ----------------------------------------------------------
        // 处理 PUSH segment（带数据的 segment）
        // ----------------------------------------------------------
		else if (cmd == IKCP_CMD_PUSH) {
			if (ikcp_canlog(kcp, IKCP_LOG_IN_DATA)) {
				ikcp_log(kcp, IKCP_LOG_IN_DATA, 
					"input psh: sn=%lu ts=%lu", (unsigned long)sn, (unsigned long)ts);
			}
			 // 只要在接收窗口内，都要ACK
			if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) < 0) {
				// 加入到ack列表
				ikcp_ack_push(kcp, sn, ts);
				if (_itimediff(sn, kcp->rcv_nxt) >= 0) {
					seg = ikcp_segment_new(kcp, len);
					seg->conv = conv;
					seg->cmd = cmd;
					seg->frg = frg;
					seg->wnd = wnd;
					seg->ts = ts;
					seg->sn = sn;
					seg->una = una;
					seg->len = len;

					if (len > 0) {
						memcpy(seg->data, data, len);
					}
					// 解析新的数据分片
					ikcp_parse_data(kcp, seg);
				}
			}
		}
		// ----------------------------------------------------------
        // IKCP_CMD_WASK：对端想知道窗口大小 → 回答 WINS
        // ----------------------------------------------------------
		else if (cmd == IKCP_CMD_WASK) {
			// ready to send back IKCP_CMD_WINS in ikcp_flush
			// tell remote my window size
			// flush 时发送 WINS大小
			kcp->probe |= IKCP_ASK_TELL;
			if (ikcp_canlog(kcp, IKCP_LOG_IN_PROBE)) {
				ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe");
			}
		}
		// ----------------------------------------------------------
        // IKCP_CMD_WINS：表示对端报告了它的窗口大小（已读）
        // ----------------------------------------------------------
		else if (cmd == IKCP_CMD_WINS) {
			// do nothing
			if (ikcp_canlog(kcp, IKCP_LOG_IN_WINS)) {
				ikcp_log(kcp, IKCP_LOG_IN_WINS,
					"input wins: %lu", (unsigned long)(wnd));
			}
		}
		else {
			return -3;
		}
 		
		// 移动data到payload之后，继续解析下一段KCP segment
		data += len;
		size -= len;
	}

	// --------------------------------------------------------------
    // fastack 处理：使用最大 ack sn 和最新 ts 更新 fastack
    // --------------------------------------------------------------
	if (flag != 0) {
		ikcp_parse_fastack(kcp, maxack, latest_ts);
	}

	// --------------------------------------------------------------
    // 拥塞控制（类似 TCP，但更简单）
    // --------------------------------------------------------------
    // 如果 snd_una 增大，说明发送的数据得到确认 → 网络健康
	if (_itimediff(kcp->snd_una, prev_una) > 0) {
		if (kcp->cwnd < kcp->rmt_wnd) {
			IUINT32 mss = kcp->mss;
			// 1. 慢启动阶段(slow start)
			if (kcp->cwnd < kcp->ssthresh) {
				kcp->cwnd++;
				kcp->incr += mss;
			}	
			 // 2. 拥塞避免阶段
			else {
				if (kcp->incr < mss) kcp->incr = mss;
				// AIMD：增量 = mss^2 / incr
				kcp->incr += (mss * mss) / kcp->incr + (mss / 16);
				if ((kcp->cwnd + 1) * mss <= kcp->incr) {
				#if 1
					kcp->cwnd = (kcp->incr + mss - 1) / ((mss > 0)? mss : 1);
				#else
					kcp->cwnd++;
				#endif
				}
			}
			if (kcp->cwnd > kcp->rmt_wnd) {
				kcp->cwnd = kcp->rmt_wnd;
				kcp->incr = kcp->rmt_wnd * mss;
			}
		}
	}

	return 0;
}


//---------------------------------------------------------------------
// ikcp_encode_seg
// 编码分片
//---------------------------------------------------------------------
static char *ikcp_encode_seg(char *ptr, const IKCPSEG *seg)
{
	ptr = ikcp_encode32u(ptr, seg->conv);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->cmd);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->frg);
	ptr = ikcp_encode16u(ptr, (IUINT16)seg->wnd);
	ptr = ikcp_encode32u(ptr, seg->ts);
	ptr = ikcp_encode32u(ptr, seg->sn);
	ptr = ikcp_encode32u(ptr, seg->una);
	ptr = ikcp_encode32u(ptr, seg->len);
	return ptr;
}

// 接受窗口的剩余
static int ikcp_wnd_unused(const ikcpcb *kcp)
{
	if (kcp->nrcv_que < kcp->rcv_wnd) {
		return kcp->rcv_wnd - kcp->nrcv_que;
	}
	return 0;
}


//---------------------------------------------------------------------
// ikcp_flush
// 它由ikcp_update调用，负责执行所有与数据发送、重传、窗口管理、拥塞控制相关的逻辑。可以将其理解为KCP的数据包发送引擎
//---------------------------------------------------------------------
void ikcp_flush(ikcpcb *kcp)
{
	IUINT32 current = kcp->current;
	// 发送缓冲区，用于暂存待发送的UDP包
	char *buffer = kcp->buffer;
	char *ptr = buffer;
	int count, size, i;
	// resent: 快速重传阈值；cwnd: 拥塞窗口
	IUINT32 resent, cwnd;
	// 最小RTO延迟，用于nodelay模式
	IUINT32 rtomin;
	struct IQUEUEHEAD *p;
	// 标记是否发生了快速重传
	int change = 0;
	// 标记是否发生了超时重传
	int lost = 0;
	// 临时 KCP 包结构体
	IKCPSEG seg;

	// 'ikcp_update' haven't been called. 
	// 检查 ikcp_update 是否已经调用过，确保 kcp 时间戳已初始化。
	if (kcp->updated == 0) return;

	// --- 1. 初始化 KCP 包头结构 (seg) ---
    // 这个seg结构体将用于发送ACK和窗口探测命令
	seg.conv = kcp->conv;
	// 默认命令：ACK
	seg.cmd = IKCP_CMD_ACK;
	seg.frg = 0;
	// 本地接收窗口的可用大小
	seg.wnd = ikcp_wnd_unused(kcp);
	// 下一个期望接收的序号（告诉对方哪些包已收到连续）
	seg.una = kcp->rcv_nxt;
	seg.len = 0;
	seg.sn = 0;
	seg.ts = 0;

	// flush acknowledges
	// --- 2. 刷新待发送的 ACK 列表 (Flush Acknowledges) ---
	count = kcp->ackcount;
	for (i = 0; i < count; i++) {
		size = (int)(ptr - buffer);
		// 检查当前缓冲区是否已满（MTU 限制）
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		// 从ACK列表中获取序号 (sn) 和时间戳 (ts)
		ikcp_ack_get(kcp, i, &seg.sn, &seg.ts);
		// 将 ACK 包编码到缓冲区中
		ptr = ikcp_encode_seg(ptr, &seg);
	}
	
	// 清空 ACK 列表
	kcp->ackcount = 0;

	// probe window size (if remote window size equals zero)
	// --- 3. 窗口探测机制 (Window Probing) ---
    // 远程接收窗口(rmt_wnd)等于 0，说明对方无法接收数据，需要探测窗口。
	if (kcp->rmt_wnd == 0) {
		// 如果是第一次需要探测，设置初始等待时间
		if (kcp->probe_wait == 0) {
			// 初始探测间隔
			kcp->probe_wait = IKCP_PROBE_INIT;
			kcp->ts_probe = kcp->current + kcp->probe_wait;
		}
		// 否则，如果已经到了探测时间	
		else {
			if (_itimediff(kcp->current, kcp->ts_probe) >= 0) {
				// 如果当前探测间隔过小，重置为初始值
				if (kcp->probe_wait < IKCP_PROBE_INIT) 
					kcp->probe_wait = IKCP_PROBE_INIT;
				
				// 窗口探测间隔呈 1.5 倍指数增长 (退避算法)
				kcp->probe_wait += kcp->probe_wait / 2;

				// 限制最大探测间隔
				if (kcp->probe_wait > IKCP_PROBE_LIMIT)
					kcp->probe_wait = IKCP_PROBE_LIMIT;
				kcp->ts_probe = kcp->current + kcp->probe_wait;
				// 设置发送窗口探测请求的标志位
				kcp->probe |= IKCP_ASK_SEND;
			}
		}
	}	
	// 远程窗口不为 0，重置探测状态
	else {
		kcp->ts_probe = 0;
		kcp->probe_wait = 0;
	}

	// flush window probing commands
	// --- 4. 发送窗口探测请求 (IKCP_CMD_WASK) ---
	if (kcp->probe & IKCP_ASK_SEND) {
		// 请求对方告知其接收窗口大小
		seg.cmd = IKCP_CMD_WASK;
		// 检查缓冲区是否需要发送（同 ACK 逻辑）
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	// flush window probing commands
	// --- 5. 发送窗口告知命令 (IKCP_CMD_WINS) ---
	if (kcp->probe & IKCP_ASK_TELL) {
		// 主动告知对方我的接收窗口大小
		seg.cmd = IKCP_CMD_WINS;
		// 检查缓冲区是否需要发送
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg);
	}
	
	// 清除探测标志位
	kcp->probe = 0;

	// calculate window size
	// --- 6. 计算有效发送窗口大小 (cwnd) ---
	cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd);
	// 如果没有关闭拥塞控制（nocwnd == 0），则还要受拥塞窗口限制
	if (kcp->nocwnd == 0) cwnd = _imin_(kcp->cwnd, cwnd);

	// move data from snd_queue to snd_buf
	// --- 7. 将数据段从发送队列 (snd_queue) 移动到发送缓冲区 (snd_buf) ---
    // 仅在窗口允许的情况下移动数据：(snd_nxt - snd_una) < cwnd
	while (_itimediff(kcp->snd_nxt, kcp->snd_una + cwnd) < 0) {
		IKCPSEG *newseg;
		// 发送队列空，退出
		if (iqueue_is_empty(&kcp->snd_queue)) break;
		// 获取队列头部的数据段
		newseg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
		// 从发送队列移除，加入到发送缓冲区
		iqueue_del(&newseg->node);
		iqueue_add_tail(&newseg->node, &kcp->snd_buf);
		kcp->nsnd_que--;
		kcp->nsnd_buf++;

		// 初始化/更新数据段的发送相关参数
		newseg->conv = kcp->conv;
		newseg->cmd = IKCP_CMD_PUSH;
		newseg->wnd = seg.wnd;
		newseg->ts = current;
		newseg->sn = kcp->snd_nxt++;
		newseg->una = kcp->rcv_nxt;
		newseg->resendts = current;
		newseg->rto = kcp->rx_rto;
		newseg->fastack = 0;
		newseg->xmit = 0;
	}

	// calculate resent
	// --- 8. 准备重传参数 ---
    // resent: 快速重传阈值，如果 kcp->fastresend > 0 则取其值，否则取最大值 (不限)
	resent = (kcp->fastresend > 0)? (IUINT32)kcp->fastresend : 0xffffffff;
	// rtomin: 无延迟模式下的RTO补偿，只有nodelay=0时生效（保守模式下）
	rtomin = (kcp->nodelay == 0)? (kcp->rx_rto >> 3) : 0;

	// flush data segments
	// --- 9. 遍历发送缓冲区 (snd_buf)，执行发送和重传逻辑 ---
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		IKCPSEG *segment = iqueue_entry(p, IKCPSEG, node);
		// 标记该数据段是否需要发送
		int needsend = 0;

		// A. 首次发送(xmit==0)
		if (segment->xmit == 0) {
			needsend = 1;
			// 发送次数加 1
			segment->xmit++;
			// 设置初始 RTO
			segment->rto = kcp->rx_rto;
			// 设置下次重传时间：当前时间 + RTO + rtomin（保守模式补偿）
			segment->resendts = current + segment->rto + rtomin;
		}
		// B. RTO超时重传
		else if (_itimediff(current, segment->resendts) >= 0) {
			needsend = 1;
			// 总发送次数统计
			segment->xmit++;
			kcp->xmit++;
			// 超时后执行RTO退避算法
			if (kcp->nodelay == 0) {
				// 经典模式：RTO翻倍(拥塞)
				segment->rto += _imax_(segment->rto, (IUINT32)kcp->rx_rto);
			}	else {
				// 无延迟模式：RTO增长较为温和 (1.5倍或 kcp->rx_rto / 2)
				IINT32 step = (kcp->nodelay < 2)? 
					((IINT32)(segment->rto)) : kcp->rx_rto;
				segment->rto += step / 2;
			}
			// 设置新的重传时间
			segment->resendts = current + segment->rto;
			// 标记发生了超时（需要触发慢启动/拥塞控制）
			lost = 1;
		}
		// C. 快速重传(收到足够多的重复ACK)
		else if (segment->fastack >= resent) {
			if ((int)segment->xmit <= kcp->fastlimit || 
				kcp->fastlimit <= 0) {
				needsend = 1;
				segment->xmit++;
				// 重置fastack计数
				segment->fastack = 0;
				// 重置重传时间
				segment->resendts = current + segment->rto;
				// 标记发生了快速重传 (需要触发拥塞控制)
				change++;
			}
		}
		// --- 10. 编码并发送需要发送的数据段 ---
		if (needsend) {
			int need;
			// 更新KCP包头字段
			segment->ts = current;
			segment->wnd = seg.wnd;
			segment->una = kcp->rcv_nxt;
			// 检查MTU限制（同ACK逻辑）
			size = (int)(ptr - buffer);
			need = IKCP_OVERHEAD + segment->len;

			if (size + need > (int)kcp->mtu) {
				ikcp_output(kcp, buffer, size);
				ptr = buffer;
			}

			// 编码KCP包头
			ptr = ikcp_encode_seg(ptr, segment);
			// 复制数据到缓冲区
			if (segment->len > 0) {
				memcpy(ptr, segment->data, segment->len);
				ptr += segment->len;
			}
			
			// 检查是否达到死亡链接阈值
			if (segment->xmit >= kcp->dead_link) {
				kcp->state = (IUINT32)-1;
			}
		}
	}

	// flash remain segments
	// --- 11. 发送剩余的缓冲区内容 ---
	size = (int)(ptr - buffer);
	if (size > 0) {
		ikcp_output(kcp, buffer, size);
	}

	// update ssthresh
	// --- 12. 更新拥塞控制参数 (ssthresh 和 cwnd) ---

	// A. 快速重传导致的拥塞控制 (Change)
	if (change) {
		// 飞行中的数据量
		IUINT32 inflight = kcp->snd_nxt - kcp->snd_una;
		// 慢启动阈值减半
		kcp->ssthresh = inflight / 2;
		// 最小阈值限制
		if (kcp->ssthresh < IKCP_THRESH_MIN)
			kcp->ssthresh = IKCP_THRESH_MIN;
		// cwnd设置为ssthresh+fastresend个包（Fast Recovery/Avoidance）
		kcp->cwnd = kcp->ssthresh + resent;
		// 相应调整 incr
		kcp->incr = kcp->cwnd * kcp->mss;
	}

	// B. 超时重传导致的拥塞控制 (Lost)
	if (lost) {
		// 慢启动阈值减半
		kcp->ssthresh = cwnd / 2;
		if (kcp->ssthresh < IKCP_THRESH_MIN)
			kcp->ssthresh = IKCP_THRESH_MIN;
		// 拥塞窗口重置为 1 (进入慢启动 Slow Start)
		kcp->cwnd = 1;
		// incr 重置为 MSS
		kcp->incr = kcp->mss;
	}
	
	// C. 确保 cwnd 至少为 1
	if (kcp->cwnd < 1) {
		kcp->cwnd = 1;
		kcp->incr = kcp->mss;
	}
}


//---------------------------------------------------------------------
// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec. 
//---------------------------------------------------------------------
//---------------------------------------------------------------------
// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// ('更新状态（重复调用，每 10ms-100ms 一次），或者你可以询问 ikcp_check 
//  何时再次调用（当没有 ikcp_input 或 ikcp_send 调用时）。')
//
// 'current' - current timestamp in millisec. 
// ('current' - 当前时间戳，单位毫秒。)
//---------------------------------------------------------------------
// 函数名：ikcp_update
// 作用：KCP 协议栈的主时钟和状态更新函数。负责触发刷新（flush）逻辑
// 参数：
//   kcp:        ikcpcb 结构体指针，代表当前的 KCP 控制块实例
//   current:    当前的时间（毫秒）
// 返回值：
//   无 (void)
void ikcp_update(ikcpcb *kcp, IUINT32 current)
{
	IINT32 slap;
	// --- 1. 初始化 KCP 时间戳 ---
	kcp->current = current;

	// 如果是第一次调用 ikcp_update：
	if (kcp->updated == 0) {
		// 设置更新标志为已初始化
		kcp->updated = 1;
		// 将下一次flush的时间戳初始化为当前时间
		kcp->ts_flush = kcp->current;
	}

	// --- 2. 计算距离下一次flush的时间差 ---
	slap = _itimediff(kcp->current, kcp->ts_flush);


	// --- 3. 处理时间回绕问题 (Time Wrap Around) ---
    // 检查时间差是否异常大（> 10000ms 或 < -10000ms），防止32位时间戳回绕导致计算错误。
	if (slap >= 10000 || slap < -10000) {
		kcp->ts_flush = kcp->current;
		slap = 0;
	}

// --- 4. 触发 ikcp_flush 逻辑 ---
    // 如果时间差 slap >= 0，说明当前时间已经到达或超过了预定的ts_flush时间点。
	if (slap >= 0) {
		// A. 预定下一次 flush 的时间点：
        // ts_flush = ts_flush (旧) + interval (周期，如 10ms)
		kcp->ts_flush += kcp->interval;

		// B. 补偿时间漂移：防止多次调用 ikcp_update 导致 ts_flush 过于超前。
        // 如果当前时间仍然大于或等于新的 ts_flush（即系统调用 ikcp_update 的频率太慢）：
		if (_itimediff(kcp->current, kcp->ts_flush) >= 0) {
			kcp->ts_flush = kcp->current + kcp->interval;
		}
		
		// C. 执行核心刷新操作：
        // 核心函数，负责检查和发送待发送的数据包、处理 ACK、计算 RTO 和重传逻辑。
		ikcp_flush(kcp);
	}
}


//---------------------------------------------------------------------
// Determine when should you invoke ikcp_update:
// (确定何时应该调用 ikcp_update:)
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// 返回你应该在哪个时间点（毫秒，相对于current）调用ikcp_update。
// 这里的调用是在没有ikcp_input或ikcp_send发生时调用的。你可以选择在那个返回的时间点调用 ikcp_update，而不是重复轮询。
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
// (这对于减少不必要的ikcp_update调用非常重要。可以用来调度ikcp_update，
// 例如实现类似epoll的机制，或者在处理大量KCP连接时进行优化。)
//---------------------------------------------------------------------
// 函数名：ikcp_check
// 作用：计算下一次 ikcp_update() 应该被调用的绝对时间点。
// 参数：
//   kcp:        ikcpcb 结构体指针，代表当前的 KCP 控制块实例。
//   current:    当前的时间（毫秒）。
// 返回值：
//   IUINT32: 下一次应该调用ikcp_update的绝对时间（毫秒）。
IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current)
{
	// kcp->ts_flush: 上一次ikcp_flush实际被调用的时间戳。
	IUINT32 ts_flush = kcp->ts_flush;
	// tm_flush: 距离下一次强制flush(基于 interval) 还有多少时间。初始化为最大值
	IINT32 tm_flush = 0x7fffffff;
	// tm_packet: 距离下一个数据包需要重传还有多少时间。初始化为最大值
	IINT32 tm_packet = 0x7fffffff;
	// minimal: 两个时间差中的最小值，即最小等待时间
	IUINT32 minimal = 0;
	struct IQUEUEHEAD *p;
	// // --- 1. 检查是否已经调用过updated ---
	if (kcp->updated == 0) {
		return current;
	}

	// --- 2. 处理时间回绕问题 (Time Wrap Around) ---
    // KCP 使用 32 位时间戳，可能会发生回绕。这里检查时间差是否超过 10 秒（10000ms）。
    // 如果时间差异常大，说明时钟可能发生了跳变或回绕，强制重置 ts_flush。
	if (_itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000) {
		ts_flush = current;
	}

	// --- 3. 检查是否已到强制 flush 时间点 ---
    // 检查是否已经到达或超过了 ts_flush。
    // 注意：ts_flush 在 ikcp_update 中会被更新为 current + interval，所以这里判断的是当前时间是否大于或等于 ts_flush。
	if (_itimediff(current, ts_flush) >= 0) {
		return current;
	}

	// --- 4. 计算距离下一次强制flush还有多长时间 ---
    // tm_flush 是ts_flush（目标时间）与current（当前时间）的差值，即还需要等待的时间
    // ts_flush 是一个未来的时间点。
	tm_flush = _itimediff(ts_flush, current);

	// --- 5. 遍历发送缓冲区，寻找下一个需要重传的包 ---
    // 遍历 kcp 的发送缓冲区 (snd_buf)。
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		IINT32 diff = _itimediff(seg->resendts, current);
		if (diff <= 0) {
			return current;
		}
		// 最小的重传时间
		if (diff < tm_packet) tm_packet = diff;
	}

	// --- 6. 确定最小等待时间 (minimal) ---
    // 最小等待时间=min(下一次强制flush等待时间, 下一个数据包重传等待时间)
	minimal = (IUINT32)(tm_packet < tm_flush ? tm_packet : tm_flush);
	// 最终的最小等待时间不能超过kcp的interval设置
    // 这是为了避免在发送缓冲区空闲时，等待时间被无限拉长（例如 tm_packet=0x7fffffff）
	if (minimal >= kcp->interval) minimal = kcp->interval;

	// --- 7. 返回下一次调用 ikcp_update 的绝对时间 ---
    // 返回：当前时间 + 最小等待时间
	return current + minimal;
}


// 设置MTU
int ikcp_setmtu(ikcpcb *kcp, int mtu)
{
	char *buffer;
	if (mtu < 50 || mtu < (int)IKCP_OVERHEAD) 
		return -1;
	// 分配3 * （mtu + kcp头)的大小
	buffer = (char*)ikcp_malloc((mtu + IKCP_OVERHEAD) * 3);
	if (buffer == NULL) 
		return -2;
	kcp->mtu = mtu;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	ikcp_free(kcp->buffer);
	kcp->buffer = buffer;
	return 0;
}

// 设置interval
int ikcp_interval(ikcpcb *kcp, int interval)
{
	if (interval > 5000) interval = 5000;
	else if (interval < 10) interval = 10;
	kcp->interval = interval;
	return 0;
}

// 作用：设置 KCP 的无延迟模式（Nodelay Mode）和关键参数。
//       这是 KCP 区别于标准 TCP 的核心优化函数。
// 参数：
//   kcp:        ikcpcb 结构体指针，代表当前的 KCP 控制块实例。
//   nodelay:    是否启用无延迟模式（Nodelay Mode）。
//               - 0: 经典模式（Classic Mode），类似 TCP 算法，延迟稍高但更稳定。
//               - 1: 启用无延迟模式，大幅降低 RTO（重传超时），牺牲稳定性换取低延迟。
//               - 2: 极速模式（Turbo Mode，通常与 fastresend=2 配合使用）。
//               - 负值: 不修改当前设置。
//   interval:   内部时钟更新频率（单位：毫秒）。即 ikcp_update() 调用的最小间隔。
//               - 推荐值是 10ms 或 20ms。
//               - 负值: 不修改当前设置。
//   resend:     快速重传模式的参数。
//               - 0: 关闭快速重传（即等待 RTO 超时）。
//               - 1: 默认快速重传（收到 3 个重复 ACK 触发）。
//               - 2: 积极快速重传（收到 2 个重复 ACK 触发）。
//               - 负值: 不修改当前设置。
//   nc:         是否关闭拥塞控制（No Congestion Window）。
//               - 0: 启用拥塞控制（标准 KCP 流程，有 cwnd 限制）。
//               - 1: 关闭拥塞控制（`kcp->nocwnd = 1`），发包速度只受接收窗口 rwnd 限制。
//               - 负值: 不修改当前设置。
// 返回值：
//   0: 成功设置。
int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc)
{
	// --- 1. 设置延迟模式 (nodelay) ---
	if (nodelay >= 0) {
		kcp->nodelay = nodelay;
		if (nodelay) {
			// 如果启用无延迟模式（nodelay > 0），将最小重传超时（RTO）设置为 IKCP_RTO_NDL（默认 30ms）。
            // 极大地缩短了 RTO 周期，使得丢包后能更快地触发重传。
			kcp->rx_minrto = IKCP_RTO_NDL;	
		}	
		else {
			// 如果关闭无延迟模式（nodelay = 0），将最小RTO 设置为IKCP_RTO_MIN（默认 100ms/200ms）。
            // 采用更保守的 RTO，类似 TCP，适用于网络拥堵但不丢包的场景。
			kcp->rx_minrto = IKCP_RTO_MIN;
		}
	}
	// --- 2. 设置内部时钟更新频率 (interval) ---
	if (interval >= 0) {
		// 限制 interval 的最大值，避免时钟更新过于稀疏。
		if (interval > 5000) interval = 5000;
		// 限制interval的最小值，避免时钟更新过于频繁，消耗过多CPU资源。
        // 建议值通常是10ms或20ms，这里硬编码了最小10ms的限制。
		else if (interval < 10) interval = 10;
		kcp->interval = interval;
	}
	// --- 3. 设置快速重传的重复ACK数 (resend) ---
	if (resend >= 0) {
		// 存储快速重传的阈值。
        // kcp->fastresend = 0: 关闭。
        // kcp->fastresend = 1: 默认（通常是3个重复 ACK）。
        // kcp->fastresend = 2: 更积极（通常是2个重复ACK）。
		kcp->fastresend = resend;
	}
	// --- 4. 设置是否关闭拥塞控制 (nc/nocwnd) ---
	if (nc >= 0) {
		// kcp->nocwnd = 1: 关闭发送窗口（拥塞窗口cwnd）的限制。
        // 此时发送速率只受接收窗口 rwnd 限制，适用于局域网或对延迟要求极高且网络质量好的场景。
        // 否则（kcp->nocwnd = 0），发送速率受 min(cwnd, rwnd) 限制。
		kcp->nocwnd = nc;
	}
	return 0;
}

// 设置发送窗口和接收窗口的大小
int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd)
{
	if (kcp) {
		if (sndwnd > 0) {
			kcp->snd_wnd = sndwnd;
		}
		if (rcvwnd > 0) {   // must >= max fragment size
			// 接收窗口最小也会是IKCP_WND_RCV
			kcp->rcv_wnd = _imax_(rcvwnd, IKCP_WND_RCV);
		}
	}
	return 0;
}

// 获取等待发送的数据长度
int ikcp_waitsnd(const ikcpcb *kcp)
{
	return kcp->nsnd_buf + kcp->nsnd_que;
}


// read conv
// 读取会话ID
IUINT32 ikcp_getconv(const void *ptr)
{
	IUINT32 conv;
	ikcp_decode32u((const char*)ptr, &conv);
	return conv;
}


