// SPDX-License-Identifier: ISC
/*
 * Copyright (C) 2018 Felix Fietkau <nbd@nbd.name>
 */
#include "mt76.h"

static inline unsigned long
mt76_aggr_tid_to_timeo(u8 tidno)
{
	/* Currently voice traffic (AC_VO) always runs without aggregation,
	 * no special handling is needed. AC_BE/AC_BK use tids 0-3. Just check
	 * for non AC_BK/AC_BE and set smaller timeout for it. */
	return max_t(unsigned long,
		HZ / (tidno >= 4 ? 25 : 10),
		1);
}

static inline u16
mt76_aggr_idx(struct mt76_rx_tid *tid, u16 seq)
{
	const u16 size = tid->size;

	if (likely(is_power_of_2(size)))
		return seq & (size - 1);

	return seq % size;
}

static inline void
mt76_aggr_release(struct mt76_rx_tid *tid, struct sk_buff_head *frames, int idx)
{
	struct sk_buff *skb;

	tid->head = ieee80211_sn_inc(tid->head);

	skb = tid->reorder_buf[idx];
	if (unlikely(!skb))
		return;

	tid->reorder_buf[idx] = NULL;
	tid->nframes--;

	__skb_queue_tail(frames, skb);
}

static void
mt76_rx_aggr_release_frames(struct mt76_rx_tid *tid,
			    struct sk_buff_head *frames,
			    u16 head)
{
	while (ieee80211_sn_less(tid->head, head))
		mt76_aggr_release(tid, frames,
				  mt76_aggr_idx(tid, tid->head));
}

static void
mt76_rx_aggr_release_head(struct mt76_rx_tid *tid, struct sk_buff_head *frames)
{
	u16 idx = mt76_aggr_idx(tid, tid->head);

	while (tid->reorder_buf[idx]) {
		mt76_aggr_release(tid, frames, idx);
		idx = mt76_aggr_idx(tid, tid->head);
	}
}

static void
mt76_rx_aggr_check_release(struct mt76_rx_tid *tid, struct sk_buff_head *frames)
{
	struct mt76_rx_status *status;
	struct sk_buff *skb;
	int start, idx, nframes;
	u16 seq;
	unsigned long timeout;

	if (!tid->nframes)
		return;

	timeout = tid->timeout;

	if (!time_after(jiffies,
			tid->oldest_time + timeout))
		return;

	mt76_rx_aggr_release_head(tid, frames);

	start = mt76_aggr_idx(tid, tid->head);
	nframes = tid->nframes;

	for (seq = ieee80211_sn_inc(tid->head);
	     mt76_aggr_idx(tid, seq) != start && nframes;
	     seq = ieee80211_sn_inc(seq)) {

		idx = mt76_aggr_idx(tid, seq);

		skb = tid->reorder_buf[idx];
		if (!skb)
			continue;

		nframes--;
		status = (struct mt76_rx_status *)skb->cb;

		if (!time_after32(jiffies,
				  status->reorder_time + timeout))
			continue;

		mt76_rx_aggr_release_frames(tid, frames, status->seqno);
	}

	mt76_rx_aggr_release_head(tid, frames);
}

static void
mt76_rx_aggr_reorder_work(struct work_struct *work)
{
	struct mt76_rx_tid *tid = container_of(work, struct mt76_rx_tid,
					       reorder_work.work);
	struct mt76_dev *dev = tid->dev;
	struct sk_buff_head frames;
	bool resched = false;

	__skb_queue_head_init(&frames);

	rcu_read_lock();
	spin_lock_bh(&tid->lock);

	tid->timer_pending = false;

	mt76_rx_aggr_check_release(tid, &frames);

	if (tid->nframes && !tid->timer_pending) {
		tid->timer_pending = true;
		resched = true;
	}

	spin_unlock_bh(&tid->lock);
	rcu_read_unlock();

	mt76_rx_complete(dev, &frames, NULL);

	if (resched)
		ieee80211_queue_delayed_work(tid->dev->hw, &tid->reorder_work,
					     tid->timeout);
}

static void
mt76_rx_aggr_check_ctl(struct sk_buff *skb, struct sk_buff_head *frames)
{
	struct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;
	struct ieee80211_bar *bar = (struct ieee80211_bar *)skb->data;
	struct mt76_wcid *wcid = status->wcid;
	struct mt76_rx_tid *tid;
	u8 tidno;
	u16 seqno;

	if (skb->len < sizeof(*bar))
		return;

	if (!ieee80211_is_ctl(bar->frame_control))
		return;

	if (!ieee80211_is_back_req(bar->frame_control))
		return;

	status->qos_ctl = tidno = le16_to_cpu(bar->control) >> 12;

	if (tidno >= IEEE80211_NUM_TIDS)
		return;

	seqno = IEEE80211_SEQ_TO_SN(le16_to_cpu(bar->start_seq_num));

	if (!wcid)
		return;

	rcu_read_lock();

	tid = rcu_dereference(wcid->aggr[tidno]);
	if (!tid)
		goto rcu_unlock;

	spin_lock_bh(&tid->lock);
	if (!tid->stopped) {
		mt76_rx_aggr_release_frames(tid, frames, seqno);
		mt76_rx_aggr_release_head(tid, frames);
	}
	spin_unlock_bh(&tid->lock);

rcu_unlock:
	rcu_read_unlock();
}

void mt76_rx_aggr_reorder(struct sk_buff *skb, struct sk_buff_head *frames)
{
	struct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;
	struct mt76_wcid *wcid = status->wcid;
	struct sk_buff **reorder_buf;
	struct mt76_rx_tid *tid;
	struct sk_buff *drop_skb = NULL;
	bool sn_less;
	u16 qos_ctl, seqno, head, size;
	u8 ackp, idx;
	u8 tidno;

	__skb_queue_tail(frames, skb);

	if (!wcid)
		return;

	qos_ctl = status->qos_ctl;
	tidno = qos_ctl & IEEE80211_QOS_CTL_TID_MASK;

	if (tidno >= IEEE80211_NUM_TIDS)
		return;

	if (!status->aggr) {
		if (!(status->flag & RX_FLAG_8023))
			mt76_rx_aggr_check_ctl(skb, frames);
		return;
	}

	/* not part of a BA session */
	ackp = qos_ctl & IEEE80211_QOS_CTL_ACK_POLICY_MASK;
	if (ackp == IEEE80211_QOS_CTL_ACK_POLICY_NOACK)
		return;

	rcu_read_lock();

	tid = rcu_dereference(wcid->aggr[tidno]);
	if (!tid) {
		rcu_read_unlock();
		return;
	}

	reorder_buf = tid->reorder_buf;

	spin_lock_bh(&tid->lock);

	if (tid->stopped)
		goto out;

	status->flag |= RX_FLAG_DUP_VALIDATED;
	head = tid->head;
	seqno = status->seqno;
	size = tid->size;
	sn_less = ieee80211_sn_less(seqno, head);

	if (!tid->started) {
		if (sn_less)
			goto out;

		tid->started = true;
	}

	if (sn_less) {
		__skb_unlink(skb, frames);
		drop_skb = skb;
		goto out;
	}

	if (seqno == head) {
		tid->head = ieee80211_sn_inc(head);
		if (tid->nframes)
			mt76_rx_aggr_release_head(tid, frames);
		goto out;
	}

	__skb_unlink(skb, frames);

	/*
	 * Frame sequence number exceeds buffering window, free up some space
	 * by releasing previous frames
	 */
	if (!ieee80211_sn_less(seqno, head + size)) {
		head = ieee80211_sn_inc(ieee80211_sn_sub(seqno, size));
		mt76_rx_aggr_release_frames(tid, frames, head);
	}

	idx = mt76_aggr_idx(tid, seqno);

	/* Discard if the current slot is already in use */
	if (unlikely(reorder_buf[idx])) {
		drop_skb = skb;
		goto out;
	}

	status->reorder_time = jiffies;

	if (!tid->nframes)
		tid->oldest_time = status->reorder_time;

	reorder_buf[idx] = skb;
	tid->nframes++;
	mt76_rx_aggr_release_head(tid, frames);

	if (!tid->timer_pending) {
		tid->timer_pending = true;
		ieee80211_queue_delayed_work(tid->dev->hw, &tid->reorder_work,
									tid->timeout);
	}

out:
	spin_unlock_bh(&tid->lock);
	rcu_read_unlock();

	if (drop_skb)
		dev_kfree_skb(drop_skb);
}

int mt76_rx_aggr_start(struct mt76_dev *dev, struct mt76_wcid *wcid, u8 tidno,
		       u16 ssn, u8 size)
{
	struct mt76_rx_tid *tid;

	if (!wcid || tidno >= IEEE80211_NUM_TIDS || !size)
		return -EINVAL;	

	if (size > 64)
		size = 64;

	tid = kzalloc(struct_size(tid, reorder_buf, size), GFP_KERNEL);
	if (!tid)
		return -ENOMEM;

	mt76_rx_aggr_stop(dev, wcid, tidno);

	tid->dev = dev;
	tid->head = ssn;
	tid->size = size;
	tid->num = tidno;
	tid->timeout = mt76_aggr_tid_to_timeo(tidno);

	INIT_DELAYED_WORK(&tid->reorder_work, mt76_rx_aggr_reorder_work);
	spin_lock_init(&tid->lock);

	rcu_assign_pointer(wcid->aggr[tidno], tid);

	return 0;
}
EXPORT_SYMBOL_GPL(mt76_rx_aggr_start);

static void mt76_rx_aggr_shutdown(struct mt76_rx_tid *tid)
{
	struct sk_buff_head frames;
	struct sk_buff **reorder_buf = tid->reorder_buf;
	u8 size = tid->size;
	int i;

	__skb_queue_head_init(&frames);

	cancel_delayed_work_sync(&tid->reorder_work);

	spin_lock_bh(&tid->lock);

	tid->stopped = true;
	tid->timer_pending = false;

	for (i = 0; tid->nframes && i < size; i++) {
		struct sk_buff *skb = reorder_buf[i];

		if (!skb)
			continue;

		reorder_buf[i] = NULL;
		tid->nframes--;

		__skb_queue_tail(&frames, skb);
	}

	spin_unlock_bh(&tid->lock);

	dev_kfree_skb_list(&frames);
}

void mt76_rx_aggr_stop(struct mt76_dev *dev, struct mt76_wcid *wcid, u8 tidno)
{
	struct mt76_rx_tid *tid = NULL;

	if (!wcid || tidno >= IEEE80211_NUM_TIDS)
		return;

	rcu_swap_protected(wcid->aggr[tidno], tid,
			   lockdep_is_held(&dev->mutex));
	if (tid) {
		mt76_rx_aggr_shutdown(tid);
		kfree_rcu(tid, rcu_head);
	}
}
EXPORT_SYMBOL_GPL(mt76_rx_aggr_stop);
