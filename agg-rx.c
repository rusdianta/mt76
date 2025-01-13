// SPDX-License-Identifier: ISC
/*
 * Copyright (C) 2018 Felix Fietkau <nbd@nbd.name>
 */
#include "mt76.h"

static unsigned long mt76_aggr_tid_to_timeo(u8 tidno)
{
	/* Currently voice traffic (AC_VO) always runs without aggregation,
	 * no special handling is needed. AC_BE/AC_BK use tids 0-3. Just check
	 * for non AC_BK/AC_BE and set smaller timeout for it. */
	return HZ / (tidno >= 4 ? 25 : 10);
}

static void
mt76_aggr_release(struct mt76_rx_tid *tid, struct sk_buff_head *frames, int idx)
{
	tid->head = ieee80211_sn_inc(tid->head);

	struct sk_buff *skb = tid->reorder_buf[idx];
	if (!skb)
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
	while (ieee80211_sn_less(tid->head, head)) {
		int idx = tid->head % tid->size;
		mt76_aggr_release(tid, frames, idx);
	}
}

static void
mt76_rx_aggr_release_head(struct mt76_rx_tid *tid, struct sk_buff_head *frames)
{
	int idx = tid->head % tid->size;

	while (tid->reorder_buf[idx]) {
		mt76_aggr_release(tid, frames, idx);
		idx = tid->head % tid->size;
	}
}

static void
mt76_rx_aggr_check_release(struct mt76_rx_tid *tid, struct sk_buff_head *frames)
{
	if (!tid->nframes)
		return;

	mt76_rx_aggr_release_head(tid, frames);

	int start = tid->head % tid->size;
	int nframes = tid->nframes;
	int idx;

	for (idx = (tid->head + 1) % tid->size;
	     idx != start && nframes;
	     idx = (idx + 1) % tid->size) {
		struct sk_buff *skb = tid->reorder_buf[idx];
		if (!skb)
			continue;

		nframes--;
		struct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;
		if (!time_after32(jiffies,
				  status->reorder_time +
				  mt76_aggr_tid_to_timeo(tid->num)))
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
	struct sk_buff_head frames;
	__skb_queue_head_init(&frames);

	local_bh_disable();
	rcu_read_lock();

	spin_lock(&tid->lock);
	mt76_rx_aggr_check_release(tid, &frames);
	int nframes = tid->nframes;
	spin_unlock(&tid->lock);

	struct mt76_dev *dev = tid->dev;
	if (nframes)
		ieee80211_queue_delayed_work(dev->hw, &tid->reorder_work,
					     mt76_aggr_tid_to_timeo(tid->num));
	mt76_rx_complete(dev, &frames, NULL);

	rcu_read_unlock();
	local_bh_enable();
}

static void
mt76_rx_aggr_check_ctl(struct sk_buff *skb, struct sk_buff_head *frames)
{
	struct ieee80211_bar *bar = mt76_skb_get_hdr(skb);

	if (!ieee80211_is_ctl(bar->frame_control))
		return;

	if (!ieee80211_is_back_req(bar->frame_control))
		return;

	struct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;
	struct mt76_wcid *wcid = status->wcid
	u8 tidno;

	status->qos_ctl = tidno = le16_to_cpu(bar->control) >> 12;
	struct mt76_rx_tid *tid = rcu_dereference(wcid->aggr[tidno]);
	if (!tid)
		return;

	spin_lock_bh(&tid->lock);
	if (!tid->stopped) {
		u16 seqno = IEEE80211_SEQ_TO_SN(le16_to_cpu(bar->start_seq_num));
		mt76_rx_aggr_release_frames(tid, frames, seqno);
		mt76_rx_aggr_release_head(tid, frames);
	}
	spin_unlock_bh(&tid->lock);
}

void mt76_rx_aggr_reorder(struct sk_buff *skb, struct sk_buff_head *frames)
{
	__skb_queue_tail(frames, skb);

	struct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;
	struct mt76_wcid *wcid = status->wcid;
	struct ieee80211_sta *sta = wcid_to_sta(wcid);

	if (!sta)
		return;

	if (!status->aggr) {
		if (!(status->flag & RX_FLAG_8023))
			mt76_rx_aggr_check_ctl(skb, frames);
		return;
	}

	/* not part of a BA session */
	u8 ackp = status->qos_ctl & IEEE80211_QOS_CTL_ACK_POLICY_MASK;
	if (ackp == IEEE80211_QOS_CTL_ACK_POLICY_NOACK)
		return;

	u8 tidno = status->qos_ctl & IEEE80211_QOS_CTL_TID_MASK;
	struct mt76_rx_tid *tid = rcu_dereference(wcid->aggr[tidno]);
	if (!tid)
		return;

	status->flag |= RX_FLAG_DUP_VALIDATED;
	spin_lock_bh(&tid->lock);

	if (tid->stopped)
		goto out;

	u16 head = tid->head;
	u16 seqno = status->seqno;
	bool sn_less = ieee80211_sn_less(seqno, head);

	if (!tid->started) {
		if (sn_less)
			goto out;

		tid->started = true;
	}

	u16 size = tid->size;

	if (sn_less) {
		__skb_unlink(skb, frames);
		dev_kfree_skb(skb);
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

	u16 idx = seqno % size;

	/* Discard if the current slot is already in use */
	if (tid->reorder_buf[idx]) {
		dev_kfree_skb(skb);
		goto out;
	}

	status->reorder_time = jiffies;
	tid->reorder_buf[idx] = skb;
	tid->nframes++;
	mt76_rx_aggr_release_head(tid, frames);

	ieee80211_queue_delayed_work(tid->dev->hw, &tid->reorder_work,
				     mt76_aggr_tid_to_timeo(tid->num));

out:
	spin_unlock_bh(&tid->lock);
}

int mt76_rx_aggr_start(struct mt76_dev *dev, struct mt76_wcid *wcid, u8 tidno,
		       u16 ssn, u16 size)
{
	mt76_rx_aggr_stop(dev, wcid, tidno);

	struct mt76_rx_tid *tid = kzalloc(struct_size(tid, reorder_buf, size), GFP_KERNEL);
	if (!tid)
		return -ENOMEM;

	tid->dev = dev;
	tid->head = ssn;
	tid->size = size;
	tid->num = tidno;
	INIT_DELAYED_WORK(&tid->reorder_work, mt76_rx_aggr_reorder_work);
	spin_lock_init(&tid->lock);

	rcu_assign_pointer(wcid->aggr[tidno], tid);

	return 0;
}
EXPORT_SYMBOL_GPL(mt76_rx_aggr_start);

static void mt76_rx_aggr_shutdown(struct mt76_dev *dev, struct mt76_rx_tid *tid)
{
	spin_lock_bh(&tid->lock);
	tid->stopped = true;

	int i;
	u16 size;

	size = tid->size;
	for (i = 0; tid->nframes && i < size; i++) {
		struct sk_buff *skb = tid->reorder_buf[i];

		if (!skb)
			continue;

		tid->reorder_buf[i] = NULL;
		tid->nframes--;
		dev_kfree_skb(skb);
	}

	spin_unlock_bh(&tid->lock);

	cancel_delayed_work_sync(&tid->reorder_work);
}

void mt76_rx_aggr_stop(struct mt76_dev *dev, struct mt76_wcid *wcid, u8 tidno)
{
	struct mt76_rx_tid *tid = NULL;

	rcu_swap_protected(wcid->aggr[tidno], tid,
			   lockdep_is_held(&dev->mutex));
	if (tid) {
		mt76_rx_aggr_shutdown(dev, tid);
		kfree_rcu(tid, rcu_head);
	}
}
EXPORT_SYMBOL_GPL(mt76_rx_aggr_stop);
