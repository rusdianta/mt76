// SPDX-License-Identifier: ISC
/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
 */

#include "mt76.h"

static int
mt76_txq_get_qid(struct ieee80211_txq *txq)
{
	if (!txq->sta)
		return MT_TXQ_BE;

	return txq->ac;
}

void
mt76_tx_check_agg_ssn(struct ieee80211_sta *sta, struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct ieee80211_txq *txq;
	struct mt76_txq *mtxq;
	u8 tid;

	if (!sta || !ieee80211_is_data_qos(hdr->frame_control) ||
	    !ieee80211_is_data_present(hdr->frame_control))
		return;

	tid = skb->priority & IEEE80211_QOS_CTL_TAG1D_MASK;
	txq = sta->txq[tid];
	mtxq = (struct mt76_txq *)txq->drv_priv;
	if (!mtxq->aggr)
		return;

	mtxq->agg_ssn = le16_to_cpu(hdr->seq_ctrl) + 0x10;
}
EXPORT_SYMBOL_GPL(mt76_tx_check_agg_ssn);

void
mt76_tx_status_lock(struct mt76_dev *dev, struct sk_buff_head *list)
		   __acquires(&dev->status_lock)
{
	__skb_queue_head_init(list);
	spin_lock_bh(&dev->status_lock);
}
EXPORT_SYMBOL_GPL(mt76_tx_status_lock);

void
mt76_tx_status_unlock(struct mt76_dev *dev, struct sk_buff_head *list)
		      __releases(&dev->status_lock)
{
	struct sk_buff *skb;

	spin_unlock_bh(&dev->status_lock);

	while ((skb = __skb_dequeue(list)) != NULL) {
		spin_lock_bh(&dev->mt76.rx_lock);
		ieee80211_tx_status(dev->hw, skb);
		spin_unlock_bh(&dev->mt76.rx_lock);
	}
}
EXPORT_SYMBOL_GPL(mt76_tx_status_unlock);

static void
__mt76_tx_status_skb_done(struct mt76_dev *dev, struct sk_buff *skb, u8 flags,
			  struct sk_buff_head *list)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct mt76_tx_cb *cb = mt76_tx_skb_cb(skb);
	u8 done = MT_TX_CB_DMA_DONE | MT_TX_CB_TXS_DONE;

	flags |= cb->flags;
	cb->flags = flags;

	if ((flags & done) != done)
		return;

	/* Tx status can be unreliable. if it fails, mark the frame as ACKed */
	if (flags & MT_TX_CB_TXS_FAILED) {
		ieee80211_tx_info_clear_status(info);
		info->status.rates[0].idx = -1;
		info->flags |= IEEE80211_TX_STAT_ACK;
	}

	__skb_queue_tail(list, skb);
}

void
mt76_tx_status_skb_done(struct mt76_dev *dev, struct sk_buff *skb,
			struct sk_buff_head *list)
{
	__mt76_tx_status_skb_done(dev, skb, MT_TX_CB_TXS_DONE, list);
}
EXPORT_SYMBOL_GPL(mt76_tx_status_skb_done);

int
mt76_tx_status_skb_add(struct mt76_dev *dev, struct mt76_wcid *wcid,
		       struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct mt76_tx_cb *cb = mt76_tx_skb_cb(skb);
	int pid;

	memset(cb, 0, sizeof(*cb));

	if (!wcid || !rcu_access_pointer(dev->wcid[wcid->idx]))
		return MT_PACKET_ID_NO_ACK;

	if (info->flags & IEEE80211_TX_CTL_NO_ACK)
		return MT_PACKET_ID_NO_ACK;

	if (!(info->flags & (IEEE80211_TX_CTL_REQ_TX_STATUS |
			     IEEE80211_TX_CTL_RATE_CTRL_PROBE)))
		return MT_PACKET_ID_NO_SKB;

	spin_lock_bh(&dev->status_lock);

	pid = idr_alloc(&wcid->pktid, skb, MT_PACKET_ID_FIRST,
			MT_PACKET_ID_MASK, GFP_ATOMIC);
	if (pid < 0) {
		pid = MT_PACKET_ID_NO_SKB;
		goto out;
	}

	cb->wcid = wcid->idx;
	cb->pktid = pid;

	if (list_empty(&wcid->list))
		list_add_tail(&wcid->list, &dev->wcid_list);

out:
	spin_unlock_bh(&dev->status_lock);

	return pid;
}
EXPORT_SYMBOL_GPL(mt76_tx_status_skb_add);

struct sk_buff *
mt76_tx_status_skb_get(struct mt76_dev *dev, struct mt76_wcid *wcid, int pktid,
		       struct sk_buff_head *list)
{
	struct sk_buff *skb;
	int id;

	lockdep_assert_held(&dev->status_lock);

	skb = idr_remove(&wcid->pktid, pktid);
	if (skb)
		goto out;

	/* look for stale entries in the wcid idr queue */
	idr_for_each_entry(&wcid->pktid, skb, id) {
		struct mt76_tx_cb *cb = mt76_tx_skb_cb(skb);

		if (pktid >= 0) {
			if (!(cb->flags & MT_TX_CB_DMA_DONE))
				continue;

			if (time_is_after_jiffies(cb->jiffies +
						   MT_TX_STATUS_SKB_TIMEOUT))
				continue;
		}

		/* It has been too long since DMA_DONE, time out this packet
		 * and stop waiting for TXS callback.
		 */
		idr_remove(&wcid->pktid, cb->pktid);
		__mt76_tx_status_skb_done(dev, skb, MT_TX_CB_TXS_FAILED |
						    MT_TX_CB_TXS_DONE, list);
	}

out:
	if (idr_is_empty(&wcid->pktid))
		list_del_init(&wcid->list);

	return skb;
}
EXPORT_SYMBOL_GPL(mt76_tx_status_skb_get);

void
mt76_tx_status_check(struct mt76_dev *dev, bool flush)
{
	struct mt76_wcid *wcid, *tmp;
	struct sk_buff_head list;

	mt76_tx_status_lock(dev, &list);
	list_for_each_entry_safe(wcid, tmp, &dev->wcid_list, list)
		mt76_tx_status_skb_get(dev, wcid, flush ? -1 : 0, &list);
	mt76_tx_status_unlock(dev, &list);
}
EXPORT_SYMBOL_GPL(mt76_tx_status_check);

void mt76_tx_complete_skb(struct mt76_dev *dev, struct sk_buff *skb)
{
	struct mt76_tx_cb *cb = mt76_tx_skb_cb(skb);
	struct sk_buff_head list;

	if (cb->pktid < MT_PACKET_ID_FIRST) {
		ieee80211_free_txskb(dev->hw, skb);
		return;
	}

	mt76_tx_status_lock(dev, &list);
	cb->jiffies = jiffies;
	__mt76_tx_status_skb_done(dev, skb, MT_TX_CB_DMA_DONE, &list);
	mt76_tx_status_unlock(dev, &list);
}
EXPORT_SYMBOL_GPL(mt76_tx_complete_skb);

void
mt76_tx(struct mt76_dev *dev, struct ieee80211_sta *sta,
	struct mt76_wcid *wcid, struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct mt76_queue *q;
	int qid = skb_get_queue_mapping(skb);

	if (WARN_ON(qid >= MT_TXQ_PSD)) {
		qid = MT_TXQ_BE;
		skb_set_queue_mapping(skb, qid);
	}

	if ((dev->drv->drv_flags & MT_DRV_HW_MGMT_TXQ) &&
	    !(info->flags & IEEE80211_TX_CTL_HW_80211_ENCAP) &&
	    !ieee80211_is_data(hdr->frame_control) &&
	    !ieee80211_is_bufferable_mmpdu(skb)) {
		qid = MT_TXQ_PSD;
	}

	if (wcid && !(wcid->tx_info & MT_WCID_TX_INFO_SET))
		ieee80211_get_tx_rates(info->control.vif, sta, skb,
				       info->control.rates, 1);

	q = dev->q_tx[qid].q;

	spin_lock_bh(&q->lock);
	dev->queue_ops->tx_queue_skb(dev, qid, skb, wcid, sta);
	dev->queue_ops->kick(dev, q);

	if (q->queued > q->ndesc - 8 && !q->stopped) {
		ieee80211_stop_queue(dev->hw, skb_get_queue_mapping(skb));
		q->stopped = true;
	}

	spin_unlock_bh(&q->lock);
}
EXPORT_SYMBOL_GPL(mt76_tx);

static struct sk_buff *
mt76_txq_dequeue(struct mt76_dev *dev, struct mt76_txq *mtxq, bool ps)
{
	struct ieee80211_txq *txq = mtxq_to_txq(mtxq);
	struct sk_buff *skb;

	skb = skb_dequeue(&mtxq->retry_q);
	if (skb) {
		u8 tid = skb->priority & IEEE80211_QOS_CTL_TID_MASK;

		if (ps && skb_queue_empty(&mtxq->retry_q))
			ieee80211_sta_set_buffered(txq->sta, tid, false);

		return skb;
	}

	skb = ieee80211_tx_dequeue(dev->hw, txq);
	if (!skb)
		return NULL;

	return skb;
}

static void
mt76_queue_ps_skb(struct mt76_dev *dev, struct ieee80211_sta *sta,
		  struct sk_buff *skb, bool last)
{
	struct mt76_wcid *wcid = (struct mt76_wcid *)sta->drv_priv;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	info->control.flags |= IEEE80211_TX_CTRL_PS_RESPONSE;
	if (last)
		info->flags |= IEEE80211_TX_STATUS_EOSP |
			       IEEE80211_TX_CTL_REQ_TX_STATUS;

	mt76_skb_set_moredata(skb, !last);
	dev->queue_ops->tx_queue_skb(dev, MT_TXQ_PSD, skb, wcid, sta);
}

void
mt76_release_buffered_frames(struct ieee80211_hw *hw, struct ieee80211_sta *sta,
			     u16 tids, int nframes,
			     enum ieee80211_frame_release_type reason,
			     bool more_data)
{
	struct mt76_dev *dev = hw->priv;
	struct sk_buff *last_skb = NULL;
	struct mt76_queue *hwq = dev->q_tx[MT_TXQ_PSD].q;
	int i;

	spin_lock_bh(&hwq->lock);
	for (i = 0; tids && nframes; i++, tids >>= 1) {
		struct ieee80211_txq *txq = sta->txq[i];
		struct mt76_txq *mtxq = (struct mt76_txq *)txq->drv_priv;
		struct sk_buff *skb;

		if (!(tids & 1))
			continue;

		do {
			skb = mt76_txq_dequeue(dev, mtxq, true);
			if (!skb)
				break;

			nframes--;
			if (last_skb)
				mt76_queue_ps_skb(dev, sta, last_skb, false);

			last_skb = skb;
		} while (nframes);
	}

	if (last_skb) {
		mt76_queue_ps_skb(dev, sta, last_skb, true);
		dev->queue_ops->kick(dev, hwq);
	} else {
		ieee80211_sta_eosp(sta);
	}

	spin_unlock_bh(&hwq->lock);
}
EXPORT_SYMBOL_GPL(mt76_release_buffered_frames);

static int
mt76_txq_send_burst(struct mt76_dev *dev, struct mt76_sw_queue *sq,
		    struct mt76_txq *mtxq, struct mt76_wcid *wcid)
{
	struct ieee80211_txq *txq = mtxq_to_txq(mtxq);
	enum mt76_txq_id qid = mt76_txq_get_qid(txq);
	struct mt76_queue *hwq = sq->q;
	struct ieee80211_tx_info *info;
	struct sk_buff *skb;
	int n_frames = 1, limit;
	struct ieee80211_tx_rate tx_rate;
	bool ampdu;
	bool probe;
	int idx;

	if (test_bit(MT_WCID_FLAG_PS, &wcid->flags))
		return 0;

	skb = mt76_txq_dequeue(dev, mtxq, false);
	if (!skb)
		return 0;

	info = IEEE80211_SKB_CB(skb);
	if (!(wcid->tx_info & MT_WCID_TX_INFO_SET))
		ieee80211_get_tx_rates(txq->vif, txq->sta, skb,
				       info->control.rates, 1);
	tx_rate = info->control.rates[0];

	probe = (info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE);
	ampdu = IEEE80211_SKB_CB(skb)->flags & IEEE80211_TX_CTL_AMPDU;
	limit = ampdu ? 16 : 3;

	spin_lock(&hwq->lock);
	idx = dev->queue_ops->tx_queue_skb(dev, qid, skb, wcid, txq->sta);
	spin_unlock(&hwq->lock);

	if (idx < 0)
		return idx;

	do {
		bool cur_ampdu;

		if (probe)
			break;

		if (test_bit(MT76_STATE_PM, &dev->state) ||
		    test_bit(MT76_RESET, &dev->state))
			return -EBUSY;

		skb = mt76_txq_dequeue(dev, mtxq, false);
		if (!skb)
			break;

		info = IEEE80211_SKB_CB(skb);
		cur_ampdu = info->flags & IEEE80211_TX_CTL_AMPDU;

		if (ampdu != cur_ampdu ||
		    (info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE)) {
			skb_queue_tail(&mtxq->retry_q, skb);
			break;
		}

		info->control.rates[0] = tx_rate;

		spin_lock(&hwq->lock);
		idx = dev->queue_ops->tx_queue_skb(dev, qid, skb, wcid,
						   txq->sta);
		spin_unlock(&hwq->lock);

		if (idx < 0)
			return idx;

		n_frames++;
	} while (n_frames < limit);

	if (!probe) {
		hwq->entry[idx].qid = sq - dev->q_tx;
		hwq->entry[idx].schedule = true;
		sq->swq_queued++;
	}

	spin_lock(&hwq->lock);
	dev->queue_ops->kick(dev, hwq);
	spin_unlock(&hwq->lock);

	return n_frames;
}

static int
mt76_txq_schedule_list(struct mt76_dev *dev, enum mt76_txq_id qid)
{
	struct mt76_sw_queue *sq = &dev->q_tx[qid];	
	struct ieee80211_txq *txq;
	struct mt76_txq *mtxq;
	struct mt76_wcid *wcid;
	int ret = 0;

	while (1) {
		int n_frames = 0;

		if (sq->swq_queued >= 4)
			break;

		if (test_bit(MT76_STATE_PM, &dev->state) ||
		    test_bit(MT76_RESET, &dev->state))
			return -EBUSY;

		txq = ieee80211_next_txq(dev->hw, qid);
		if (!txq)
			break;

		mtxq = (struct mt76_txq *)txq->drv_priv;
		wcid = rcu_dereference(dev->wcid[mtxq->wcid]);
		if (!wcid || test_bit(MT_WCID_FLAG_PS, &wcid->flags))
			continue;

		if (mtxq->send_bar && mtxq->aggr) {
			struct ieee80211_txq *txq = mtxq_to_txq(mtxq);
			struct ieee80211_sta *sta = txq->sta;
			struct ieee80211_vif *vif = txq->vif;
			u16 agg_ssn = mtxq->agg_ssn;
			u8 tid = txq->tid;

			mtxq->send_bar = false;
			ieee80211_send_bar(vif, sta->addr, tid, agg_ssn);
		}		

		n_frames = mt76_txq_send_burst(dev, sq, mtxq, wcid);

		ieee80211_return_txq(dev->hw, txq,
				     !skb_queue_empty(&mtxq->retry_q));

		if (unlikely(n_frames < 0))
			return n_frames;

		ret += n_frames;
	}

	return ret;
}

void mt76_txq_schedule(struct mt76_dev *dev, enum mt76_txq_id qid)
{
	struct mt76_sw_queue *sq = &dev->q_tx[qid];
	int len;

	if (qid >= 4)
		return;

	if (sq->swq_queued >= 4)
		return;

	local_bh_disable();
	rcu_read_lock();

	do {
		ieee80211_txq_schedule_start(dev->hw, qid);
		len = mt76_txq_schedule_list(dev, qid);
		ieee80211_txq_schedule_end(dev->hw, qid);
	} while (len > 0);

	rcu_read_unlock();
	local_bh_enable();
}
EXPORT_SYMBOL_GPL(mt76_txq_schedule);

void mt76_txq_schedule_all(struct mt76_dev *dev)
{
	int i;

	for (i = 0; i <= MT_TXQ_BK; i++)
		mt76_txq_schedule(dev, i);
}
EXPORT_SYMBOL_GPL(mt76_txq_schedule_all);

void mt76_tx_worker(struct mt76_worker *w)
{
	struct mt76_dev *dev = container_of(w, struct mt76_dev, tx_worker);

	mt76_txq_schedule_all(dev);
}

void mt76_stop_tx_queues(struct mt76_dev *dev, struct ieee80211_sta *sta,
			 bool send_bar)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sta->txq); i++) {
		struct ieee80211_txq *txq = sta->txq[i];
		struct mt76_queue *hwq;
		struct mt76_txq *mtxq;

		if (!txq)
			continue;

		mtxq = (struct mt76_txq *)txq->drv_priv;
		hwq = mtxq->swq->q;

		spin_lock_bh(&hwq->lock);
		mtxq->send_bar = mtxq->aggr && send_bar;
		spin_unlock_bh(&hwq->lock);
	}
}
EXPORT_SYMBOL_GPL(mt76_stop_tx_queues);

void mt76_wake_tx_queue(struct ieee80211_hw *hw, struct ieee80211_txq *txq)
{
	struct mt76_dev *dev = hw->priv;

	if (!test_bit(MT76_STATE_RUNNING, &dev->state))
		return;

	mt76_worker_schedule(&dev->tx_worker);
}
EXPORT_SYMBOL_GPL(mt76_wake_tx_queue);

void mt76_txq_remove(struct mt76_dev *dev, struct ieee80211_txq *txq)
{
	struct mt76_txq *mtxq;
	struct sk_buff *skb;

	if (!txq)
		return;

	mtxq = (struct mt76_txq *)txq->drv_priv;

	while ((skb = skb_dequeue(&mtxq->retry_q)) != NULL)
		ieee80211_free_txskb(dev->hw, skb);
}
EXPORT_SYMBOL_GPL(mt76_txq_remove);

void mt76_txq_init(struct mt76_dev *dev, struct ieee80211_txq *txq)
{
	struct mt76_txq *mtxq = (struct mt76_txq *)txq->drv_priv;

	skb_queue_head_init(&mtxq->retry_q);

	mtxq->swq = &dev->q_tx[mt76_txq_get_qid(txq)];
}
EXPORT_SYMBOL_GPL(mt76_txq_init);

u8 mt76_ac_to_hwq(u8 ac)
{
	static const u8 wmm_queue_map[] = {
		[IEEE80211_AC_BE] = 0,
		[IEEE80211_AC_BK] = 1,
		[IEEE80211_AC_VI] = 2,
		[IEEE80211_AC_VO] = 3,
	};

	if (WARN_ON(ac >= IEEE80211_NUM_ACS))
		return 0;

	return wmm_queue_map[ac];
}
EXPORT_SYMBOL_GPL(mt76_ac_to_hwq);

int mt76_skb_adjust_pad(struct sk_buff *skb, int pad)
{
	struct sk_buff *iter, *last = skb;

	/* First packet of a A-MSDU burst keeps track of the whole burst
	 * length, need to update length of it and the last packet.
	 */
	skb_walk_frags(skb, iter) {
		last = iter;
		if (!iter->next) {
			skb->data_len += pad;
			skb->len += pad;
			break;
		}
	}

	if (skb_pad(last, pad))
		return -ENOMEM;

	__skb_put(last, pad);

	return 0;
}
EXPORT_SYMBOL_GPL(mt76_skb_adjust_pad);
