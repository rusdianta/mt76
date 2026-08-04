// SPDX-License-Identifier: ISC
/*
 * Copyright (C) 2019 Felix Fietkau <nbd@nbd.name>
 */

#include "mt76.h"

#define AVG_PKT_SIZE	1024

#define DIV_ROUND_UP_U64(n, d)				\
({							\
	u64 __n = (n);					\
	u32 __d = (d);					\
	__n += __d - 1;					\
	do_div(__n, __d);				\
	__n;						\
})

/* Number of bits for an average sized packet */
#define MCS_NBITS (AVG_PKT_SIZE << 3)

/* Number of symbols for a packet with (bps) bits per symbol */
#define MCS_NSYMS(bps) DIV_ROUND_UP(MCS_NBITS, (bps))

/* Transmission time (1024 usec) for a packet containing (syms) * symbols */
#define MCS_SYMBOL_TIME(sgi, syms)					\
	(sgi ?								\
	  ((syms) * 18 * 1024 + 4 * 1024) / 5 :	/* syms * 3.6 us */	\
	  ((syms) * 1024) << 2			/* syms * 4 us */	\
	)

/* Transmit duration for the raw data part of an average sized packet */
#define MCS_DURATION(streams, sgi, bps) \
	MCS_SYMBOL_TIME(sgi, MCS_NSYMS((streams) * (bps)))

#define BW_20			0
#define BW_40			1

/*
 * Define group sort order: HT40 -> SGI -> #streams
 */
#define MT_MAX_STREAMS		2
#define MT_HT_STREAM_GROUPS	4 /* BW(=2) * SGI(=2) */

#define MT_HT_GROUP_0	0

#define MCS_GROUP_RATES		8

#define MT_MAX_HT_MCS	(MT_MAX_STREAMS * MCS_GROUP_RATES)

#define HT_GROUP_IDX(_streams, _sgi, _ht40)	\
	MT_HT_GROUP_0 +			\
	MT_MAX_STREAMS * 2 * _ht40 +	\
	MT_MAX_STREAMS * _sgi +	\
	_streams - 1

#define _MAX(a, b) (((a)>(b))?(a):(b))

#define GROUP_SHIFT(duration)						\
	_MAX(0, 16 - __builtin_clz(duration))

/* MCS rate information for an MCS group */
#define __MCS_GROUP(_streams, _sgi, _ht40, _s)				\
	[HT_GROUP_IDX(_streams, _sgi, _ht40)] = {			\
	.shift = _s,							\
	.duration = {							\
		MCS_DURATION(_streams, _sgi, _ht40 ? 54 : 26) >> _s,	\
		MCS_DURATION(_streams, _sgi, _ht40 ? 108 : 52) >> _s,	\
		MCS_DURATION(_streams, _sgi, _ht40 ? 162 : 78) >> _s,	\
		MCS_DURATION(_streams, _sgi, _ht40 ? 216 : 104) >> _s,	\
		MCS_DURATION(_streams, _sgi, _ht40 ? 324 : 156) >> _s,	\
		MCS_DURATION(_streams, _sgi, _ht40 ? 432 : 208) >> _s,	\
		MCS_DURATION(_streams, _sgi, _ht40 ? 486 : 234) >> _s,	\
		MCS_DURATION(_streams, _sgi, _ht40 ? 540 : 260) >> _s	\
	}								\
}

#define MCS_GROUP_SHIFT(_streams, _sgi, _ht40)				\
	GROUP_SHIFT(MCS_DURATION(_streams, _sgi, _ht40 ? 54 : 26))

#define MCS_GROUP(_streams, _sgi, _ht40)				\
	__MCS_GROUP(_streams, _sgi, _ht40,				\
		    MCS_GROUP_SHIFT(_streams, _sgi, _ht40))

struct mcs_group {
	u8 shift;
	u16 duration[MCS_GROUP_RATES];
};

static const struct mcs_group airtime_mcs_groups[] = {
	MCS_GROUP(1, 0, BW_20),
	MCS_GROUP(2, 0, BW_20),

	MCS_GROUP(1, 1, BW_20),
	MCS_GROUP(2, 1, BW_20),

	MCS_GROUP(1, 0, BW_40),
	MCS_GROUP(2, 0, BW_40),

	MCS_GROUP(1, 1, BW_40),
	MCS_GROUP(2, 1, BW_40),
};

enum mt76_phy_encoding {
	MT76_PHY_LEGACY,
	MT76_PHY_HT,
};

static u32
mt76_calc_legacy_rate_duration(const struct ieee80211_rate *rate, bool short_pre,
			       int len)
{
	u64 duration;

	if (!rate->bitrate)
		return 0;

	switch (rate->hw_value >> 8) {
	case MT_PHY_TYPE_CCK:
		duration = 144 + 48; /* preamble + PLCP */
		if (short_pre)
			duration >>= 1;

		duration += 10; /* SIFS */
		break;
	case MT_PHY_TYPE_OFDM:
		duration = 20 + 16; /* preamble + SIFS */
		break;
	default:
		WARN_ON_ONCE(1);
		return 0;
	}

	duration += DIV_ROUND_UP_U64((u64)len * 80, rate->bitrate);

	return (u32)min_t(u64, duration, U32_MAX);
}

static u32
mt76_calc_airtime(struct mt76_dev *dev, enum mt76_phy_encoding encoding, u8 band,
		  int bw, bool sgi, bool sp, int rate_idx, int len)
{
	const struct ieee80211_rate *rate;
	const struct mcs_group *g;
	struct ieee80211_supported_band *sband;
	u64 duration;
	int streams;
	int group;
	int idx;

	if (unlikely(len <= 0 || rate_idx < 0))
    	return 0;

	switch (encoding) {
	case MT76_PHY_LEGACY:
		if (WARN_ON_ONCE(band > NL80211_BAND_5GHZ))
			return 0;

		sband = dev->hw->wiphy->bands[band];
		if (!sband || rate_idx >= sband->n_bitrates)
			return 0;

		rate = &sband->bitrates[rate_idx];

		return mt76_calc_legacy_rate_duration(rate, sp, len);
	case MT76_PHY_HT:
		if (rate_idx >= MT_MAX_HT_MCS)
			return 0;

		streams = (rate_idx >> 3) + 1;

		if (streams > MT_MAX_STREAMS)
			return 0;
		
		idx = rate_idx & 7;
		group = HT_GROUP_IDX(streams, sgi, bw);
		break;
	default:
		WARN_ON_ONCE(1);
		return 0;
	}

	if (WARN_ON_ONCE(streams > MT_MAX_STREAMS))
		return 0;

	if (unlikely(group < 0 || group >= ARRAY_SIZE(airtime_mcs_groups)))
		return 0;

	g = &airtime_mcs_groups[group];

	duration = (u64)g->duration[idx] << g->shift;
	duration = DIV_ROUND_UP_U64(duration * len, AVG_PKT_SIZE << 10);	

	duration += 36 + (streams << 2);

	return (u32)min_t(u64, duration, U32_MAX);
}

u32 mt76_calc_rx_airtime(struct mt76_dev *dev, struct mt76_rx_status *status,
			 int len)
{
	int bw;

	switch (status->bw) {
	case RATE_INFO_BW_20:
		bw = BW_20;
		break;
	case RATE_INFO_BW_40:
		bw = BW_40;
		break;
	default:
		WARN_ON_ONCE(1);
		return 0;
	}

	return mt76_calc_airtime(dev, status->encoding, status->band, bw,
				 status->enc_flags & RX_ENC_FLAG_SHORT_GI,
				 status->enc_flags & RX_ENC_FLAG_SHORTPRE,
				 status->rate_idx, len);
}

u32 mt76_calc_tx_airtime(struct mt76_dev *dev, struct ieee80211_tx_info *info,
			 int len)
{
	u64 duration = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(info->status.rates); i++) {
		struct ieee80211_tx_rate *rate;
		enum mt76_phy_encoding encoding;
		bool sgi = false;
		bool sp = false;
		int bw;
		int rate_idx;
		u64 cur_duration;

		rate = &info->status.rates[i];

		if (rate->idx < 0 || !rate->count)
			break;

		if (rate->flags & IEEE80211_TX_RC_40_MHZ_WIDTH)
			bw = BW_40;
		else
			bw = BW_20;

		sp = rate->flags & IEEE80211_TX_RC_USE_SHORT_PREAMBLE;
		sgi = rate->flags & IEEE80211_TX_RC_SHORT_GI;
		rate_idx = rate->idx;

		if (rate->flags & IEEE80211_TX_RC_MCS) {
			encoding = MT76_PHY_HT;
		} else {
			encoding = MT76_PHY_LEGACY;
		}

		cur_duration = mt76_calc_airtime(dev, encoding, info->band, bw,
					sgi, sp, rate_idx, len);
		duration += cur_duration * rate->count;
	}

	return (u32)min_t(u64, duration, U32_MAX);
}
EXPORT_SYMBOL_GPL(mt76_calc_tx_airtime);
