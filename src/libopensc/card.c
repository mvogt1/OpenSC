/*
 * card.c: General smart card functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <limits.h>
#include <time.h>

#include "reader-tr03119.h"
#include "internal.h"
#include "asn1.h"
#include "common/compat_strlcpy.h"

#ifdef ENABLE_SM
static int sc_card_sm_load(sc_card_t *card, const char *path, const char *module);
static int sc_card_sm_unload(sc_card_t *card);
static int sc_card_sm_check(sc_card_t *card);
#endif

int sc_check_sw(sc_card_t *card, unsigned int sw1, unsigned int sw2)
{
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ops->check_sw == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	return card->ops->check_sw(card, sw1, sw2);
}

void sc_format_apdu(sc_card_t *card, sc_apdu_t *apdu,
		    int cse, int ins, int p1, int p2)
{
	if (card == NULL || apdu == NULL) {
		return;
	}
	memset(apdu, 0, sizeof(*apdu));
	apdu->cla = (u8) card->cla;
	apdu->cse = cse;
	apdu->ins = (u8) ins;
	apdu->p1 = (u8) p1;
	apdu->p2 = (u8) p2;
}

void sc_format_apdu_cse_lc_le(struct sc_apdu *apdu)
{
	/* TODO calculating the APDU case, Lc and Le should actually only be
	 * done in sc_apdu2bytes, but to gradually change OpenSC we start here. */
	/* Let sc_detect_apdu_cse set short or extended  and test for chaining */

	if (!apdu)
		return;
	if (apdu->datalen > SC_MAX_APDU_DATA_SIZE
			|| apdu->resplen > SC_MAX_APDU_RESP_SIZE) {
		/* extended length  or data chaining and/or get response */
		if (apdu->datalen <= SC_MAX_EXT_APDU_DATA_SIZE)
			apdu->lc = apdu->datalen;
		if (apdu->resplen <= SC_MAX_EXT_APDU_RESP_SIZE)
			apdu->le = apdu->resplen;
		if (apdu->resplen && !apdu->datalen)
			apdu->cse = SC_APDU_CASE_2;
		if (!apdu->resplen && apdu->datalen)
			apdu->cse = SC_APDU_CASE_3;
		if (apdu->resplen && apdu->datalen)
			apdu->cse = SC_APDU_CASE_4;
	} else {
		/* short length */
		if (apdu->datalen <= SC_MAX_APDU_DATA_SIZE)
			apdu->lc = apdu->datalen;
		if (apdu->resplen <= SC_MAX_APDU_RESP_SIZE)
			apdu->le = apdu->resplen;
		if (!apdu->resplen && !apdu->datalen)
			apdu->cse = SC_APDU_CASE_1;
		if (apdu->resplen && !apdu->datalen)
			apdu->cse = SC_APDU_CASE_2_SHORT;
		if (!apdu->resplen && apdu->datalen)
			apdu->cse = SC_APDU_CASE_3_SHORT;
		if (apdu->resplen && apdu->datalen)
			apdu->cse = SC_APDU_CASE_4_SHORT;
	}
}

void sc_format_apdu_ex(struct sc_apdu *apdu,
		u8 cla, u8 ins, u8 p1, u8 p2,
		const u8 *data, size_t datalen,
		u8 *resp, size_t resplen)
{
	if (!apdu) {
		return;
	}

	memset(apdu, 0, sizeof(*apdu));
	apdu->cla = cla;
	apdu->ins = ins;
	apdu->p1 = p1;
	apdu->p2 = p2;
	apdu->resp = resp;
	apdu->resplen = resplen;
	apdu->data = data;
	apdu->datalen = datalen;
	sc_format_apdu_cse_lc_le(apdu);
}

static sc_card_t * sc_card_new(sc_context_t *ctx)
{
	sc_card_t *card;

	if (ctx == NULL)
		return NULL;

	card = calloc(1, sizeof(struct sc_card));
	if (card == NULL)
		return NULL;
	card->ops = malloc(sizeof(struct sc_card_operations));
	if (card->ops == NULL) {
		free(card);
		return NULL;
	}

	card->ctx = ctx;
	if (sc_mutex_create(ctx, &card->mutex) != SC_SUCCESS) {
		free(card->ops);
		free(card);
		return NULL;
	}

	card->type = -1;
	card->app_count = -1;

	return card;
}

static void sc_card_free(sc_card_t *card)
{
	sc_free_apps(card);
	sc_free_ef_atr(card);

	free(card->ops);

	if (card->algorithms != NULL)   {
		int i;
		for (i=0; i<card->algorithm_count; i++)   {
			struct sc_algorithm_info *info = (card->algorithms + i);
			if (info->algorithm == SC_ALGORITHM_EC ||
					info->algorithm == SC_ALGORITHM_EDDSA ||
					info->algorithm == SC_ALGORITHM_XEDDSA) {
				sc_clear_ec_params(&info->u._ec.params);
			}
		}
		free(card->algorithms);

		card->algorithms = NULL;
		card->algorithm_count = 0;
	}

#ifdef SC_LOCK_STATS
	free(card->lock_stats);
#endif
	if (card->mutex != NULL) {
		int r = sc_mutex_destroy(card->ctx, card->mutex);
		if (r != SC_SUCCESS)
			sc_log(card->ctx, "unable to destroy mutex");
	}
	sc_mem_clear(card, sizeof(*card));
	free(card);
}

size_t sc_get_max_recv_size(const sc_card_t *card)
{
	size_t max_recv_size;
	if (card == NULL || card->reader == NULL) {
		return 0;
	}
	max_recv_size = card->max_recv_size;

	/* initialize max_recv_size to a meaningful value */
	if (card->caps & SC_CARD_CAP_APDU_EXT) {
		if (!max_recv_size)
			max_recv_size = 65536;
	} else {
		if (!max_recv_size)
			max_recv_size = 256;
	}

	/*  Override card limitations with reader limitations. */
	if (card->reader->max_recv_size != 0
			&& (card->reader->max_recv_size < card->max_recv_size))
		max_recv_size = card->reader->max_recv_size;

	return max_recv_size;
}

size_t sc_get_max_send_size(const sc_card_t *card)
{
	size_t max_send_size;

	if (card == NULL || card->reader == NULL) {
		return 0;
	}

	max_send_size = card->max_send_size;

	/* initialize max_send_size to a meaningful value */
	if (card->caps & SC_CARD_CAP_APDU_EXT
			&& card->reader->active_protocol != SC_PROTO_T0) {
		if (!max_send_size)
			max_send_size = 65535;
	} else {
		if (!max_send_size)
			max_send_size = 255;
	}

	/*  Override card limitations with reader limitations. */
	if (card->reader->max_send_size != 0
			&& (card->reader->max_send_size < card->max_send_size))
		max_send_size = card->reader->max_send_size;

	return max_send_size;
}

int sc_connect_card(sc_reader_t *reader, sc_card_t **card_out)
{
	sc_card_t *card;
	sc_context_t *ctx;
	struct sc_card_driver *driver;
	int i, r = 0, idx, connected = 0;

	if (card_out == NULL || reader == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = reader->ctx;
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (reader->ops->connect == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	card = sc_card_new(ctx);
	if (card == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	r = reader->ops->connect(reader);
	if (r)
		goto err;

	connected = 1;
	card->reader = reader;
	card->ctx = ctx;

	if (reader->flags & SC_READER_ENABLE_ESCAPE)
		sc_detect_escape_cmds(reader);

	memcpy(&card->atr, &reader->atr, sizeof(card->atr));
	memcpy(&card->uid, &reader->uid, sizeof(card->uid));

	_sc_parse_atr(reader);

	/* See if the ATR matches any ATR specified in the config file */
	if ((driver = ctx->forced_driver) == NULL) {
		sc_log(ctx, "matching configured ATRs");
		for (i = 0; ctx->card_drivers[i] != NULL; i++) {
			driver = ctx->card_drivers[i];

			if (driver->atr_map == NULL ||
			    !strcmp(driver->short_name, "default")) {
				driver = NULL;
				continue;
			}
			sc_log(ctx, "trying driver '%s'", driver->short_name);
			idx = _sc_match_atr(card, driver->atr_map, NULL);
			if (idx >= 0) {
				struct sc_atr_table *src = &driver->atr_map[idx];

				sc_log(ctx, "matched driver '%s'", driver->name);
				/* It's up to card driver to notice these correctly */
				card->name = src->name;
				card->type = src->type;
				card->flags = src->flags;
				break;
			}
			driver = NULL;
		}
	}

	if (driver != NULL) {
		/* Forced driver, or matched via ATR mapping from config file */
		card->driver = driver;

		memcpy(card->ops, card->driver->ops, sizeof(struct sc_card_operations));
		if (card->ops->match_card != NULL)
			if (card->ops->match_card(card) != 1)
				sc_log(ctx, "driver '%s' match_card() failed: %s (will continue anyway)", card->driver->name, sc_strerror(r));

		if (card->ops->init != NULL) {
			r = card->ops->init(card);
			if (r) {
				sc_log(ctx, "driver '%s' init() failed: %s", card->driver->name, sc_strerror(r));
				goto err;
			}
		}
	}
	else {
		sc_card_t uninitialized = *card;
		sc_log(ctx, "matching built-in ATRs");
		for (i = 0; ctx->card_drivers[i] != NULL; i++) {
			/* FIXME If we had a clean API description, we'd probably get a
			 * cleaner implementation of the driver's match_card and init,
			 * which should normally *not* modify the card object if
			 * unsuccessful. However, after years of relentless hacking, reality
			 * is different: The card object is changed in virtually every card
			 * driver so in order to prevent unwanted interaction, we reset the
			 * card object here and hope that the card driver at least doesn't
			 * allocate any internal resources that need to be freed. If we
			 * had more time, we should refactor the existing code to not
			 * modify sc_card_t until complete success (possibly by combining
			 * `match_card()` and `init()`) */
			*card = uninitialized;

			struct sc_card_driver *drv = ctx->card_drivers[i];
			const struct sc_card_operations *ops = drv->ops;

			sc_log(ctx, "trying driver '%s'", drv->short_name);
			if (ops == NULL || ops->match_card == NULL)   {
				continue;
			}
			else if (!(ctx->flags & SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER)
				   	&& !strcmp("default", drv->short_name))   {
				sc_log(ctx , "ignore 'default' card driver");
				continue;
			}

			/* Needed if match_card() needs to talk with the card (e.g. card-muscle) */
			*card->ops = *ops;
			if (ops->match_card(card) != 1)
				continue;
			sc_log(ctx, "matched: %s", drv->name);
			memcpy(card->ops, ops, sizeof(struct sc_card_operations));
			card->driver = drv;
			r = ops->init(card);
			if (r) {
				sc_log(ctx, "driver '%s' init() failed: %s", drv->name, sc_strerror(r));
				if (r == SC_ERROR_INVALID_CARD) {
					card->driver = NULL;
					continue;
				}
				goto err;
			}
			break;
		}
	}
	if (card->driver == NULL) {
		sc_log(ctx, "unable to find driver for inserted card");
		r = SC_ERROR_INVALID_CARD;
		goto err;
	}
	if (card->name == NULL)
		card->name = card->driver->name;

	/* initialize max_send_size/max_recv_size to a meaningful value */
	card->max_recv_size = sc_get_max_recv_size(card);
	card->max_send_size = sc_get_max_send_size(card);

	sc_log(ctx, "card info name:'%s', type:%i, flags:0x%lX, max_send/recv_size:%zu/%zu",
			card->name, card->type, card->flags, card->max_send_size, card->max_recv_size);

#ifdef ENABLE_SM
	/* Check, if secure messaging module present. */
	r = sc_card_sm_check(card);
	if (r)   {
		sc_log(ctx, "cannot load secure messaging module");
		goto err;
	}
#endif
	*card_out = card;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
err:
	if (connected)
		reader->ops->disconnect(reader);
	if (card != NULL)
		sc_card_free(card);
	LOG_FUNC_RETURN(ctx, r);
}

int sc_disconnect_card(sc_card_t *card)
{
	sc_context_t *ctx;

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);

	if (card->ops->finish) {
		int r = card->ops->finish(card);
		if (r)
			sc_log(ctx, "card driver finish() failed: %s", sc_strerror(r));
	}

	if (card->reader->ops->disconnect) {
		int r = card->reader->ops->disconnect(card->reader);
		if (r)
			sc_log(ctx, "disconnect() failed: %s", sc_strerror(r));
	}

#ifdef ENABLE_SM
	/* release SM related resources */
	sc_card_sm_unload(card);
#endif

	sc_card_free(card);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int sc_reset(sc_card_t *card, int do_cold_reset)
{
	int r, r2;

	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->reader->ops->reset == NULL)
		return SC_ERROR_NOT_SUPPORTED;

	r = sc_mutex_lock(card->ctx, card->mutex);
	if (r != SC_SUCCESS)
		return r;

	r = card->reader->ops->reset(card->reader, do_cold_reset);

	r2 = sc_mutex_unlock(card->ctx, card->mutex);
	if (r2 != SC_SUCCESS) {
		sc_log(card->ctx, "unable to release lock");
		r = r != SC_SUCCESS ? r : r2;
	}

	return r;
}

#ifdef SC_LOCK_STATS
/* Lock statistics per sc_lock() call site. A section is the time between
 * sc_lock() and the matching sc_unlock(). Only outermost sections lock the
 * reader (e.g. SCardBeginTransaction), nested ones just count. */

#define SC_LOCK_STATS_DEPTH 16

struct sc_lock_site {
	const char *file;
	const char *func;
	unsigned long outer;		/* outermost sections */
	unsigned long outer_no_apdu;	/* ... without any APDU */
	unsigned long apdus;		/* APDUs in outermost sections */
	uint64_t acquire_ns, acquire_max_ns; /* time in sc_lock() */
	uint64_t held_ns, held_max_ns;	/* time between lock and unlock */
	unsigned long nested;		/* nested sections */
	uint64_t nested_held_ns;
	unsigned long lock_failed;
	unsigned long unlock_elsewhere;	/* unlocked in another function */
	unsigned long unlock_unmatched;	/* unlock without lock */
};

/* Gap between an outermost unlock and the next outermost lock */
struct sc_lock_gap {
	const char *unlock_file, *unlock_func;
	const char *lock_file, *lock_func;
	unsigned long count;
	uint64_t gap_ns, gap_min_ns, gap_max_ns;
};

struct sc_lock_stats {
	void *mutex;
	struct sc_lock_site *sites;
	size_t site_count, site_cap;
	struct sc_lock_gap *gaps;
	size_t gap_count, gap_cap;
	unsigned long apdus_unlocked;
};

struct sc_lock_frame {
	const char *file, *func;
	uint64_t locked_ns;
	int outer;
};

struct sc_lock_card_stats {
	struct sc_lock_frame frames[SC_LOCK_STATS_DEPTH];
	int depth;
	unsigned long apdus;		/* APDUs in the current outermost section */
	const char *unlock_file, *unlock_func; /* last outermost unlock */
	uint64_t unlock_ns;
};

static uint64_t lock_stats_now(void)
{
#ifdef _WIN32
	LARGE_INTEGER freq, count;

	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&count);
	return (uint64_t)(count.QuadPart / freq.QuadPart) * 1000000000ULL +
	       (uint64_t)(count.QuadPart % freq.QuadPart) * 1000000000ULL / (uint64_t)freq.QuadPart;
#else
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static const char *lock_stats_basename(const char *file)
{
	const char *p;

	if (file == NULL)
		return "?";
	if ((p = strrchr(file, '/')) != NULL)
		file = p + 1;
	if ((p = strrchr(file, '\\')) != NULL)
		file = p + 1;
	return file;
}

static int lock_stats_same(const char *file1, const char *func1, const char *file2, const char *func2)
{
	return (file1 == file2 || strcmp(file1, file2) == 0) && (func1 == func2 || strcmp(func1, func2) == 0);
}

/* Call with st->mutex held */
static struct sc_lock_site *lock_stats_site(struct sc_lock_stats *st, const char *file, const char *func)
{
	struct sc_lock_site *site;
	size_t i;

	for (i = 0; i < st->site_count; i++)
		if (lock_stats_same(st->sites[i].file, st->sites[i].func, file, func))
			return &st->sites[i];
	if (st->site_count == st->site_cap) {
		size_t cap = st->site_cap ? 2 * st->site_cap : 64;
		site = realloc(st->sites, cap * sizeof(*site));
		if (site == NULL)
			return NULL;
		st->sites = site;
		st->site_cap = cap;
	}
	site = &st->sites[st->site_count++];
	memset(site, 0, sizeof(*site));
	site->file = file;
	site->func = func;
	return site;
}

/* Call with st->mutex held */
static struct sc_lock_gap *lock_stats_gap(struct sc_lock_stats *st,
		const char *unlock_file, const char *unlock_func,
		const char *lock_file, const char *lock_func)
{
	struct sc_lock_gap *gap;
	size_t i;

	for (i = 0; i < st->gap_count; i++) {
		gap = &st->gaps[i];
		if (lock_stats_same(gap->unlock_file, gap->unlock_func, unlock_file, unlock_func) &&
				lock_stats_same(gap->lock_file, gap->lock_func, lock_file, lock_func))
			return gap;
	}
	if (st->gap_count == st->gap_cap) {
		size_t cap = st->gap_cap ? 2 * st->gap_cap : 64;
		gap = realloc(st->gaps, cap * sizeof(*gap));
		if (gap == NULL)
			return NULL;
		st->gaps = gap;
		st->gap_cap = cap;
	}
	gap = &st->gaps[st->gap_count++];
	memset(gap, 0, sizeof(*gap));
	gap->unlock_file = unlock_file;
	gap->unlock_func = unlock_func;
	gap->lock_file = lock_file;
	gap->lock_func = lock_func;
	return gap;
}

/* Called from sc_lock_at() with card->mutex held */
static void lock_stats_locked(sc_card_t *card, const char *file, const char *func, int r, uint64_t start)
{
	struct sc_lock_stats *st = card->ctx->lock_stats;
	struct sc_lock_card_stats *cs;
	struct sc_lock_site *site;
	struct sc_lock_frame *frame;
	struct sc_lock_gap *gap;
	uint64_t now, d;
	int outer;

	if (st == NULL)
		return;
	if (card->lock_stats == NULL && (card->lock_stats = calloc(1, sizeof(*card->lock_stats))) == NULL)
		return;
	cs = card->lock_stats;
	now = lock_stats_now();
	file = lock_stats_basename(file);
	outer = r == SC_SUCCESS && card->lock_count == 1;

	sc_mutex_lock(card->ctx, st->mutex);
	site = lock_stats_site(st, file, func);
	if (r != SC_SUCCESS) {
		if (site)
			site->lock_failed++;
		goto out;
	}
	if (outer) {
		/* frames left over from unbalanced lock_count changes */
		cs->depth = 0;
		cs->apdus = 0;
		if (site) {
			d = now - start;
			site->outer++;
			site->acquire_ns += d;
			if (d > site->acquire_max_ns)
				site->acquire_max_ns = d;
		}
		if (cs->unlock_func != NULL &&
				(gap = lock_stats_gap(st, cs->unlock_file, cs->unlock_func, file, func)) != NULL) {
			d = start > cs->unlock_ns ? start - cs->unlock_ns : 0;
			if (gap->count == 0 || d < gap->gap_min_ns)
				gap->gap_min_ns = d;
			if (d > gap->gap_max_ns)
				gap->gap_max_ns = d;
			gap->gap_ns += d;
			gap->count++;
		}
	} else if (site) {
		site->nested++;
	}
	if (cs->depth < SC_LOCK_STATS_DEPTH) {
		frame = &cs->frames[cs->depth];
		frame->file = file;
		frame->func = func;
		frame->locked_ns = now;
		frame->outer = outer;
	}
	cs->depth++;
out:
	sc_mutex_unlock(card->ctx, st->mutex);
}

/* Called from sc_unlock_at() with card->mutex held */
static void lock_stats_unlocked(sc_card_t *card, const char *file, const char *func, int unmatched, uint64_t start)
{
	struct sc_lock_stats *st = card->ctx->lock_stats;
	struct sc_lock_card_stats *cs = card->lock_stats;
	struct sc_lock_site *site;
	struct sc_lock_frame *frame;
	uint64_t now, d;

	if (st == NULL)
		return;
	now = lock_stats_now();
	file = lock_stats_basename(file);

	sc_mutex_lock(card->ctx, st->mutex);
	if (unmatched || cs == NULL || cs->depth == 0) {
		if ((site = lock_stats_site(st, file, func)) != NULL)
			site->unlock_unmatched++;
		goto out;
	}
	cs->depth--;
	if (cs->depth >= SC_LOCK_STATS_DEPTH)
		goto out;
	frame = &cs->frames[cs->depth];
	if ((site = lock_stats_site(st, frame->file, frame->func)) == NULL)
		goto out;
	if (!lock_stats_same(frame->file, frame->func, file, func))
		site->unlock_elsewhere++;
	d = start > frame->locked_ns ? start - frame->locked_ns : 0;
	if (frame->outer) {
		site->held_ns += d;
		if (d > site->held_max_ns)
			site->held_max_ns = d;
		site->apdus += cs->apdus;
		if (cs->apdus == 0)
			site->outer_no_apdu++;
	} else {
		site->nested_held_ns += d;
	}
	if (card->lock_count == 0) {
		cs->unlock_file = file;
		cs->unlock_func = func;
		cs->unlock_ns = now;
	}
out:
	sc_mutex_unlock(card->ctx, st->mutex);
}

void sc_lock_stats_apdu(sc_card_t *card)
{
	struct sc_lock_stats *st = card->ctx->lock_stats;

	if (st == NULL)
		return;
	if (card->lock_stats != NULL && card->lock_stats->depth > 0) {
		card->lock_stats->apdus++;
	} else {
		sc_mutex_lock(card->ctx, st->mutex);
		st->apdus_unlocked++;
		sc_mutex_unlock(card->ctx, st->mutex);
	}
}

int sc_lock_stats_init(sc_context_t *ctx)
{
	const char *env = getenv("OPENSC_LOCK_STATS");
	struct sc_lock_stats *st;
	int r;

	if (env == NULL || *env == '\0')
		return SC_SUCCESS;
	if ((st = calloc(1, sizeof(*st))) == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	r = sc_mutex_create(ctx, &st->mutex);
	if (r != SC_SUCCESS) {
		free(st);
		return r;
	}
	ctx->lock_stats = st;
	return SC_SUCCESS;
}

void sc_lock_stats_free(sc_context_t *ctx)
{
	struct sc_lock_stats *st = ctx->lock_stats;

	if (st == NULL)
		return;
	sc_mutex_destroy(ctx, st->mutex);
	free(st->sites);
	free(st->gaps);
	free(st);
	ctx->lock_stats = NULL;
}

static double lock_stats_ms(uint64_t ns)
{
	return (double)ns / 1e6;
}

static int lock_stats_cmp_site(const void *a, const void *b)
{
	const struct sc_lock_site *s1 = *(const struct sc_lock_site *const *)a;
	const struct sc_lock_site *s2 = *(const struct sc_lock_site *const *)b;
	uint64_t t1 = s1->acquire_ns + s1->held_ns, t2 = s2->acquire_ns + s2->held_ns;

	if (t1 != t2)
		return t1 < t2 ? 1 : -1;
	if (s1->outer != s2->outer)
		return s1->outer < s2->outer ? 1 : -1;
	return s1->nested < s2->nested ? 1 : s1->nested > s2->nested ? -1 : 0;
}

static int lock_stats_cmp_gap(const void *a, const void *b)
{
	const struct sc_lock_gap *g1 = *(const struct sc_lock_gap *const *)a;
	const struct sc_lock_gap *g2 = *(const struct sc_lock_gap *const *)b;

	if (g1->count != g2->count)
		return g1->count < g2->count ? 1 : -1;
	return g1->gap_ns > g2->gap_ns ? 1 : g1->gap_ns < g2->gap_ns ? -1 : 0;
}

static void lock_stats_write(FILE *f, sc_context_t *ctx, struct sc_lock_stats *st)
{
	const struct sc_lock_site **sites = NULL;
	const struct sc_lock_gap **gaps = NULL;
	unsigned long outer = 0, no_apdu = 0, apdus = 0;
	uint64_t acquire = 0, held = 0;
	size_t i;

	if (st->site_count && (sites = malloc(st->site_count * sizeof(*sites))) == NULL)
		return;
	if (st->gap_count && (gaps = malloc(st->gap_count * sizeof(*gaps))) == NULL) {
		free(sites);
		return;
	}
	for (i = 0; i < st->site_count; i++)
		sites[i] = &st->sites[i];
	for (i = 0; i < st->gap_count; i++)
		gaps[i] = &st->gaps[i];
	if (sites)
		qsort(sites, st->site_count, sizeof(*sites), lock_stats_cmp_site);
	if (gaps)
		qsort(gaps, st->gap_count, sizeof(*gaps), lock_stats_cmp_gap);

	fprintf(f, "=== OpenSC lock statistics, app %s, pid %lu ===\n",
			ctx->app_name ? ctx->app_name : "?",
#ifdef _WIN32
			(unsigned long)GetCurrentProcessId());
#else
			(unsigned long)getpid());
#endif
	fprintf(f, "Lock sites, sorted by total time of outermost sections (times in ms)\n");
	fprintf(f, "%8s %8s %8s %10s %8s %8s %10s %8s %8s %8s %10s %6s %6s %6s  %s\n",
			"outer", "no-apdu", "apdus", "acquire", "avg", "max", "held", "avg", "max",
			"nested", "n-held", "failed", "elsewh", "unmtch", "site");
	for (i = 0; i < st->site_count; i++) {
		const struct sc_lock_site *s = sites[i];
		unsigned long n = s->outer ? s->outer : 1;

		fprintf(f, "%8lu %8lu %8lu %10.3f %8.3f %8.3f %10.3f %8.3f %8.3f %8lu %10.3f %6lu %6lu %6lu  %s:%s\n",
				s->outer, s->outer_no_apdu, s->apdus,
				lock_stats_ms(s->acquire_ns), lock_stats_ms(s->acquire_ns / n), lock_stats_ms(s->acquire_max_ns),
				lock_stats_ms(s->held_ns), lock_stats_ms(s->held_ns / n), lock_stats_ms(s->held_max_ns),
				s->nested, lock_stats_ms(s->nested_held_ns),
				s->lock_failed, s->unlock_elsewhere, s->unlock_unmatched,
				s->file, s->func);
		outer += s->outer;
		no_apdu += s->outer_no_apdu;
		apdus += s->apdus;
		acquire += s->acquire_ns;
		held += s->held_ns;
	}
	fprintf(f, "%8lu %8lu %8lu %10.3f %8s %8s %10.3f  total, %lu APDUs outside of sections\n",
			outer, no_apdu, apdus, lock_stats_ms(acquire), "", "", lock_stats_ms(held), st->apdus_unlocked);

	fprintf(f, "Gaps between outermost sections, sorted by count (times in ms)\n");
	fprintf(f, "%8s %10s %8s %8s %8s  %s\n", "count", "total", "avg", "min", "max", "unlock site -> next lock site");
	for (i = 0; i < st->gap_count; i++) {
		const struct sc_lock_gap *g = gaps[i];

		fprintf(f, "%8lu %10.3f %8.3f %8.3f %8.3f  %s:%s -> %s:%s\n",
				g->count, lock_stats_ms(g->gap_ns), lock_stats_ms(g->gap_ns / g->count),
				lock_stats_ms(g->gap_min_ns), lock_stats_ms(g->gap_max_ns),
				g->unlock_file, g->unlock_func, g->lock_file, g->lock_func);
	}
	free(sites);
	free(gaps);
}
#endif /* SC_LOCK_STATS */

void sc_dump_lock_stats(sc_context_t *ctx)
{
#ifdef SC_LOCK_STATS
	const char *env = getenv("OPENSC_LOCK_STATS");
	struct sc_lock_stats *st;
	FILE *f;

	if (ctx == NULL || (st = ctx->lock_stats) == NULL || env == NULL || *env == '\0')
		return;
	if (strcmp(env, "stderr") == 0)
		f = stderr;
	else if ((f = fopen(env, "a")) == NULL)
		return;
	sc_mutex_lock(ctx, st->mutex);
	lock_stats_write(f, ctx, st);
	sc_mutex_unlock(ctx, st->mutex);
	if (f == stderr)
		fflush(f);
	else
		fclose(f);
#else
	(void)ctx;
#endif
}

int (sc_lock)(sc_card_t *card)
{
	return sc_lock_at(card, NULL, "?");
}

int sc_lock_at(sc_card_t *card, const char *file, const char *func)
{
	int r = 0, r2 = 0;
	int was_reset = 0;
	int reader_lock_obtained  = 0;
#ifdef SC_LOCK_STATS
	uint64_t start = card && card->ctx->lock_stats ? lock_stats_now() : 0;
#endif

	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	r = sc_mutex_lock(card->ctx, card->mutex);
	if (r != SC_SUCCESS)
		return r;
	if (card->lock_count == 0) {
		if (card->reader->ops->lock != NULL) {
			r = card->reader->ops->lock(card->reader);
			while (r == SC_ERROR_CARD_RESET || r == SC_ERROR_READER_REATTACHED) {
				if (was_reset++ > 4) /* TODO retry a few times */
					break;
				r = card->reader->ops->lock(card->reader);
			}
			if (r == 0)
				reader_lock_obtained = 1;
		}
	}
	if (r == 0)
		card->lock_count++;
#ifdef SC_LOCK_STATS
	lock_stats_locked(card, file, func, r, start);
#else
	(void)file;
	(void)func;
#endif

	r2 = sc_mutex_unlock(card->ctx, card->mutex);
	if (r2 != SC_SUCCESS) {
		sc_log(card->ctx, "unable to release card->mutex lock");
		r = r != SC_SUCCESS ? r : r2;
	}

	if (r == 0 && was_reset > 0) {
#ifdef ENABLE_SM
		if (card->sm_ctx.ops.open)
			card->sm_ctx.ops.open(card);
#endif
	}

	/* give card driver a chance to do something when reader lock first obtained */
	if (r == 0 && reader_lock_obtained == 1  && card->ops->card_reader_lock_obtained) {
		if (SC_SUCCESS != card->ops->card_reader_lock_obtained(card, was_reset))
			sc_log(card->ctx, "card_reader_lock_obtained failed");
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

int (sc_unlock)(sc_card_t *card)
{
	return sc_unlock_at(card, NULL, "?");
}

int sc_unlock_at(sc_card_t *card, const char *file, const char *func)
{
	int r, r2;
#ifdef SC_LOCK_STATS
	uint64_t start = card && card->ctx->lock_stats ? lock_stats_now() : 0;
#else
	(void)file;
	(void)func;
#endif

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	r = sc_mutex_lock(card->ctx, card->mutex);
	if (r != SC_SUCCESS)
		LOG_FUNC_RETURN(card->ctx, r);

	if (card->lock_count < 1) {
		sc_log(card->ctx, "card is not locked, sc_unlock() called without prior sc_lock()");
#ifdef SC_LOCK_STATS
		lock_stats_unlocked(card, file, func, 1, start);
#endif
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto out;
	}
	if (--card->lock_count == 0) {
		/* release reader lock */
		if (card->reader->ops->unlock != NULL)
			r = card->reader->ops->unlock(card->reader);
	}
#ifdef SC_LOCK_STATS
	lock_stats_unlocked(card, file, func, 0, start);
#endif
out:
	r2 = sc_mutex_unlock(card->ctx, card->mutex);
	if (r2 != SC_SUCCESS) {
		sc_log(card->ctx, "unable to release lock");
		r = (r == SC_SUCCESS) ? r2 : r;
	}

	return r;
}

int sc_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	int r;

	if (card == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->list_files == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->list_files(card, buf, buflen);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_create_file(sc_card_t *card, sc_file_t *file)
{
	int r;
	char pbuf[SC_MAX_PATH_STRING_SIZE];
	const sc_path_t *in_path;

	if (card == NULL || file == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	in_path = &file->path;
	r = sc_path_print(pbuf, sizeof(pbuf), in_path);
	if (r != SC_SUCCESS)
		pbuf[0] = '\0';

	sc_log(card->ctx, "called; type=%d, path=%s, id=%04i, size=%zu",
			in_path->type, pbuf, file->id, file->size);
	/* ISO 7816-4: "Number of data bytes in the file, including structural information if any"
	 * can not be bigger than two bytes */
	if (file->size > 0xFFFF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (card->ops->create_file == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	r = card->ops->create_file(card, file);
	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int r;
	char pbuf[SC_MAX_PATH_STRING_SIZE];

	if (card == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = sc_path_print(pbuf, sizeof(pbuf), path);
	if (r != SC_SUCCESS)
		pbuf[0] = '\0';

	sc_log(card->ctx, "called; type=%d, path=%s", path->type, pbuf);
	if (card->ops->delete_file == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->delete_file(card, path);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_read_binary(sc_card_t *card, unsigned int idx,
		   unsigned char *buf, size_t count, unsigned long *flags)
{
	size_t max_le = sc_get_max_recv_size(card);
	size_t todo = count;
	int r;

	if (card == NULL || card->ops == NULL || buf == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_log(card->ctx, "called; %zu bytes at index %d", count, idx);
	if (count == 0)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

#ifdef ENABLE_SM
	if (card->sm_ctx.ops.read_binary)   {
		r = card->sm_ctx.ops.read_binary(card, idx, buf, count);
		if (r)
			LOG_FUNC_RETURN(card->ctx, r);
	}
#endif

	if (card->ops->read_binary == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	/* lock the card now to avoid deselection of the file */
	r = sc_lock(card);
	LOG_TEST_RET(card->ctx, r, "sc_lock() failed");

	while (todo > 0) {
		size_t chunk = MIN(todo, max_le);

		r = card->ops->read_binary(card, idx, buf, chunk, flags);
		if (r == 0 || r == SC_ERROR_FILE_END_REACHED)
			break;
		if (r < 0 && todo != count) {
			/* the last command failed, but previous ones succeeded.
			 * Let's just return what we've successfully read. */
			sc_log(card->ctx, "Subsequent read failed with %d, returning what was read successfully.", r);
			break;
		}
		if (r < 0) {
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, r);
		}
		if ((idx > SIZE_MAX - (size_t) r) || (size_t) r > todo) {
			/* `idx + r` or `todo - r` would overflow */
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OFFSET_TOO_LARGE);
		}

		todo -= (size_t) r;
		buf  += (size_t) r;
		idx  += (size_t) r;
	}

	sc_unlock(card);

	LOG_FUNC_RETURN(card->ctx, (int)(count - todo));
}

int sc_write_binary(sc_card_t *card, unsigned int idx,
		    const u8 *buf, size_t count, unsigned long flags)
{
	size_t max_lc = sc_get_max_send_size(card);
	size_t todo = count;
	int r;

	if (card == NULL || card->ops == NULL || buf == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_log(card->ctx, "called; %zu bytes at index %d", count, idx);
	if (count == 0)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	if (card->ops->write_binary == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	/* lock the card now to avoid deselection of the file */
	r = sc_lock(card);
	LOG_TEST_RET(card->ctx, r, "sc_lock() failed");

	while (todo > 0) {
		size_t chunk = MIN(todo, max_lc);

		r = card->ops->write_binary(card, idx, buf, chunk, flags);
		if (r == 0 || r == SC_ERROR_FILE_END_REACHED)
			break;
		if (r < 0) {
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, r);
		}
		if ((idx > SIZE_MAX - (size_t) r) || (size_t) r > todo) {
			/* `idx + r` or `todo - r` would overflow */
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OFFSET_TOO_LARGE);
		}

		todo -= (size_t) r;
		buf  += (size_t) r;
		idx  += (size_t) r;
	}

	sc_unlock(card);

	LOG_FUNC_RETURN(card->ctx, (int)(count - todo));
}

int sc_update_binary(sc_card_t *card, unsigned int idx,
		     const u8 *buf, size_t count, unsigned long flags)
{
	size_t max_lc = sc_get_max_send_size(card);
	size_t todo = count;
	int r;

	if (card == NULL || card->ops == NULL || buf == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_log(card->ctx, "called; %zu bytes at index %d", count, idx);
	if (count == 0)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

#ifdef ENABLE_SM
	if (card->sm_ctx.ops.update_binary)   {
		r = card->sm_ctx.ops.update_binary(card, idx, buf, count);
		if (r)
			LOG_FUNC_RETURN(card->ctx, r);
	}
#endif

	if (card->ops->update_binary == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	/* lock the card now to avoid deselection of the file */
	r = sc_lock(card);
	LOG_TEST_RET(card->ctx, r, "sc_lock() failed");

	while (todo > 0) {
		size_t chunk = MIN(todo, max_lc);

		r = card->ops->update_binary(card, idx, buf, chunk, flags);
		if (r == 0 || r == SC_ERROR_FILE_END_REACHED)
			break;
		if (r < 0) {
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, r);
		}
		if ((idx > SIZE_MAX - (size_t) r) || (size_t) r > todo) {
			/* `idx + r` or `todo - r` would overflow */
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OFFSET_TOO_LARGE);
		}

		todo -= (size_t) r;
		buf  += (size_t) r;
		idx  += (size_t) r;
	}

	sc_unlock(card);

	LOG_FUNC_RETURN(card->ctx, (int)(count - todo));
}


int sc_erase_binary(struct sc_card *card, unsigned int idx, size_t count,  unsigned long flags)
{
	int r;
	size_t todo = count;

	if (card == NULL || card->ops == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_log(card->ctx, "called; erase %zu bytes from offset %d", count, idx);
	if (count == 0)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	if (card->ops->erase_binary == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	/* lock the card now to avoid deselection of the file */
	r = sc_lock(card);
	LOG_TEST_RET(card->ctx, r, "sc_lock() failed");

	while (todo > 0) {
		r = card->ops->erase_binary(card, idx, todo, flags);
		if (r == 0 || r == SC_ERROR_FILE_END_REACHED)
			break;
		if (r < 0) {
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, r);
		}
		if ((idx > SIZE_MAX - (size_t) r) || (size_t) r > todo) {
			/* `idx + r` or `todo - r` would overflow */
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OFFSET_TOO_LARGE);
		}

		todo -= (size_t) r;
		idx  += (size_t) r;
	}

	sc_unlock(card);

	LOG_FUNC_RETURN(card->ctx, (int)(count - todo));
}


int sc_select_file(sc_card_t *card, const sc_path_t *in_path,  sc_file_t **file)
{
	int r;
	char pbuf[SC_MAX_PATH_STRING_SIZE];

	if (card == NULL || in_path == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = sc_path_print(pbuf, sizeof(pbuf), in_path);
	if (r != SC_SUCCESS)
		pbuf[0] = '\0';

	/* FIXME We should be a bit less strict and let the upper layers do
	 * the initialization (including reuse of existing file objects). We
	 * implemented this here because we are lazy. */
	if (file != NULL)
		*file = NULL;

	sc_log(card->ctx, "called; type=%d, path=%s", in_path->type, pbuf);
	if (in_path->len > SC_MAX_PATH_SIZE)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (in_path->type == SC_PATH_TYPE_PATH) {
		/* Perform a sanity check */
		size_t i;

		if ((in_path->len & 1) != 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

		for (i = 0; i < in_path->len/2; i++) {
			u8 p1 = in_path->value[2*i],
			   p2 = in_path->value[2*i+1];

			if ((p1 == 0x3F && p2 == 0x00) && i != 0)
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		}
	}
	if (card->ops->select_file == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->select_file(card, in_path, file);
	LOG_TEST_RET(card->ctx, r, "'SELECT' error");

	if (file) {
		if (*file)
			/* Remember file path */
			(*file)->path = *in_path;
		else
			/* FIXME We should be a bit less strict and let the upper layers do
			 * the error checking. We implemented this here because we are
			 * lazy.  */
			r = SC_ERROR_INVALID_DATA;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}


int sc_get_data(sc_card_t *card, unsigned int tag, u8 *buf, size_t len)
{
	int	r;

	sc_log(card->ctx, "called, tag=%04x", tag);
	if (card->ops->get_data == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->get_data(card, tag, buf, len);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_put_data(sc_card_t *card, unsigned int tag, const u8 *buf, size_t len)
{
	int	r;

	sc_log(card->ctx,"called, tag=%04x", tag);

	if (card->ops->put_data == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->put_data(card, tag, buf, len);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_get_challenge(sc_card_t *card, u8 *rnd, size_t len)
{
	int r;

	if (len == 0)
		return SC_SUCCESS;

	if (card == NULL || rnd == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	LOG_FUNC_CALLED(card->ctx);

	if (card->ops == NULL || card->ops->get_challenge == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		LOG_FUNC_RETURN(card->ctx, r);

	while (len > 0) {
		r = card->ops->get_challenge(card, rnd, len);
		if (r == 0)
			r = SC_ERROR_INVALID_DATA;
		if (r < 0) {
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, r);
		}

		rnd += (size_t) r;
		len -= (size_t) r;
	}

	sc_unlock(card);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int sc_read_record(sc_card_t *card, unsigned int rec_nr, unsigned int idx,
		   u8 *buf ,size_t count, unsigned long flags)
{
	size_t max_le = sc_get_max_recv_size(card);
	size_t todo = count;
	int r;

	if (card == NULL || card->ops == NULL || buf == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);
	if (count == 0)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	if (card->ops->read_record == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	/* lock the card now to avoid deselection of the file */
	r = sc_lock(card);
	LOG_TEST_RET(card->ctx, r, "sc_lock() failed");

	while (todo > 0) {
		size_t chunk = MIN(todo, max_le);

		r = card->ops->read_record(card, rec_nr, idx, buf, chunk, flags);
		if (r == 0 || r == SC_ERROR_FILE_END_REACHED)
			break;
		if (r < 0 && todo != count) {
			/* the last command failed, but previous ones succeeded.
			 * Let's just return what we've successfully read. */
			sc_log(card->ctx, "Subsequent read failed with %d, returning what was read successfully.", r);
			break;
		}
		if (r < 0) {
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, r);
		}
		if ((idx > SIZE_MAX - (size_t) r) || (size_t) r > todo) {
			/* `idx + r` or `todo - r` would overflow */
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OFFSET_TOO_LARGE);
		}

		todo -= (size_t) r;
		buf  += (size_t) r;
		idx  += (size_t) r;
	}

	sc_unlock(card);

	LOG_FUNC_RETURN(card->ctx, (int)(count - todo));
}

int sc_write_record(sc_card_t *card, unsigned int rec_nr, const u8 * buf,
		    size_t count, unsigned long flags)
{
	int r;

	if (card == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->write_record == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	r = card->ops->write_record(card, rec_nr, buf, count, flags);
	if (r == SC_SUCCESS) {
		r = (int)count;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_append_record(sc_card_t *card, const u8 * buf, size_t count,
		     unsigned long flags)
{
	int r;

	if (card == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->append_record == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	r = card->ops->append_record(card, buf, count, flags);
	if (r == SC_SUCCESS) {
		r = (int)count;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_update_record(sc_card_t *card, unsigned int rec_nr, unsigned int idx,
		     const u8 * buf, size_t count, unsigned long flags)
{
	size_t max_lc = sc_get_max_send_size(card);
	size_t todo = count;
	int r;

	if (card == NULL || card->ops == NULL || buf == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);
	if (count == 0)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	if (card->ops->update_record == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	/* lock the card now to avoid deselection of the file */
	r = sc_lock(card);
	LOG_TEST_RET(card->ctx, r, "sc_lock() failed");

	while (todo > 0) {
		size_t chunk = MIN(todo, max_lc);

		r = card->ops->update_record(card, rec_nr, idx, buf, chunk, flags);
		if (r == 0 || r == SC_ERROR_FILE_END_REACHED)
			break;
		if (r < 0) {
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, r);
		}
		if ((idx > SIZE_MAX - (size_t) r) || (size_t) r > todo) {
			/* `idx + r` or `todo - r` would overflow */
			sc_unlock(card);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OFFSET_TOO_LARGE);
		}

		todo -= (size_t) r;
		buf  += (size_t) r;
		idx  += (size_t) r;
	}

	sc_unlock(card);

	LOG_FUNC_RETURN(card->ctx, (int)(count - todo));
}

int sc_delete_record(sc_card_t *card, unsigned int rec_nr)
{
	int r;

	if (card == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->delete_record == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	r = card->ops->delete_record(card, rec_nr);

	LOG_FUNC_RETURN(card->ctx, r);
}

int
sc_card_ctl(sc_card_t *card, unsigned long cmd, void *args)
{
	int r = SC_ERROR_NOT_SUPPORTED;

	if (card == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "called with cmd=%lu\n", cmd);

	if (card->ops->card_ctl != NULL)
		r = card->ops->card_ctl(card, cmd, args);

	/* suppress "not supported" error messages */
	if (r == SC_ERROR_NOT_SUPPORTED) {
		sc_log(card->ctx, "card_ctl(%lu) not supported", cmd);
		return r;
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

int _sc_card_add_algorithm(sc_card_t *card, const sc_algorithm_info_t *info)
{
	sc_algorithm_info_t *p;

	if (info == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	p = (sc_algorithm_info_t *) realloc(card->algorithms, (card->algorithm_count + 1) * sizeof(*info));
	if (!p) {
		return SC_ERROR_OUT_OF_MEMORY;
	}
	card->algorithms = p;
	p += card->algorithm_count;
	card->algorithm_count++;
	*p = *info;
	return SC_SUCCESS;
}

int _sc_card_add_symmetric_alg(sc_card_t *card, unsigned int algorithm,
			       unsigned int key_length, unsigned long flags)
{
	sc_algorithm_info_t info;

	memset(&info, 0, sizeof(info));
	info.algorithm = algorithm;
	info.key_length = key_length;
	info.flags = flags;

	return _sc_card_add_algorithm(card, &info);
}

static int
_sc_card_add_ec_alg_int(sc_card_t *card, size_t key_length,
			unsigned long flags, unsigned long ext_flags,
			struct sc_object_id *curve_oid,
			int algorithm)
{
	sc_algorithm_info_t info;
	int r;

	memset(&info, 0, sizeof(info));
	sc_init_oid(&info.u._ec.params.id);

	info.algorithm = algorithm;
	info.key_length = key_length;
	info.flags = flags;

	info.u._ec.ext_flags = ext_flags;
	if (curve_oid) {
		info.u._ec.params.id = *curve_oid;
		r = sc_encode_oid(card->ctx, &info.u._ec.params.id, &info.u._ec.params.der.value, &info.u._ec.params.der.len);
		LOG_TEST_GOTO_ERR(card->ctx, r, "sc_encode_oid failed");
		r = sc_pkcs15_fix_ec_parameters(card->ctx, &info.u._ec.params);
		LOG_TEST_GOTO_ERR(card->ctx, r, "sc_pkcs15_fix_ec_parameters failed");
	}

	r = _sc_card_add_algorithm(card, &info);
	return r;
err:
	sc_clear_ec_params(&info.u._ec.params);
	return r;
}

int  _sc_card_add_ec_alg(sc_card_t *card, size_t key_length,
			unsigned long flags, unsigned long ext_flags,
			struct sc_object_id *curve_oid)
{
	return _sc_card_add_ec_alg_int(card, key_length, flags, ext_flags,
		curve_oid, SC_ALGORITHM_EC);
}

int  _sc_card_add_eddsa_alg(sc_card_t *card, size_t key_length,
			unsigned long flags, unsigned long ext_flags,
			struct sc_object_id *curve_oid)
{
	/* For simplicity, share the ec union with the curve information */
	return _sc_card_add_ec_alg_int(card, key_length, flags, ext_flags,
		curve_oid, SC_ALGORITHM_EDDSA);
}

int  _sc_card_add_xeddsa_alg(sc_card_t *card, size_t key_length,
			unsigned long flags, unsigned long ext_flags,
			struct sc_object_id *curve_oid)
{
	/* For simplicity, share the ec union with the curve information */
	return _sc_card_add_ec_alg_int(card, key_length, flags, ext_flags,
		curve_oid, SC_ALGORITHM_XEDDSA);
}

sc_algorithm_info_t *sc_card_find_alg(sc_card_t *card,
		unsigned int algorithm, size_t key_length, void *param)
{
	int i;

	for (i = 0; i < card->algorithm_count; i++) {
		sc_algorithm_info_t *info = &card->algorithms[i];

		if (param && (info->algorithm == SC_ALGORITHM_EC ||
			info->algorithm == SC_ALGORITHM_EDDSA ||
			info->algorithm == SC_ALGORITHM_XEDDSA)) {
			if (sc_compare_oid((struct sc_object_id *)param, &info->u._ec.params.id))
				return info;
		} else if (info->algorithm != algorithm) {
			continue;
		} else if (info->key_length == key_length)
			return info;
	}
	return NULL;
}

sc_algorithm_info_t *sc_card_find_ec_alg(sc_card_t *card,
		size_t key_length, struct sc_object_id *curve_name)
{
	return sc_card_find_alg(card, SC_ALGORITHM_EC, key_length, curve_name);
}

sc_algorithm_info_t *sc_card_find_eddsa_alg(sc_card_t *card,
		size_t key_length, struct sc_object_id *curve_name)
{
	return sc_card_find_alg(card, SC_ALGORITHM_EDDSA, key_length, curve_name);
}

sc_algorithm_info_t *sc_card_find_xeddsa_alg(sc_card_t *card,
		size_t key_length, struct sc_object_id *curve_name)
{
	return sc_card_find_alg(card, SC_ALGORITHM_XEDDSA, key_length, curve_name);
}

int _sc_card_add_rsa_alg(sc_card_t *card, size_t key_length,
			 unsigned long flags, unsigned long exponent)
{
	sc_algorithm_info_t info;

	memset(&info, 0, sizeof(info));
	info.algorithm = SC_ALGORITHM_RSA;
	info.key_length = key_length;
	info.flags = flags;
	/* disable particular PKCS1 v1.5 padding type if also RAW is supported on card */
	if ((info.flags & (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_RAW)) == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_RAW)) {
		if (card->ctx->disable_hw_pkcs1_padding & SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01)
			info.flags &= ~SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01;
		if (card->ctx->disable_hw_pkcs1_padding & SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_02)
			info.flags &= ~SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_02;
	}
	info.u._rsa.exponent = exponent;

	return _sc_card_add_algorithm(card, &info);
}

sc_algorithm_info_t *sc_card_find_rsa_alg(sc_card_t *card, size_t key_length)
{
	return sc_card_find_alg(card, SC_ALGORITHM_RSA, key_length, NULL);
}

sc_algorithm_info_t *sc_card_find_gostr3410_alg(sc_card_t *card, size_t key_length)
{
	return sc_card_find_alg(card, SC_ALGORITHM_GOSTR3410, key_length, NULL);
}

static int match_atr_table(sc_context_t *ctx, const struct sc_atr_table *table, struct sc_atr *atr)
{
	u8 *card_atr_bin;
	size_t card_atr_bin_len;
	char card_atr_hex[3 * SC_MAX_ATR_SIZE];
	size_t card_atr_hex_len;
	unsigned int i = 0;

	if (ctx == NULL || table == NULL || atr == NULL)
		return -1;
	card_atr_bin = atr->value;
	card_atr_bin_len = atr->len;
	sc_bin_to_hex(card_atr_bin, card_atr_bin_len, card_atr_hex, sizeof(card_atr_hex), ':');
	card_atr_hex_len = strlen(card_atr_hex);

	sc_debug(ctx, SC_LOG_DEBUG_MATCH, "ATR     : %s", card_atr_hex);

	for (i = 0; table[i].atr != NULL; i++) {
		const char *tatr = table[i].atr;
		const char *matr = table[i].atrmask;
		size_t tatr_len = strlen(tatr);
		u8 mbin[SC_MAX_ATR_SIZE], tbin[SC_MAX_ATR_SIZE];
		size_t mbin_len, tbin_len, s, matr_len;
		size_t fix_hex_len = card_atr_hex_len;
		size_t fix_bin_len = card_atr_bin_len;

		sc_debug(ctx, SC_LOG_DEBUG_MATCH, "ATR try : %s", tatr);

		if (tatr_len != fix_hex_len) {
			sc_debug(ctx, SC_LOG_DEBUG_MATCH, "ignored - wrong length");
			continue;
		}
		if (matr != NULL) {
			sc_debug(ctx, SC_LOG_DEBUG_MATCH, "ATR mask: %s", matr);

			matr_len = strlen(matr);
			if (tatr_len != matr_len)
				continue;
			tbin_len = sizeof(tbin);
			sc_hex_to_bin(tatr, tbin, &tbin_len);
			mbin_len = sizeof(mbin);
			sc_hex_to_bin(matr, mbin, &mbin_len);
			if (mbin_len != fix_bin_len) {
				sc_debug(ctx, SC_LOG_DEBUG_MATCH, "length of atr and atr mask do not match - ignored: %s - %s", tatr, matr);
				continue;
			}
			for (s = 0; s < tbin_len; s++) {
				/* reduce tatr with mask */
				tbin[s] = (tbin[s] & mbin[s]);
				/* create copy of card_atr_bin masked) */
				mbin[s] = (card_atr_bin[s] & mbin[s]);
			}
			if (memcmp(tbin, mbin, tbin_len) != 0)
				continue;
		} else {
			if (strncasecmp(tatr, card_atr_hex, tatr_len) != 0)
				continue;
		}
		return i;
	}
	return -1;
}

int _sc_match_atr(sc_card_t *card, const struct sc_atr_table *table, int *type_out)
{
	int res;

	if (card == NULL)
		return -1;
	res = match_atr_table(card->ctx, table, &card->atr);
	if (res < 0)
		return res;
	if (type_out != NULL)
		*type_out = table[res].type;
	return res;
}

scconf_block *_sc_match_atr_block(sc_context_t *ctx, struct sc_card_driver *driver, struct sc_atr *atr)
{
	struct sc_card_driver *drv;
	struct sc_atr_table *table;
	int res;

	if (ctx == NULL)
		return NULL;
	if (driver) {
		drv = driver;
		table = drv->atr_map;
		res = match_atr_table(ctx, table, atr);
		if (res < 0)
			return NULL;
		return table[res].card_atr;
	} else {
		unsigned int i;

		for (i = 0; ctx->card_drivers[i] != NULL; i++) {
			drv = ctx->card_drivers[i];
			table = drv->atr_map;
			res = match_atr_table(ctx, table, atr);
			if (res < 0)
				continue;
			return table[res].card_atr;
		}
	}
	return NULL;
}

int _sc_add_atr(sc_context_t *ctx, struct sc_card_driver *driver, struct sc_atr_table *src)
{
	struct sc_atr_table *map, *dst;

	map = (struct sc_atr_table *) realloc(driver->atr_map,
			(driver->natrs + 2) * sizeof(struct sc_atr_table));
	if (!map)
		return SC_ERROR_OUT_OF_MEMORY;
	driver->atr_map = map;

	dst = &driver->atr_map[driver->natrs++];
	memset(dst, 0, sizeof(*dst));
	memset(&driver->atr_map[driver->natrs], 0, sizeof(struct sc_atr_table));
	dst->atr = strdup(src->atr);
	if (!dst->atr)
		return SC_ERROR_OUT_OF_MEMORY;

	if (src->atrmask) {
		dst->atrmask = strdup(src->atrmask);
		if (!dst->atrmask)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	else {
		dst->atrmask = NULL;
	}

	if (src->name) {
		dst->name = strdup(src->name);
		if (!dst->name)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	else {
		dst->name = NULL;
	}

	dst->type = src->type;
	dst->flags = src->flags;
	dst->card_atr = src->card_atr;

	return SC_SUCCESS;
}


int _sc_free_atr(sc_context_t *ctx, struct sc_card_driver *driver)
{
	unsigned int i;

	for (i = 0; i < driver->natrs; i++) {
		struct sc_atr_table *src = &driver->atr_map[i];

		if (src->atr)
			free((void *)src->atr);
		if (src->atrmask)
			free((void *)src->atrmask);
		if (src->name)
			free((void *)src->name);
		src->card_atr = NULL;
		src = NULL;
	}
	if (driver->atr_map)
		free(driver->atr_map);
	driver->atr_map = NULL;
	driver->natrs = 0;

	return SC_SUCCESS;
}


scconf_block *sc_get_conf_block(sc_context_t *ctx, const char *name1, const char *name2, int priority)
{
	int i;
	scconf_block *conf_block = NULL;

	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		scconf_block **blocks;

		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i], name1, name2);
		if (blocks != NULL) {
			conf_block = blocks[0];
			free(blocks);
		}
		if (conf_block != NULL && priority)
			break;
	}
	return conf_block;
}

void
sc_clear_ec_params(struct sc_ec_parameters *ecp)
{
	if (ecp) {
		free(ecp->named_curve);
		free(ecp->der.value);
		memset(ecp, 0, sizeof(struct sc_ec_parameters));
	}
	return;
}

int sc_copy_ec_params(struct sc_ec_parameters *dst, struct sc_ec_parameters *src)
{
	if (!dst || !src)
		return SC_ERROR_INVALID_ARGUMENTS;

	memset(dst, 0, sizeof(*dst));
	if (src->named_curve)   {
		dst->named_curve = strdup(src->named_curve);
		if (!dst->named_curve)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	dst->id = src->id;
	if (src->der.value && src->der.len)   {
		dst->der.value = malloc(src->der.len);
		if (!dst->der.value) {
			free(dst->named_curve);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		memcpy(dst->der.value, src->der.value, src->der.len);
		dst->der.len = src->der.len;
	}
	dst->type = src->type;
	dst->field_length = src->field_length;
	dst->key_type = src->key_type;

	return SC_SUCCESS;
}

scconf_block *
sc_match_atr_block(sc_context_t *ctx, struct sc_card_driver *driver, struct sc_atr *atr)
{
	return _sc_match_atr_block(ctx, driver, atr);
}

#ifdef ENABLE_SM
static int
sc_card_sm_unload(struct sc_card *card)
{
	if (card->sm_ctx.module.ops.module_cleanup)
		card->sm_ctx.module.ops.module_cleanup(card->ctx);

	if (card->sm_ctx.module.handle)
		sc_dlclose(card->sm_ctx.module.handle);
	card->sm_ctx.module.handle = NULL;
	return 0;
}


static int
sc_card_sm_load(struct sc_card *card, const char *module_path, const char *in_module)
{
	struct sc_context *ctx = NULL;
	int rv = SC_ERROR_INTERNAL;
	char *module = NULL;
#ifdef _WIN32
	const char path_delim = '\\';
#else
	const char path_delim = '/';
#endif

	if (card == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	if (!in_module)
		return sc_card_sm_unload(card);

	sc_log(ctx, "SM module '%s' located in '%s'", in_module, module_path);
	if (module_path && strlen(module_path) > 0)   {
		size_t sz = strlen(in_module) + strlen(module_path) + 3;
		module = malloc(sz);
		if (module)
			snprintf(module, sz, "%s%c%s", module_path, path_delim, in_module);
	}
	else   {
		module = strdup(in_module);
	}

	if (!module)
		return SC_ERROR_OUT_OF_MEMORY;

	sc_log(ctx, "try to load SM module '%s'", module);
	do  {
		struct sm_module_operations *mod_ops = &card->sm_ctx.module.ops;
		void *mod_handle;

		card->sm_ctx.module.handle = sc_dlopen(module);
		if (!card->sm_ctx.module.handle)   {
			sc_log(ctx, "cannot open dynamic library '%s': %s", module, sc_dlerror());
			break;
		}
		mod_handle = card->sm_ctx.module.handle;

		mod_ops->initialize = sc_dlsym(mod_handle, "initialize");
		if (!mod_ops->initialize)   {
			sc_log(ctx, "SM handler 'initialize' not exported: %s", sc_dlerror());
			break;
		}

		mod_ops->get_apdus  = sc_dlsym(mod_handle, "get_apdus");
		if (!mod_ops->get_apdus)   {
			sc_log(ctx, "SM handler 'get_apdus' not exported: %s", sc_dlerror());
			break;
		}

		mod_ops->finalize  = sc_dlsym(mod_handle, "finalize");
		if (!mod_ops->finalize)
			sc_log(ctx, "SM handler 'finalize' not exported -- ignored");

		mod_ops->module_init  = sc_dlsym(mod_handle, "module_init");
		if (!mod_ops->module_init)
			sc_log(ctx, "SM handler 'module_init' not exported -- ignored");

		mod_ops->module_cleanup  = sc_dlsym(mod_handle, "module_cleanup");
		if (!mod_ops->module_cleanup)
			sc_log(ctx, "SM handler 'module_cleanup' not exported -- ignored");

		mod_ops->test  = sc_dlsym(mod_handle, "test");
		if (mod_ops->test)
			sc_log(ctx, "SM handler 'test' not exported -- ignored");

		rv = 0;
		break;
	} while(0);

	if (rv)
		sc_card_sm_unload(card);

	card->sm_ctx.sm_mode = SM_MODE_ACL;
	if (module)
		free(module);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, rv);
}


/* get SM related configuration settings and initialize SM session, SM module, ... */
static int
sc_card_sm_check(struct sc_card *card)
{
	const char *sm = NULL, *module_name = NULL, *module_path = NULL, *module_data = NULL, *sm_mode = NULL;
	struct sc_context *ctx = card->ctx;
	scconf_block *atrblock = NULL, *sm_conf_block = NULL;
	int rv, ii;
#ifdef _WIN32
	char temp_path[PATH_MAX];
	size_t temp_len = PATH_MAX - 1;
	char expanded_val[PATH_MAX];
	DWORD expanded_len = PATH_MAX;
#endif

	LOG_FUNC_CALLED(ctx);

	/* get the name of card specific SM configuration section */
	atrblock = _sc_match_atr_block(ctx, card->driver, &card->atr);
	if (atrblock == NULL)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	sm = scconf_get_str(atrblock, "secure_messaging", NULL);
	if (!sm)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	/* get SM configuration section by the name */
	sc_log(ctx, "secure_messaging configuration block '%s'", sm);
        for (ii = 0; ctx->conf_blocks[ii]; ii++) {
		scconf_block **blocks;

		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[ii], "secure_messaging", sm);
		if (blocks) {
			sm_conf_block = blocks[0];
			free(blocks);
		}
		if (sm_conf_block != NULL)
			break;
	}

	if (!sm_conf_block)
		LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_CONFIGURATION, "SM configuration block not preset");

	/* check if an external SM module has to be used */
#ifdef _WIN32
	rv = sc_ctx_win32_get_config_value(NULL, "SmDir", "Software\\" OPENSC_VS_FF_COMPANY_NAME "\\OpenSC" OPENSC_ARCH_SUFFIX,
			temp_path, &temp_len);
	if (rv == SC_SUCCESS) {
		temp_path[temp_len] = '\0';
		module_path = temp_path;
	}
	expanded_len = ExpandEnvironmentStringsA(module_path, expanded_val, expanded_len);
	if (0 < expanded_len && expanded_len < sizeof expanded_val)
		module_path = expanded_val;
#else
	module_path = scconf_get_str(sm_conf_block, "module_path", DEFAULT_SM_MODULE_PATH);
#endif
	module_name = scconf_get_str(sm_conf_block, "module_name", DEFAULT_SM_MODULE);
	sc_log(ctx, "SM module '%s' in  '%s'", module_name, module_path);
	if (!module_name)
		LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_CONFIGURATION, "Invalid SM configuration: module not defined");

	rv = sc_card_sm_load(card, module_path, module_name);
	LOG_TEST_RET(ctx, rv, "Failed to load SM module");

	strlcpy(card->sm_ctx.module.filename, module_name, sizeof(card->sm_ctx.module.filename));
	strlcpy(card->sm_ctx.config_section, sm, sizeof(card->sm_ctx.config_section));

	/* allocate resources for the external SM module */
	if (card->sm_ctx.module.ops.module_init)   {
		module_data = scconf_get_str(sm_conf_block, "module_data", NULL);

		rv = card->sm_ctx.module.ops.module_init(ctx, module_data);
		LOG_TEST_RET(ctx, rv, "Cannot initialize SM module");
	}

	/* initialize SM session in the case of 'APDU TRANSMIT' SM mode */
	sm_mode = scconf_get_str(sm_conf_block, "mode", NULL);
	if (sm_mode && !strcasecmp("Transmit", sm_mode))   {
		if (!card->sm_ctx.ops.open || !card->sm_ctx.ops.get_sm_apdu || !card->sm_ctx.ops.free_sm_apdu)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "'Transmit' SM asked but not supported by card driver");

		card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;
		rv = card->sm_ctx.ops.open(card);
		LOG_TEST_RET(ctx, rv, "Cannot initialize SM");
	}

	sc_log(ctx, "SM mode:%X", card->sm_ctx.sm_mode);
	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, rv);
}
#endif
