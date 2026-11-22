/*
 * reader-pcsc-proxy.c: Proxy for PC/SC status calls of the PC/SC driver
 *
 * Copyright (C) 2026 Martin Vogt
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

#ifdef ENABLE_PCSC	/* empty file without pcsc */

#include "reader-pcsc-proxy.h"

/* the monitor needs a thread and the PnP notification of PC/SC, older
 * macOS has none */
#if defined(HAVE_PTHREAD) && !defined(_WIN32) && !defined(__APPLE__)
#define HAVE_PCSC_PROXY_MONITOR 1
#endif

#ifdef HAVE_PCSC_PROXY_MONITOR

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
 * The monitor thread waits in SCardGetStatusChange(INFINITE) on its own
 * context for changes of all readers and keeps a copy of their states.
 * A poll (timeout 0) is answered from this copy like PC/SC would do it.
 *
 * SCardStatus() goes to PC/SC once per card handle, its result is kept and
 * returned again as long as the monitor has seen no change of any reader
 * since then.  A card reset by another application changes no reader
 * state, it is noticed by the next call on the card (SCARD_W_RESET_CARD).
 *
 * SCardListReaders() is answered from the list of readers the thread
 * watches, it is renewed on every PnP notification.
 *
 * Every call the copy cannot answer goes to PC/SC.
 */

#define MONITOR_MAX_READERS 16
#define MONITOR_NAME_LEN 256
#define MONITOR_PNP_READER "\\\\?PnP?\\Notification"

struct monitor_entry {
	char name[MONITOR_NAME_LEN];
	DWORD state;
	DWORD cbAtr;
	unsigned char rgbAtr[MAX_ATR_SIZE];
};

#define MONITOR_MAX_CARDS 16

/* result of the last successful SCardStatus() of a card handle */
struct monitor_card {
	SCARDHANDLE hCard;
	int used;
	unsigned long generation;	/* of the copy at the time of the call */
	DWORD readers_len;
	DWORD state;
	DWORD protocol;
	DWORD cbAtr;
	unsigned char rgbAtr[MAX_ATR_SIZE];
};

struct pcsc_proxy_monitor {
	struct pcsc_proxy *proxy;
	SCARDCONTEXT mon_ctx;
	pthread_t thread;
	pid_t pid;

	/* protected by lock */
	pthread_mutex_t lock;
	int valid;	/* the copy is the current PC/SC state */
	int stop;
	int exited;
	size_t count;
	struct monitor_entry entry[MONITOR_MAX_READERS];
	DWORD pnp_state;
	/* entry[] lists all readers of PC/SC, the result of its SCardListReaders */
	int list_complete;
	LONG list_rv;
	/* counts the changes the thread has seen */
	unsigned long generation;
	struct monitor_card card[MONITOR_MAX_CARDS];

	/* used by the thread only */
	size_t nwatch;	/* readers in watch[], without PnP */
	int watch_complete;	/* watch[] has all readers */
	LONG watch_list_rv;
	char watch_name[MONITOR_MAX_READERS][MONITOR_NAME_LEN];
	SCARD_READERSTATE watch[MONITOR_MAX_READERS + 1];
};

static void monitor_sleep_ms(long ms)
{
	struct timespec ts = { 0, ms * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/* thread: watch the readers PC/SC lists now */
static void monitor_list_readers(struct pcsc_proxy_monitor *mon)
{
	char buf[MONITOR_MAX_READERS * MONITOR_NAME_LEN + 1];
	DWORD len = sizeof buf, pnp_state;
	size_t n = 0;
	const char *p;
	LONG rv;

	/* the PnP entry follows the readers, it is unset before the first call */
	pnp_state = mon->watch[mon->nwatch].szReader ?
			mon->watch[mon->nwatch].dwCurrentState : SCARD_STATE_UNAWARE;

	rv = mon->proxy->SCardListReaders(mon->mon_ctx, NULL, buf, &len);
	mon->watch_list_rv = rv;
	mon->watch_complete = rv == SCARD_S_SUCCESS;
#ifdef SCARD_E_NO_READERS_AVAILABLE
	if (rv == (LONG)SCARD_E_NO_READERS_AVAILABLE)
		mon->watch_complete = 1;
#endif
	if (rv != SCARD_S_SUCCESS)
		len = 0;	/* no readers (yet) */

	for (p = buf; len > 1 && p < buf + len && *p != '\0'; p += strlen(p) + 1) {
		if (strlen(p) >= MONITOR_NAME_LEN || n == MONITOR_MAX_READERS) {
			mon->watch_complete = 0;	/* not watched */
			continue;
		}
		strcpy(mon->watch_name[n], p);
		/* unaware: the next wait returns at once with the current state */
		mon->watch[n].szReader = mon->watch_name[n];
		mon->watch[n].dwCurrentState = SCARD_STATE_UNAWARE;
		mon->watch[n].dwEventState = SCARD_STATE_UNAWARE;
		n++;
	}
	mon->watch[n].szReader = MONITOR_PNP_READER;
	mon->watch[n].dwCurrentState = pnp_state;
	mon->watch[n].dwEventState = SCARD_STATE_UNAWARE;
	mon->nwatch = n;

	/* the copy is not valid until the next wait has returned */
	pthread_mutex_lock(&mon->lock);
	mon->valid = 0;
	mon->generation++;
	pthread_mutex_unlock(&mon->lock);

	sc_log(mon->proxy->ctx, "pcsc proxy: watching %zu reader%s", n, n == 1 ? "" : "s");
}

static void *monitor_thread(void *arg)
{
	struct pcsc_proxy_monitor *mon = arg;
	int idle = 0;
	LONG rv;

	monitor_list_readers(mon);

	for (;;) {
		int rebuild = 0, changed = 0;
		size_t i;

		pthread_mutex_lock(&mon->lock);
		if (mon->stop) {
			pthread_mutex_unlock(&mon->lock);
			break;
		}
		pthread_mutex_unlock(&mon->lock);

		rv = mon->proxy->SCardGetStatusChange(mon->mon_ctx, INFINITE,
				mon->watch, (DWORD)(mon->nwatch + 1));
		if (rv == (LONG)SCARD_E_TIMEOUT)
			continue;
		if (rv == (LONG)SCARD_E_UNKNOWN_READER) {
			/* a reader went away between listing and waiting */
			if (++idle >= 3)
				monitor_sleep_ms(100);
			monitor_list_readers(mon);
			continue;
		}
		if (rv != SCARD_S_SUCCESS) {
			if (rv != (LONG)SCARD_E_CANCELLED)
				sc_log(mon->proxy->ctx, "pcsc proxy: SCardGetStatusChange failed: 0x%08lx",
						(unsigned long)rv);
			break;
		}

		for (i = 0; i <= mon->nwatch; i++) {
			SCARD_READERSTATE *rs = &mon->watch[i];
			DWORD state = rs->dwEventState & ~SCARD_STATE_CHANGED;

			if (state != (rs->dwCurrentState & ~SCARD_STATE_CHANGED))
				changed = 1;
			if (i == mon->nwatch) {
				if (rs->dwEventState & SCARD_STATE_CHANGED)
					rebuild = 1;
			} else if (state & (SCARD_STATE_UNKNOWN | SCARD_STATE_IGNORE)) {
				rebuild = 1;
			}
			rs->dwCurrentState = state;
		}

		pthread_mutex_lock(&mon->lock);
		mon->count = mon->nwatch;
		for (i = 0; i < mon->nwatch; i++) {
			struct monitor_entry *e = &mon->entry[i];
			const SCARD_READERSTATE *rs = &mon->watch[i];

			memcpy(e->name, mon->watch_name[i], MONITOR_NAME_LEN);
			e->state = rs->dwCurrentState;
			e->cbAtr = rs->cbAtr <= MAX_ATR_SIZE ? rs->cbAtr : 0;
			memcpy(e->rgbAtr, rs->rgbAtr, e->cbAtr);
		}
		mon->pnp_state = mon->watch[mon->nwatch].dwCurrentState;
		mon->list_complete = mon->watch_complete;
		mon->list_rv = mon->watch_list_rv;
		if (changed || rebuild)
			mon->generation++;
		mon->valid = !rebuild;
		pthread_mutex_unlock(&mon->lock);

		if (rebuild)
			monitor_list_readers(mon);

		/* do not spin if PC/SC reports changes that are none */
		if (!changed && !rebuild && ++idle >= 3)
			monitor_sleep_ms(100);
		else if (changed)
			idle = 0;
	}

	pthread_mutex_lock(&mon->lock);
	mon->valid = 0;
	mon->exited = 1;
	pthread_mutex_unlock(&mon->lock);
	sc_log(mon->proxy->ctx, "pcsc proxy: monitor stopped");
	return NULL;
}

/* answer a poll from the copy, 0 if the copy cannot answer it */
static int monitor_answer(struct pcsc_proxy_monitor *mon,
		SCARD_READERSTATE *rgReaderStates, DWORD cReaders, LONG *rv)
{
	int answered = 1, changed = 0;
	DWORD i;
	size_t j;

	if (mon->pid != getpid())
		return 0;	/* forked child, the thread belongs to the parent */

	pthread_mutex_lock(&mon->lock);
	answered = mon->valid;
	/* check all readers first, the caller's states are only changed
	 * if the whole call is answered */
	for (i = 0; answered && i < cReaders; i++) {
		const SCARD_READERSTATE *rs = &rgReaderStates[i];
		DWORD cur = rs->dwCurrentState & ~SCARD_STATE_CHANGED;

		if (rs->szReader == NULL) {
			answered = 0;
		} else if (!strcmp(rs->szReader, MONITOR_PNP_READER)) {
			/* only "no new reader" is answered */
			if (cur != mon->pnp_state)
				answered = 0;
		} else {
			for (j = 0; j < mon->count; j++)
				if (!strcmp(mon->entry[j].name, rs->szReader))
					break;
			if (j == mon->count)
				answered = 0;
		}
	}
	for (i = 0; answered && i < cReaders; i++) {
		SCARD_READERSTATE *rs = &rgReaderStates[i];
		DWORD cur = rs->dwCurrentState & ~SCARD_STATE_CHANGED;

		if (!strcmp(rs->szReader, MONITOR_PNP_READER)) {
			rs->dwEventState = mon->pnp_state;
			continue;
		}
		for (j = 0; j < mon->count; j++)
			if (!strcmp(mon->entry[j].name, rs->szReader))
				break;
		rs->dwEventState = mon->entry[j].state;
		if (mon->entry[j].state != cur) {
			rs->dwEventState |= SCARD_STATE_CHANGED;
			changed = 1;
		}
		rs->cbAtr = mon->entry[j].cbAtr;
		memcpy(rs->rgbAtr, mon->entry[j].rgbAtr, rs->cbAtr);
	}
	pthread_mutex_unlock(&mon->lock);

	if (answered)
		*rv = changed ? SCARD_S_SUCCESS : (LONG)SCARD_E_TIMEOUT;
	return answered;
}

static struct monitor_card *monitor_card_find(struct pcsc_proxy_monitor *mon, SCARDHANDLE hCard)
{
	size_t i;

	for (i = 0; i < MONITOR_MAX_CARDS; i++)
		if (mon->card[i].used && mon->card[i].hCard == hCard)
			return &mon->card[i];
	return NULL;
}

/* answer SCardStatus() from the kept result, 0 if it cannot be used */
static int monitor_status_answer(struct pcsc_proxy_monitor *mon, SCARDHANDLE hCard,
		LPDWORD pcchReaderLen, LPDWORD pdwState, LPDWORD pdwProtocol,
		LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
	struct monitor_card *card;
	int answered = 0;

	pthread_mutex_lock(&mon->lock);
	card = monitor_card_find(mon, hCard);
	if (card && mon->valid && card->generation == mon->generation) {
		*pcchReaderLen = card->readers_len;
		if (pdwState)
			*pdwState = card->state;
		if (pdwProtocol)
			*pdwProtocol = card->protocol;
		*pcbAtrLen = card->cbAtr;
		memcpy(pbAtr, card->rgbAtr, card->cbAtr);
		answered = 1;
	} else if (card) {
		card->used = 0;
	}
	pthread_mutex_unlock(&mon->lock);
	return answered;
}

/* keep a successful SCardStatus() result, generation is the one of the copy
 * before the call */
static void monitor_status_keep(struct pcsc_proxy_monitor *mon, SCARDHANDLE hCard,
		unsigned long generation, DWORD readers_len, DWORD state, DWORD protocol,
		const BYTE *atr, DWORD atr_len)
{
	struct monitor_card *card;
	size_t i;

	if (atr_len > MAX_ATR_SIZE)
		return;
	pthread_mutex_lock(&mon->lock);
	card = monitor_card_find(mon, hCard);
	for (i = 0; card == NULL && i < MONITOR_MAX_CARDS; i++)
		if (!mon->card[i].used)
			card = &mon->card[i];
	if (card == NULL)
		card = &mon->card[0];	/* full, replace one */
	card->hCard = hCard;
	card->used = 1;
	card->generation = generation;
	card->readers_len = readers_len;
	card->state = state;
	card->protocol = protocol;
	card->cbAtr = atr_len;
	memcpy(card->rgbAtr, atr, atr_len);
	pthread_mutex_unlock(&mon->lock);
}

/* answer SCardListReaders() from the watched readers, 0 if it cannot be used */
static int monitor_list_answer(struct pcsc_proxy_monitor *mon,
		LPSTR mszReaders, LPDWORD pcchReaders, LONG *rv)
{
	int answered = 0;
	DWORD len = 1;	/* the final '\0' */
	size_t i;

	pthread_mutex_lock(&mon->lock);
	if (mon->valid && mon->list_complete) {
		answered = 1;
		for (i = 0; i < mon->count; i++)
			len += (DWORD)strlen(mon->entry[i].name) + 1;
		if (mon->list_rv != SCARD_S_SUCCESS) {
			*rv = mon->list_rv;	/* no readers */
		} else if (mszReaders == NULL) {
			*pcchReaders = len;
			*rv = SCARD_S_SUCCESS;
		} else if (*pcchReaders < len) {
			*pcchReaders = len;
			*rv = SCARD_E_INSUFFICIENT_BUFFER;
		} else {
			char *p = mszReaders;

			for (i = 0; i < mon->count; i++) {
				size_t n = strlen(mon->entry[i].name) + 1;

				memcpy(p, mon->entry[i].name, n);
				p += n;
			}
			*p = '\0';
			*pcchReaders = len;
			*rv = SCARD_S_SUCCESS;
		}
	}
	pthread_mutex_unlock(&mon->lock);
	return answered;
}

int pcsc_proxy_start_monitor(struct pcsc_proxy *proxy)
{
	struct pcsc_proxy_monitor *mon;
	LONG rv;

	mon = calloc(1, sizeof *mon);
	if (mon == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	mon->proxy = proxy;
	mon->pid = getpid();
	if (pthread_mutex_init(&mon->lock, NULL) != 0) {
		free(mon);
		return SC_ERROR_INTERNAL;
	}

	rv = proxy->SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &mon->mon_ctx);
	if (rv != SCARD_S_SUCCESS) {
		sc_log(proxy->ctx, "pcsc proxy: SCardEstablishContext failed: 0x%08lx",
				(unsigned long)rv);
		goto err;
	}
	if (pthread_create(&mon->thread, NULL, monitor_thread, mon) != 0) {
		sc_log(proxy->ctx, "pcsc proxy: cannot create thread");
		proxy->SCardReleaseContext(mon->mon_ctx);
		goto err;
	}
	proxy->monitor = mon;
	sc_log(proxy->ctx, "pcsc proxy: monitor started");
	return SC_SUCCESS;

err:
	pthread_mutex_destroy(&mon->lock);
	free(mon);
	return SC_ERROR_INTERNAL;
}

static void monitor_stop(struct pcsc_proxy *proxy)
{
	struct pcsc_proxy_monitor *mon = proxy->monitor;
	int exited = 0, i;

	proxy->monitor = NULL;

	/* forked child: the thread and the context belong to the parent;
	 * process exit: PC/SC may not answer any more */
	if (mon->pid != getpid() || proxy->ctx->flags & SC_CTX_FLAG_TERMINATE)
		return;

	pthread_mutex_lock(&mon->lock);
	mon->stop = 1;
	pthread_mutex_unlock(&mon->lock);

	/* SCardCancel only stops a running wait, so repeat it until the
	 * thread has noticed the stop flag */
	for (i = 0; i < 200 && !exited; i++) {
		proxy->SCardCancel(mon->mon_ctx);
		pthread_mutex_lock(&mon->lock);
		exited = mon->exited;
		pthread_mutex_unlock(&mon->lock);
		if (!exited)
			monitor_sleep_ms(10);
	}
	if (!exited) {
		/* do not hang the application, leave the thread behind */
		sc_log(proxy->ctx, "pcsc proxy: monitor does not stop");
		pthread_detach(mon->thread);
		return;
	}
	pthread_join(mon->thread, NULL);
	proxy->SCardReleaseContext(mon->mon_ctx);
	pthread_mutex_destroy(&mon->lock);
	free(mon);
}

#else

int pcsc_proxy_start_monitor(struct pcsc_proxy *proxy)
{
	sc_log(proxy->ctx, "pcsc proxy: monitor not supported on this platform");
	return SC_ERROR_NOT_SUPPORTED;
}

#endif /* HAVE_PCSC_PROXY_MONITOR */

void pcsc_proxy_init(struct pcsc_proxy *proxy, sc_context_t *ctx,
		SCardGetStatusChange_t get_status_change, SCardStatus_t status,
		SCardListReaders_t list_readers)
{
	proxy->ctx = ctx;
	proxy->SCardGetStatusChange = get_status_change;
	proxy->SCardStatus = status;
	proxy->SCardListReaders = list_readers;
	proxy->monitor = NULL;
}

void pcsc_proxy_finish(struct pcsc_proxy *proxy)
{
#ifdef HAVE_PCSC_PROXY_MONITOR
	if (proxy->monitor)
		monitor_stop(proxy);
#endif
}

LONG pcsc_proxy_SCardGetStatusChange(struct pcsc_proxy *proxy, SCARDCONTEXT hContext,
		DWORD dwTimeout, SCARD_READERSTATE *rgReaderStates, DWORD cReaders)
{
#ifdef HAVE_PCSC_PROXY_MONITOR
	LONG rv;

	if (dwTimeout == 0 && proxy->monitor
			&& monitor_answer(proxy->monitor, rgReaderStates, cReaders, &rv)) {
		sc_log(proxy->ctx, "pcsc proxy: SCardGetStatusChange answered: 0x%08lx",
				(unsigned long)rv);
		return rv;
	}
#endif
	return proxy->SCardGetStatusChange(hContext, dwTimeout, rgReaderStates, cReaders);
}

void pcsc_proxy_card_forget(struct pcsc_proxy *proxy, SCARDHANDLE hCard)
{
#ifdef HAVE_PCSC_PROXY_MONITOR
	struct pcsc_proxy_monitor *mon = proxy->monitor;
	struct monitor_card *card;

	if (mon == NULL || mon->pid != getpid())
		return;
	pthread_mutex_lock(&mon->lock);
	card = monitor_card_find(mon, hCard);
	if (card)
		card->used = 0;
	pthread_mutex_unlock(&mon->lock);
#else
	(void)proxy;
	(void)hCard;
#endif
}

LONG pcsc_proxy_SCardStatus(struct pcsc_proxy *proxy, SCARDHANDLE hCard,
		LPSTR mszReaderNames, LPDWORD pcchReaderLen, LPDWORD pdwState,
		LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
#ifdef HAVE_PCSC_PROXY_MONITOR
	struct pcsc_proxy_monitor *mon = proxy->monitor;
	DWORD state = 0, protocol = 0;
	unsigned long generation;
	int valid;
	LONG rv;

	/* only the calls of reader-pcsc.c: no reader names, ATR buffer of
	 * full size */
	if (mon == NULL || mon->pid != getpid() || mszReaderNames != NULL
			|| pcchReaderLen == NULL || pbAtr == NULL || pcbAtrLen == NULL
			|| *pcbAtrLen < MAX_ATR_SIZE)
		return proxy->SCardStatus(hCard, mszReaderNames, pcchReaderLen, pdwState,
				pdwProtocol, pbAtr, pcbAtrLen);

	if (monitor_status_answer(mon, hCard, pcchReaderLen, pdwState, pdwProtocol,
				pbAtr, pcbAtrLen)) {
		sc_log(proxy->ctx, "pcsc proxy: SCardStatus answered");
		return SCARD_S_SUCCESS;
	}

	/* a change seen during the call makes the result old at once */
	pthread_mutex_lock(&mon->lock);
	valid = mon->valid;
	generation = mon->generation;
	pthread_mutex_unlock(&mon->lock);

	rv = proxy->SCardStatus(hCard, NULL, pcchReaderLen, &state, &protocol,
			pbAtr, pcbAtrLen);
	if (pdwState)
		*pdwState = state;
	if (pdwProtocol)
		*pdwProtocol = protocol;
	if (rv == SCARD_S_SUCCESS && valid)
		monitor_status_keep(mon, hCard, generation, *pcchReaderLen, state,
				protocol, pbAtr, *pcbAtrLen);
	return rv;
#else
	return proxy->SCardStatus(hCard, mszReaderNames, pcchReaderLen, pdwState,
			pdwProtocol, pbAtr, pcbAtrLen);
#endif
}

LONG pcsc_proxy_SCardListReaders(struct pcsc_proxy *proxy, SCARDCONTEXT hContext,
		LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders)
{
#ifdef HAVE_PCSC_PROXY_MONITOR
	struct pcsc_proxy_monitor *mon = proxy->monitor;
	LONG rv;

	/* all groups, no buffer allocated by PC/SC */
	if (mon != NULL && mon->pid == getpid() && mszGroups == NULL
			&& pcchReaders != NULL
#ifdef SCARD_AUTOALLOCATE
			&& !(mszReaders != NULL && *pcchReaders == SCARD_AUTOALLOCATE)
#endif
			&& monitor_list_answer(mon, mszReaders, pcchReaders, &rv)) {
		sc_log(proxy->ctx, "pcsc proxy: SCardListReaders answered: 0x%08lx",
				(unsigned long)rv);
		return rv;
	}
#endif
	return proxy->SCardListReaders(hContext, mszGroups, mszReaders, pcchReaders);
}

#endif   /* ENABLE_PCSC */
