/*
 * pcsc-api.c: Loading of and access to the PC/SC provider library
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

#ifdef ENABLE_PCSC /* empty file without pcsc */

/* Set to 1 to count and time every PC/SC call. The statistics are written
 * when the PC/SC reader driver is released: as one JSON line appended to the
 * file named by the environment variable OPENSC_PCSC_STATS, or to the debug
 * log if the variable is not set. With 0 the wrappers only forward the call. */
#define PCSC_API_STATS 0

#include <stdlib.h>
#include <string.h>

#include "common/libscdl.h"
#include "internal.h"
#include "pcsc-api.h"

#if PCSC_API_STATS

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#ifdef _WIN32
#include <process.h>
#include <windows.h>
#define getpid _getpid
#else
#include <unistd.h>
#endif
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

enum pcsc_api_fn {
	PCSC_FN_SCardEstablishContext,
	PCSC_FN_SCardReleaseContext,
	PCSC_FN_SCardConnect,
	PCSC_FN_SCardReconnect,
	PCSC_FN_SCardDisconnect,
	PCSC_FN_SCardBeginTransaction,
	PCSC_FN_SCardEndTransaction,
	PCSC_FN_SCardStatus,
	PCSC_FN_SCardGetStatusChange,
	/* SCardGetStatusChange with dwTimeout != 0 waits for events on purpose,
	 * so it is accounted separately to not distort the timing */
	PCSC_FN_SCardGetStatusChange_blocking,
	PCSC_FN_SCardCancel,
	PCSC_FN_SCardControlOLD,
	PCSC_FN_SCardControl,
	PCSC_FN_SCardTransmit,
	PCSC_FN_SCardListReaders,
	PCSC_FN_SCardGetAttrib,
	PCSC_FN_COUNT
};

static const char *pcsc_api_fn_names[PCSC_FN_COUNT] = {
		"SCardEstablishContext",
		"SCardReleaseContext",
		"SCardConnect",
		"SCardReconnect",
		"SCardDisconnect",
		"SCardBeginTransaction",
		"SCardEndTransaction",
		"SCardStatus",
		"SCardGetStatusChange",
		"SCardGetStatusChange(blocking)",
		"SCardCancel",
		"SCardControlOLD",
		"SCardControl",
		"SCardTransmit",
		"SCardListReaders",
		"SCardGetAttrib",
};

#define PCSC_API_MAX_SITES 256

struct pcsc_api_stat {
	unsigned long calls;
	unsigned long errors;
	uint64_t total_ns;
	uint64_t min_ns;
	uint64_t max_ns;
};

struct pcsc_api_site {
	enum pcsc_api_fn fn;
	const char *caller; /* __FUNCTION__ of the call site, static storage */
	int line;
	struct pcsc_api_stat stat;
};

struct pcsc_api_stats {
#if defined(_WIN32)
	CRITICAL_SECTION lock;
#elif defined(HAVE_PTHREAD)
	pthread_mutex_t lock;
#endif
	uint64_t start_ns;
	struct pcsc_api_stat fn[PCSC_FN_COUNT];
	struct pcsc_api_site sites[PCSC_API_MAX_SITES];
	size_t nsites;
	unsigned long dropped; /* calls from sites not fitting into sites[] */
};

static uint64_t
pcsc_api_now_ns(void)
{
#ifdef _WIN32
	static LARGE_INTEGER freq;
	LARGE_INTEGER now;

	if (freq.QuadPart == 0)
		QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&now);
	return (uint64_t)((double)now.QuadPart * 1e9 / (double)freq.QuadPart);
#else
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
#endif
}

static void
pcsc_api_stats_lock(struct pcsc_api_stats *stats)
{
#if defined(_WIN32)
	EnterCriticalSection(&stats->lock);
#elif defined(HAVE_PTHREAD)
	pthread_mutex_lock(&stats->lock);
#endif
}

static void
pcsc_api_stats_unlock(struct pcsc_api_stats *stats)
{
#if defined(_WIN32)
	LeaveCriticalSection(&stats->lock);
#elif defined(HAVE_PTHREAD)
	pthread_mutex_unlock(&stats->lock);
#endif
}

static void
pcsc_api_stat_add(struct pcsc_api_stat *stat, uint64_t ns, LONG rv)
{
	if (stat->calls == 0 || ns < stat->min_ns)
		stat->min_ns = ns;
	if (ns > stat->max_ns)
		stat->max_ns = ns;
	stat->calls++;
	stat->total_ns += ns;
	if (rv != SCARD_S_SUCCESS)
		stat->errors++;
}

static void
pcsc_api_stats_record(struct pcsc_api *api, enum pcsc_api_fn fn,
		const char *caller, int line, uint64_t start_ns, LONG rv)
{
	struct pcsc_api_stats *stats = api->stats;
	uint64_t ns;
	size_t i;

	if (stats == NULL)
		return;
	ns = pcsc_api_now_ns() - start_ns;
	if (caller == NULL)
		caller = "?";

	pcsc_api_stats_lock(stats);
	pcsc_api_stat_add(&stats->fn[fn], ns, rv);
	for (i = 0; i < stats->nsites; i++) {
		struct pcsc_api_site *site = &stats->sites[i];
		if (site->fn == fn && site->line == line && strcmp(site->caller, caller) == 0)
			break;
	}
	if (i == stats->nsites && stats->nsites < PCSC_API_MAX_SITES) {
		stats->sites[i].fn = fn;
		stats->sites[i].caller = caller;
		stats->sites[i].line = line;
		stats->nsites++;
	}
	if (i < stats->nsites)
		pcsc_api_stat_add(&stats->sites[i].stat, ns, rv);
	else
		stats->dropped++;
	pcsc_api_stats_unlock(stats);
}

static void
pcsc_api_stats_init(struct pcsc_api *api)
{
	struct pcsc_api_stats *stats = calloc(1, sizeof *stats);

	if (stats == NULL)
		return;
#if defined(_WIN32)
	InitializeCriticalSection(&stats->lock);
#elif defined(HAVE_PTHREAD)
	pthread_mutex_init(&stats->lock, NULL);
#endif
	stats->start_ns = pcsc_api_now_ns();
	api->stats = stats;
}

static void
pcsc_api_json_string(FILE *f, const char *s)
{
	fputc('"', f);
	for (; s && *s; s++) {
		if (*s == '"' || *s == '\\')
			fprintf(f, "\\%c", *s);
		else if ((unsigned char)*s < 0x20)
			fprintf(f, "\\u%04x", (unsigned char)*s);
		else
			fputc(*s, f);
	}
	fputc('"', f);
}

static void
pcsc_api_json_stat(FILE *f, const struct pcsc_api_stat *stat)
{
	fprintf(f, "\"calls\":%lu,\"errors\":%lu,\"total_ns\":%llu,\"min_ns\":%llu,\"max_ns\":%llu",
			stat->calls, stat->errors, (unsigned long long)stat->total_ns,
			(unsigned long long)stat->min_ns, (unsigned long long)stat->max_ns);
}

/* One JSON object per line, so several processes can append to one file */
static void
pcsc_api_stats_write_json(sc_context_t *ctx, struct pcsc_api_stats *stats, FILE *f)
{
	size_t i;
	int first = 1;

	fprintf(f, "{\"version\":1,\"pid\":%ld,\"app\":", (long)getpid());
	pcsc_api_json_string(f, ctx->app_name);
	fprintf(f, ",\"elapsed_ns\":%llu,\"dropped\":%lu,\"functions\":{",
			(unsigned long long)(pcsc_api_now_ns() - stats->start_ns), stats->dropped);
	for (i = 0; i < PCSC_FN_COUNT; i++) {
		if (stats->fn[i].calls == 0)
			continue;
		fprintf(f, "%s\"%s\":{", first ? "" : ",", pcsc_api_fn_names[i]);
		pcsc_api_json_stat(f, &stats->fn[i]);
		fputc('}', f);
		first = 0;
	}
	fprintf(f, "},\"sites\":[");
	for (i = 0; i < stats->nsites; i++) {
		fprintf(f, "%s{\"fn\":\"%s\",\"caller\":", i ? "," : "",
				pcsc_api_fn_names[stats->sites[i].fn]);
		pcsc_api_json_string(f, stats->sites[i].caller);
		fprintf(f, ",\"line\":%d,", stats->sites[i].line);
		pcsc_api_json_stat(f, &stats->sites[i].stat);
		fputc('}', f);
	}
	fprintf(f, "]}\n");
}

static void
pcsc_api_stats_log(sc_context_t *ctx, struct pcsc_api_stats *stats)
{
	size_t i;

	sc_log(ctx, "PC/SC statistics (%lu calls dropped from site table):", stats->dropped);
	for (i = 0; i < PCSC_FN_COUNT; i++) {
		if (stats->fn[i].calls == 0)
			continue;
		sc_log(ctx, "  %-32s calls=%lu errors=%lu total=%lluus",
				pcsc_api_fn_names[i], stats->fn[i].calls, stats->fn[i].errors,
				(unsigned long long)(stats->fn[i].total_ns / 1000));
	}
	for (i = 0; i < stats->nsites; i++) {
		struct pcsc_api_site *site = &stats->sites[i];
		sc_log(ctx, "  %-32s %s:%d calls=%lu errors=%lu total=%lluus",
				pcsc_api_fn_names[site->fn], site->caller, site->line,
				site->stat.calls, site->stat.errors,
				(unsigned long long)(site->stat.total_ns / 1000));
	}
}

static void
pcsc_api_stats_finish(sc_context_t *ctx, struct pcsc_api *api)
{
	struct pcsc_api_stats *stats = api->stats;
	const char *path = getenv("OPENSC_PCSC_STATS");
	FILE *f = NULL;

	if (stats == NULL)
		return;
	api->stats = NULL;

	if (path != NULL && *path != '\0')
		f = fopen(path, "a");
	if (f != NULL) {
		pcsc_api_stats_write_json(ctx, stats, f);
		fclose(f);
	} else {
		pcsc_api_stats_log(ctx, stats);
	}

#if defined(_WIN32)
	DeleteCriticalSection(&stats->lock);
#elif defined(HAVE_PTHREAD)
	pthread_mutex_destroy(&stats->lock);
#endif
	free(stats);
}

#define PCSC_API_WRAP(fnid, call) \
	do { \
		uint64_t start_ns = api->stats ? pcsc_api_now_ns() : 0; \
		LONG rv = (call); \
		pcsc_api_stats_record(api, (fnid), caller, line, start_ns, rv); \
		return rv; \
	} while (0)

#else /* PCSC_API_STATS */

#define pcsc_api_stats_init(api)
#define pcsc_api_stats_finish(ctx, api)
#define PCSC_API_WRAP(fnid, call) \
	do { \
		(void)caller; \
		(void)line; \
		return (call); \
	} while (0)

#endif /* PCSC_API_STATS */

int
pcsc_api_load(sc_context_t *ctx, struct pcsc_api *api, const char *provider_library)
{
	memset(api, 0, sizeof *api);

	api->dlhandle = sc_dlopen(provider_library);
	if (api->dlhandle == NULL)
		return SC_ERROR_CANNOT_LOAD_MODULE;

	api->SCardEstablishContext = (SCardEstablishContext_t)sc_dlsym(api->dlhandle, "SCardEstablishContext");
	api->SCardReleaseContext = (SCardReleaseContext_t)sc_dlsym(api->dlhandle, "SCardReleaseContext");
	api->SCardConnect = (SCardConnect_t)sc_dlsym(api->dlhandle, "SCardConnect");
	api->SCardReconnect = (SCardReconnect_t)sc_dlsym(api->dlhandle, "SCardReconnect");
	api->SCardDisconnect = (SCardDisconnect_t)sc_dlsym(api->dlhandle, "SCardDisconnect");
	api->SCardBeginTransaction = (SCardBeginTransaction_t)sc_dlsym(api->dlhandle, "SCardBeginTransaction");
	api->SCardEndTransaction = (SCardEndTransaction_t)sc_dlsym(api->dlhandle, "SCardEndTransaction");
	api->SCardStatus = (SCardStatus_t)sc_dlsym(api->dlhandle, "SCardStatus");
	api->SCardGetStatusChange = (SCardGetStatusChange_t)sc_dlsym(api->dlhandle, "SCardGetStatusChange");
	api->SCardCancel = (SCardCancel_t)sc_dlsym(api->dlhandle, "SCardCancel");
	api->SCardTransmit = (SCardTransmit_t)sc_dlsym(api->dlhandle, "SCardTransmit");
	api->SCardListReaders = (SCardListReaders_t)sc_dlsym(api->dlhandle, "SCardListReaders");

	if (api->SCardConnect == NULL)
		api->SCardConnect = (SCardConnect_t)sc_dlsym(api->dlhandle, "SCardConnectA");
	if (api->SCardStatus == NULL)
		api->SCardStatus = (SCardStatus_t)sc_dlsym(api->dlhandle, "SCardStatusA");
	if (api->SCardGetStatusChange == NULL)
		api->SCardGetStatusChange = (SCardGetStatusChange_t)sc_dlsym(api->dlhandle, "SCardGetStatusChangeA");
	if (api->SCardListReaders == NULL)
		api->SCardListReaders = (SCardListReaders_t)sc_dlsym(api->dlhandle, "SCardListReadersA");

	/* If we have SCardGetAttrib it is correct API */
	api->SCardGetAttrib = (SCardGetAttrib_t)sc_dlsym(api->dlhandle, "SCardGetAttrib");
	if (api->SCardGetAttrib != NULL) {
#ifdef __APPLE__
		api->SCardControl = (SCardControl_t)sc_dlsym(api->dlhandle, "SCardControl132");
#endif
		if (api->SCardControl == NULL) {
			api->SCardControl = (SCardControl_t)sc_dlsym(api->dlhandle, "SCardControl");
		}
	} else {
		api->SCardControlOLD = (SCardControlOLD_t)sc_dlsym(api->dlhandle, "SCardControl");
	}

	if (
			api->SCardReleaseContext == NULL ||
			api->SCardConnect == NULL ||
			api->SCardReconnect == NULL ||
			api->SCardDisconnect == NULL ||
			api->SCardBeginTransaction == NULL ||
			api->SCardEndTransaction == NULL ||
			api->SCardStatus == NULL ||
			api->SCardGetStatusChange == NULL ||
			api->SCardCancel == NULL ||
			(api->SCardControl == NULL && api->SCardControlOLD == NULL) ||
			api->SCardTransmit == NULL ||
			api->SCardListReaders == NULL) {
		sc_dlclose(api->dlhandle);
		memset(api, 0, sizeof *api);
		return SC_ERROR_CANNOT_LOAD_MODULE;
	}

	pcsc_api_stats_init(api);

	return SC_SUCCESS;
}

void
pcsc_api_unload(sc_context_t *ctx, struct pcsc_api *api)
{
	pcsc_api_stats_finish(ctx, api);
	if (api->dlhandle != NULL)
		sc_dlclose(api->dlhandle);
	memset(api, 0, sizeof *api);
}

LONG
pcsc_api_SCardEstablishContext(struct pcsc_api *api, const char *caller, int line,
		DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
{
	PCSC_API_WRAP(PCSC_FN_SCardEstablishContext,
			api->SCardEstablishContext(dwScope, pvReserved1, pvReserved2, phContext));
}

LONG
pcsc_api_SCardReleaseContext(struct pcsc_api *api, const char *caller, int line,
		SCARDCONTEXT hContext)
{
	PCSC_API_WRAP(PCSC_FN_SCardReleaseContext, api->SCardReleaseContext(hContext));
}

LONG
pcsc_api_SCardConnect(struct pcsc_api *api, const char *caller, int line,
		SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
		DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
{
	PCSC_API_WRAP(PCSC_FN_SCardConnect,
			api->SCardConnect(hContext, szReader, dwShareMode, dwPreferredProtocols,
					phCard, pdwActiveProtocol));
}

LONG
pcsc_api_SCardReconnect(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols,
		DWORD dwInitialization, LPDWORD pdwActiveProtocol)
{
	PCSC_API_WRAP(PCSC_FN_SCardReconnect,
			api->SCardReconnect(hCard, dwShareMode, dwPreferredProtocols,
					dwInitialization, pdwActiveProtocol));
}

LONG
pcsc_api_SCardDisconnect(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, DWORD dwDisposition)
{
	PCSC_API_WRAP(PCSC_FN_SCardDisconnect, api->SCardDisconnect(hCard, dwDisposition));
}

LONG
pcsc_api_SCardBeginTransaction(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard)
{
	PCSC_API_WRAP(PCSC_FN_SCardBeginTransaction, api->SCardBeginTransaction(hCard));
}

LONG
pcsc_api_SCardEndTransaction(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, DWORD dwDisposition)
{
	PCSC_API_WRAP(PCSC_FN_SCardEndTransaction, api->SCardEndTransaction(hCard, dwDisposition));
}

LONG
pcsc_api_SCardStatus(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, LPSTR mszReaderNames, LPDWORD pcchReaderLen,
		LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
	PCSC_API_WRAP(PCSC_FN_SCardStatus,
			api->SCardStatus(hCard, mszReaderNames, pcchReaderLen, pdwState,
					pdwProtocol, pbAtr, pcbAtrLen));
}

LONG
pcsc_api_SCardGetStatusChange(struct pcsc_api *api, const char *caller, int line,
		SCARDCONTEXT hContext, DWORD dwTimeout, SCARD_READERSTATE *rgReaderStates, DWORD cReaders)
{
	PCSC_API_WRAP(dwTimeout ? PCSC_FN_SCardGetStatusChange_blocking : PCSC_FN_SCardGetStatusChange,
			api->SCardGetStatusChange(hContext, dwTimeout, rgReaderStates, cReaders));
}

LONG
pcsc_api_SCardCancel(struct pcsc_api *api, const char *caller, int line,
		SCARDCONTEXT hContext)
{
	PCSC_API_WRAP(PCSC_FN_SCardCancel, api->SCardCancel(hContext));
}

LONG
pcsc_api_SCardControlOLD(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, LPCVOID pbSendBuffer, DWORD cbSendLength,
		LPVOID pbRecvBuffer, LPDWORD lpBytesReturned)
{
	PCSC_API_WRAP(PCSC_FN_SCardControlOLD,
			api->SCardControlOLD(hCard, pbSendBuffer, cbSendLength, pbRecvBuffer,
					lpBytesReturned));
}

LONG
pcsc_api_SCardControl(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer,
		DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength,
		LPDWORD lpBytesReturned)
{
	PCSC_API_WRAP(PCSC_FN_SCardControl,
			api->SCardControl(hCard, dwControlCode, pbSendBuffer, cbSendLength,
					pbRecvBuffer, cbRecvLength, lpBytesReturned));
}

LONG
pcsc_api_SCardTransmit(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci,
		LPCBYTE pbSendBuffer, DWORD cbSendLength, LPSCARD_IO_REQUEST pioRecvPci,
		LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength)
{
	PCSC_API_WRAP(PCSC_FN_SCardTransmit,
			api->SCardTransmit(hCard, pioSendPci, pbSendBuffer, cbSendLength,
					pioRecvPci, pbRecvBuffer, pcbRecvLength));
}

LONG
pcsc_api_SCardListReaders(struct pcsc_api *api, const char *caller, int line,
		SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders)
{
	PCSC_API_WRAP(PCSC_FN_SCardListReaders,
			api->SCardListReaders(hContext, mszGroups, mszReaders, pcchReaders));
}

LONG
pcsc_api_SCardGetAttrib(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr, LPDWORD pcbAttrLen)
{
	PCSC_API_WRAP(PCSC_FN_SCardGetAttrib,
			api->SCardGetAttrib(hCard, dwAttrId, pbAttr, pcbAttrLen));
}

#endif /* ENABLE_PCSC */
