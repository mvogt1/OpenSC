/*
 * pcsc-api.h: Loading of and access to the PC/SC provider library
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

#ifndef _OPENSC_PCSC_API_H
#define _OPENSC_PCSC_API_H

#include "libopensc/internal-winscard.h"
#include "libopensc/opensc.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pcsc_api_stats;

/* Function pointers of the loaded PC/SC provider library. The pointers may
 * be tested for NULL, but calls must go through PCSC_CALL() so that they are
 * accounted for when statistics are enabled (PCSC_API_STATS in pcsc-api.c). */
struct pcsc_api {
	void *dlhandle;
	SCardEstablishContext_t SCardEstablishContext;
	SCardReleaseContext_t SCardReleaseContext;
	SCardConnect_t SCardConnect;
	SCardReconnect_t SCardReconnect;
	SCardDisconnect_t SCardDisconnect;
	SCardBeginTransaction_t SCardBeginTransaction;
	SCardEndTransaction_t SCardEndTransaction;
	SCardStatus_t SCardStatus;
	SCardGetStatusChange_t SCardGetStatusChange;
	SCardCancel_t SCardCancel;
	SCardControlOLD_t SCardControlOLD;
	SCardControl_t SCardControl;
	SCardTransmit_t SCardTransmit;
	SCardListReaders_t SCardListReaders;
	SCardGetAttrib_t SCardGetAttrib;

	struct pcsc_api_stats *stats;
};

/* Loads the provider library and resolves all symbols.
 * Returns SC_SUCCESS or SC_ERROR_CANNOT_LOAD_MODULE. */
int pcsc_api_load(sc_context_t *ctx, struct pcsc_api *api, const char *provider_library);
/* Writes the statistics (if enabled) and unloads the provider library. */
void pcsc_api_unload(sc_context_t *ctx, struct pcsc_api *api);

/* Calls a PC/SC function and records the calling function and line:
 *   rv = PCSC_CALL(&gpriv->api, SCardTransmit, card, ...); */
#define PCSC_CALL(api, fn, ...) pcsc_api_##fn((api), __FUNCTION__, __LINE__, __VA_ARGS__)

LONG pcsc_api_SCardEstablishContext(struct pcsc_api *api, const char *caller, int line,
		DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext);
LONG pcsc_api_SCardReleaseContext(struct pcsc_api *api, const char *caller, int line,
		SCARDCONTEXT hContext);
LONG pcsc_api_SCardConnect(struct pcsc_api *api, const char *caller, int line,
		SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
		DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);
LONG pcsc_api_SCardReconnect(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols,
		DWORD dwInitialization, LPDWORD pdwActiveProtocol);
LONG pcsc_api_SCardDisconnect(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, DWORD dwDisposition);
LONG pcsc_api_SCardBeginTransaction(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard);
LONG pcsc_api_SCardEndTransaction(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, DWORD dwDisposition);
LONG pcsc_api_SCardStatus(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, LPSTR mszReaderNames, LPDWORD pcchReaderLen,
		LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen);
LONG pcsc_api_SCardGetStatusChange(struct pcsc_api *api, const char *caller, int line,
		SCARDCONTEXT hContext, DWORD dwTimeout, SCARD_READERSTATE *rgReaderStates, DWORD cReaders);
LONG pcsc_api_SCardCancel(struct pcsc_api *api, const char *caller, int line,
		SCARDCONTEXT hContext);
LONG pcsc_api_SCardControlOLD(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, LPCVOID pbSendBuffer, DWORD cbSendLength,
		LPVOID pbRecvBuffer, LPDWORD lpBytesReturned);
LONG pcsc_api_SCardControl(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer,
		DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength,
		LPDWORD lpBytesReturned);
LONG pcsc_api_SCardTransmit(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci,
		LPCBYTE pbSendBuffer, DWORD cbSendLength, LPSCARD_IO_REQUEST pioRecvPci,
		LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength);
LONG pcsc_api_SCardListReaders(struct pcsc_api *api, const char *caller, int line,
		SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders);
LONG pcsc_api_SCardGetAttrib(struct pcsc_api *api, const char *caller, int line,
		SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr, LPDWORD pcbAttrLen);

#ifdef __cplusplus
}
#endif

#endif /* _OPENSC_PCSC_API_H */
