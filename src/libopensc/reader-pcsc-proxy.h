/*
 * reader-pcsc-proxy.h: Proxy for PC/SC status calls of the PC/SC driver
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

#ifndef _READER_PCSC_PROXY_H
#define _READER_PCSC_PROXY_H

#include "internal.h"
#include "internal-winscard.h"

/*
 * reader-pcsc.c calls SCardGetStatusChange(), SCardStatus(),
 * SCardListReaders() and SCardCancel() through
 * this proxy.  The proxy may answer a call itself instead of asking PC/SC.
 */
struct pcsc_proxy_monitor;

struct pcsc_proxy {
	sc_context_t *ctx;

	/* the real PC/SC functions */
	SCardGetStatusChange_t SCardGetStatusChange;
	SCardStatus_t SCardStatus;
	SCardListReaders_t SCardListReaders;
	SCardCancel_t SCardCancel;
	/* used by the monitor thread */
	SCardEstablishContext_t SCardEstablishContext;
	SCardReleaseContext_t SCardReleaseContext;

	/* NULL: every call goes to PC/SC */
	struct pcsc_proxy_monitor *monitor;
};

void pcsc_proxy_init(struct pcsc_proxy *proxy, sc_context_t *ctx,
		SCardGetStatusChange_t get_status_change, SCardStatus_t status,
		SCardListReaders_t list_readers, SCardCancel_t cancel);
/* start the thread that answers SCardGetStatusChange(), repeated
 * SCardStatus() and SCardListReaders() calls, needs the
 * SCardEstablishContext and SCardReleaseContext members to be set */
int pcsc_proxy_start_monitor(struct pcsc_proxy *proxy);
void pcsc_proxy_finish(struct pcsc_proxy *proxy);
/* the card handle was disconnected, reconnected or a call on it failed:
 * do not answer SCardStatus() for it from the copy any more */
void pcsc_proxy_card_forget(struct pcsc_proxy *proxy, SCARDHANDLE hCard);

LONG pcsc_proxy_SCardGetStatusChange(struct pcsc_proxy *proxy, SCARDCONTEXT hContext,
		DWORD dwTimeout, SCARD_READERSTATE *rgReaderStates, DWORD cReaders);
LONG pcsc_proxy_SCardStatus(struct pcsc_proxy *proxy, SCARDHANDLE hCard,
		LPSTR mszReaderNames, LPDWORD pcchReaderLen, LPDWORD pdwState,
		LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen);
LONG pcsc_proxy_SCardCancel(struct pcsc_proxy *proxy, SCARDCONTEXT hContext);
LONG pcsc_proxy_SCardListReaders(struct pcsc_proxy *proxy, SCARDCONTEXT hContext,
		LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders);

#endif
