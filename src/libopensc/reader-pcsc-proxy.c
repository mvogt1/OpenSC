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

void pcsc_proxy_init(struct pcsc_proxy *proxy, sc_context_t *ctx,
		SCardGetStatusChange_t get_status_change, SCardStatus_t status)
{
	proxy->ctx = ctx;
	proxy->SCardGetStatusChange = get_status_change;
	proxy->SCardStatus = status;
}

void pcsc_proxy_finish(struct pcsc_proxy *proxy)
{
	(void)proxy;
}

LONG pcsc_proxy_SCardGetStatusChange(struct pcsc_proxy *proxy, SCARDCONTEXT hContext,
		DWORD dwTimeout, SCARD_READERSTATE *rgReaderStates, DWORD cReaders)
{
	return proxy->SCardGetStatusChange(hContext, dwTimeout, rgReaderStates, cReaders);
}

LONG pcsc_proxy_SCardStatus(struct pcsc_proxy *proxy, SCARDHANDLE hCard,
		LPSTR mszReaderNames, LPDWORD pcchReaderLen, LPDWORD pdwState,
		LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
	return proxy->SCardStatus(hCard, mszReaderNames, pcchReaderLen, pdwState,
			pdwProtocol, pbAtr, pcbAtrLen);
}

#endif   /* ENABLE_PCSC */
