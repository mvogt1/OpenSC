#!/usr/bin/env python3
"""Keep a PKCS#11 module loaded and poll the token once per second.

usage: p11loop.py MODULE [SECONDS]

Every second it calls C_GetSlotList(token present), C_GetSlotInfo and, in a
new session, C_FindObjects, and prints the slot flags and the number of
objects.  Use it to see card removal/insertion in a running process, or
with "pcscd-monitor.py -w -e" to count the PC/SC calls of a long run.
"""
import ctypes as C
import sys
import time

CK_ULONG = C.c_ulong
CKF_TOKEN_PRESENT = 1
CKF_SERIAL_SESSION = 4


class CK_VERSION(C.Structure):
    _fields_ = [("major", C.c_ubyte), ("minor", C.c_ubyte)]


class CK_SLOT_INFO(C.Structure):
    _fields_ = [("slotDescription", C.c_char * 64), ("manufacturerID", C.c_char * 32),
                ("flags", CK_ULONG), ("hardwareVersion", CK_VERSION),
                ("firmwareVersion", CK_VERSION)]


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        return
    lib = C.CDLL(sys.argv[1])
    seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    rv = lib.C_Initialize(None)
    print("C_Initialize rv=0x%x" % rv, flush=True)
    for i in range(seconds):
        n = CK_ULONG(16)
        slots = (CK_ULONG * 16)()
        rv = lib.C_GetSlotList(C.c_ubyte(1), slots, C.byref(n))
        line = "%3d %s GetSlotList(token) rv=0x%x n=%d" % (i, time.strftime("%H:%M:%S"), rv, n.value)
        if rv == 0 and n.value > 0:
            info = CK_SLOT_INFO()
            rv = lib.C_GetSlotInfo(slots[0], C.byref(info))
            line += " | slot flags=0x%x" % info.flags
            sess = CK_ULONG()
            rv = lib.C_OpenSession(slots[0], CK_ULONG(CKF_SERIAL_SESSION), None, None, C.byref(sess))
            if rv == 0:
                objs = (CK_ULONG * 256)()
                cnt = CK_ULONG()
                lib.C_FindObjectsInit(sess, None, CK_ULONG(0))
                rv = lib.C_FindObjects(sess, objs, CK_ULONG(256), C.byref(cnt))
                lib.C_FindObjectsFinal(sess)
                line += " | objects=%d rv=0x%x" % (cnt.value, rv)
                lib.C_CloseSession(sess)
            else:
                line += " | OpenSession rv=0x%x" % rv
        print(line, flush=True)
        time.sleep(1)
    print("C_Finalize rv=0x%x" % lib.C_Finalize(None), flush=True)


if __name__ == "__main__":
    main()
