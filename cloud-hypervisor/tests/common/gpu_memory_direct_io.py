#!/usr/bin/env python3
# Copyright (c) 2026 Crusoe Energy Systems LLC
#
# SPDX-License-Identifier: Apache-2.0
#
# gpu_memory_direct_io.py NODE SIZE COUNT PATH: direct I/O of COUNT x SIZE
# bytes to PATH from a buffer whose pages are bound to NUMA node NODE, the
# node under which the NVIDIA driver onlines a Grace GPU's memory. Prints the
# buffer's actual node, then "OK:" or what went wrong. Run as root.
import ctypes
import mmap
import os
import sys

NR_SET_MEMPOLICY, NR_MOVE_PAGES, MPOL_BIND = 237, 239, 2  # arm64
libc = ctypes.CDLL(None, use_errno=True)

node, size, count, path = (int(sys.argv[1]), int(sys.argv[2]),
                           int(sys.argv[3]), sys.argv[4])


def pattern(i):
    return bytes([(0xA5 + i) & 0xFF]) * size


mask = ctypes.c_ulong(1 << node)
if libc.syscall(NR_SET_MEMPOLICY, MPOL_BIND, ctypes.byref(mask),
                ctypes.c_ulong(64)) != 0:
    print(f"set_mempolicy failed errno={ctypes.get_errno()}")
    sys.exit(2)

buf = mmap.mmap(-1, size)
buf.write(pattern(0))

addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
pages = (ctypes.c_void_p * 1)(addr)
status = (ctypes.c_int * 1)(-1)
libc.syscall(NR_MOVE_PAGES, 0, ctypes.c_ulong(1), pages, None, status, 0)
print(f"buffer {size} B at 0x{addr:x} is on node {status[0]} "
      f"(requested {node})", flush=True)

fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_DIRECT, 0o644)
try:
    for i in range(count):
        buf.seek(0)
        buf.write(pattern(i))
        n = os.pwrite(fd, buf, i * size)
        if n != size:
            print(f"short write {n} at {i}")
            sys.exit(3)
    os.fsync(fd)

    for i in range(count):
        buf.seek(0)
        buf.write(bytes(size))
        n = os.preadv(fd, [buf], i * size)
        if n != size:
            print(f"short read {n} at {i}")
            sys.exit(3)
        if buf[:size] != pattern(i):
            print(f"data mismatch at {i}")
            sys.exit(4)

    print(f"OK: {count} x {size} B direct I/O write+read from node {status[0]}")
except OSError as e:
    print(f"IO ERROR: {e}")
    sys.exit(5)
finally:
    os.close(fd)
