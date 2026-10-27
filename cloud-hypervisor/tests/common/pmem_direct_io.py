#!/usr/bin/env python3
# Copyright (c) 2026 Crusoe Energy Systems LLC
#
# SPDX-License-Identifier: Apache-2.0
#
# pmem_direct_io.py SIZE COUNT PATH: direct I/O of COUNT x SIZE bytes to PATH
# from a mapping of the virtio-pmem, which this script first turns into a
# device-dax character device through sysfs (no ndctl needed). Prints where
# the buffer is, "pmem buffer: yes" when it lies in the namespace, then "OK:"
# or what went wrong. Run as root.
import ctypes
import mmap
import os
import sys
import time

size, count, path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
NVDIMM_BUS, NS = "/sys/bus/nd", "namespace0.0"


def rd(p):
    with open(p) as f:
        return f.read().strip()


def wr(p, v):
    with open(p, "w") as f:
        f.write(v)


def pattern(i):
    return bytes([(0xA5 + i) & 0xFF]) * size


if not os.path.exists("/dev/dax0.0"):
    if os.path.exists(f"{NVDIMM_BUS}/drivers/nd_pmem/{NS}"):
        wr(f"{NVDIMM_BUS}/drivers/nd_pmem/unbind", NS)  # release /dev/pmem0

    # The region's unused dax personality device, "dax0.0".
    dax = rd(f"{NVDIMM_BUS}/devices/region0/dax_seed")
    wr(f"{NVDIMM_BUS}/devices/{dax}/uuid", rd("/proc/sys/kernel/random/uuid"))
    wr(f"{NVDIMM_BUS}/devices/{dax}/mode", "ram")  # struct pages in RAM (--map=mem)
    wr(f"{NVDIMM_BUS}/devices/{dax}/namespace", NS)
    wr(f"{NVDIMM_BUS}/drivers_probe", dax)  # dax_pmem binds it: /dev/dax0.0

    for _ in range(100):
        if os.path.exists("/dev/dax0.0"):
            break
        time.sleep(0.1)
    if not os.path.exists("/dev/dax0.0"):
        print(f"no /dev/dax0.0 after configuring {dax}")
        sys.exit(2)

ns_start = int(rd(f"{NVDIMM_BUS}/devices/{NS}/resource"), 16)
ns_size = int(rd(f"{NVDIMM_BUS}/devices/{NS}/size"))
align = int(rd("/sys/bus/dax/devices/dax0.0/align"))

fd = os.open("/dev/dax0.0", os.O_RDWR)
buf = mmap.mmap(fd, max(size, align), flags=mmap.MAP_SHARED,
                prot=mmap.PROT_READ | mmap.PROT_WRITE)
os.close(fd)
view = memoryview(buf)[:size]
addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
buf.write(pattern(0))  # fault the page in before reading its PFN

with open("/proc/self/pagemap", "rb") as pm:
    pm.seek(addr // mmap.PAGESIZE * 8)
    entry = int.from_bytes(pm.read(8), "little")
pa = (entry & ((1 << 55) - 1)) * mmap.PAGESIZE
inside = "yes" if ns_start <= pa < ns_start + ns_size else "no"
print(f"buffer {size} B at 0x{addr:x} pa 0x{pa:x}, {NS} at 0x{ns_start:x}"
      f"+0x{ns_size:x}", flush=True)
print(f"pmem buffer: {inside}", flush=True)

fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_DIRECT, 0o644)
try:
    for i in range(count):
        buf.seek(0)
        buf.write(pattern(i))
        n = os.pwrite(fd, view, i * size)
        if n != size:
            print(f"short write {n} at {i}")
            sys.exit(3)
    os.fsync(fd)

    for i in range(count):
        buf.seek(0)
        buf.write(bytes(size))
        n = os.preadv(fd, [view], i * size)
        if n != size:
            print(f"short read {n} at {i}")
            sys.exit(3)
        if bytes(view) != pattern(i):
            print(f"data mismatch at {i}")
            sys.exit(4)

    print(f"OK: {count} x {size} B direct I/O write+read from pmem")
except OSError as e:
    print(f"IO ERROR: {e}")
    sys.exit(5)
finally:
    os.close(fd)
