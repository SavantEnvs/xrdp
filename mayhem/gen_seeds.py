#!/usr/bin/env python3
"""Generates the seed corpora (mayhem/<target>/testsuite) and prelude.inc.

Usage: python3 mayhem/gen_seeds.py mayhem
"""
import os, struct, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "."
u8 = lambda v: struct.pack("<B", v)
u16 = lambda v: struct.pack("<H", v)
u32 = lambda v: struct.pack("<I", v)
i32 = lambda v: struct.pack("<i", v)
be16 = lambda v: struct.pack(">H", v)
utf16 = lambda s: s.encode("utf-16-le")


def tpkt(p):
    return b"\x03\x00" + be16(len(p) + 4) + p


def dt(p):
    return tpkt(b"\x02\xf0\x80" + p)


def per_len(n):
    return be16(0x8000 | n)


def ber_len(n):
    return b"\x82" + be16(n)


def x224_cr(cookie=b"Cookie: mstshash=fuzz\r\n", proto=0):
    body = b"\xe0\x00\x00\x00\x00\x00" + cookie + b"\x01\x00\x08\x00" + u32(proto)
    return tpkt(bytes([len(body)]) + body)


def block(tag, body):
    return u16(tag) + u16(len(body) + 4) + body


def cs_core(early=0x0001, width=1024, height=768):
    b = u32(0x00080004) + u16(width) + u16(height) + u16(0xCA01) + u16(0xAA03)
    b += u32(0x409) + u32(19041) + utf16("fuzz").ljust(32, b"\0")
    b += u32(4) + u32(0) + u32(12) + b"\0" * 64
    b += u16(0xCA01) + u16(1) + u32(0) + u16(24) + u16(0x000F) + u16(early)
    b += b"\0" * 64 + u8(7) + u8(0) + u32(0)
    b += u32(340) + u32(190) + u16(0) + u32(100) + u32(100)
    return block(0xC001, b)


def cs_security(m=0x1B):
    return block(0xC002, u32(m) + u32(0))


def cs_net(names=("rdpdr", "rdpsnd", "cliprdr")):
    opts = [0x80800000, 0xC0000000, 0xC0A00000]
    b = u32(len(names))
    for n, o in zip(names, opts):
        b += n.encode().ljust(8, b"\0") + u32(o)
    return block(0xC003, b)


def cs_cluster():
    return block(0xC004, u32(0x0D) + u32(0))


def cs_monitor(n=1):
    b = u32(0) + u32(n)
    for i in range(n):
        b += i32(i * 1024) + i32(0) + i32(i * 1024 + 1023) + i32(767) + u32(1 if i == 0 else 0)
    return block(0xC005, b)


def cs_monitor_ex(n=1):
    b = u32(0) + u32(20) + u32(n)
    for i in range(n):
        b += u32(340) + u32(190) + u32(0) + u32(100) + u32(100)
    return block(0xC008, b)


def connect_initial(blocks):
    ud = b"".join(blocks)
    rest = b"\x00\x08\x00\x10\x00\x01\xc0\x00Duca" + per_len(len(ud)) + ud
    gcc = b"\x00\x05\x00\x14\x7c\x00\x01" + per_len(len(rest)) + rest
    def ber_int(v):
        n = 1 if v < 0x80 else 2 if v < 0x8000 else 3
        return b"\x02" + bytes([n]) + v.to_bytes(n, "big")

    def dp(vals):
        body = b"".join(ber_int(v) for v in vals)
        return b"\x30" + bytes([len(body)]) + body
    dp_t = dp([34, 2, 0, 1, 0, 1, 0xFFFF, 2])
    dp_min = dp([1, 1, 1, 1, 0, 1, 0x420, 2])
    dp_max = dp([0xFFFF, 0xFC17, 0xFFFF, 1, 0, 1, 0xFFFF, 2])
    ci = b"\x04\x01\x01\x04\x01\x01\x01\x01\xff" + dp_t + dp_min + dp_max
    ci += b"\x04" + ber_len(len(gcc)) + gcc
    return dt(b"\x7f\x65" + ber_len(len(ci)) + ci)


def edrq():
    return dt(b"\x04\x01\x00\x01\x00")


def aurq():
    return dt(b"\x28")


def cjrq(user, chan):
    return dt(b"\x38" + be16(user) + be16(chan))


def sdrq(chan, payload, user=1):
    ln = len(payload)
    plen = bytes([ln]) if ln < 128 else be16(0x8000 | ln)
    return dt(b"\x64" + be16(user) + be16(chan) + b"\x70" + plen + payload)


def client_info(flags=0x33 | 0x100 | 0x40000 * 0, extended=True):
    flags = 0x33 | (0x100 if extended else 0)  # INFO_ENABLEWINDOWSKEY gates the extended packet
    dom, user, pw, shell, wd = "", "fuzz", "", "", ""
    b = u32(0) + u32(flags)
    b += u16(len(utf16(dom))) + u16(len(utf16(user))) + u16(len(utf16(pw)))
    b += u16(len(utf16(shell))) + u16(len(utf16(wd)))
    for t in (dom, user, pw, shell, wd):
        b += utf16(t) + b"\0\0"
    if extended:
        addr = utf16("10.0.0.1") + b"\0\0"
        cdir = utf16("C:\\") + b"\0\0"
        b += u16(2) + u16(len(addr)) + addr + u16(len(cdir)) + cdir
        b += i32(0) + utf16("UTC").ljust(64, b"\0") + b"\0" * 16 + i32(0)
        b += utf16("UTC").ljust(64, b"\0") + b"\0" * 16 + i32(0)
        b += u32(0) + u32(0x80)
    return sdrq(1003, u32(0x40) + b)


def prelude(early=0x0001, nchan=3, monitors=1, ex=True, extended=True):
    names = ("rdpdr", "rdpsnd", "cliprdr")[:nchan]
    blocks = [cs_core(early), cs_cluster(), cs_security(), cs_net(names)] if nchan else \
             [cs_core(early), cs_cluster(), cs_security()]
    if monitors:
        blocks.append(cs_monitor(monitors))
        if ex:
            blocks.append(cs_monitor_ex(monitors))
    pdus = [x224_cr(), connect_initial(blocks), edrq(), aurq()]
    pdus.append(cjrq(1, 1002))
    pdus.append(cjrq(1, 1003))
    for i in range(nchan):
        pdus.append(cjrq(1, 1004 + i))
    pdus.append(client_info(extended=extended))
    return pdus


def share_ctl(pdutype, payload, source=1002):
    return u16(len(payload) + 6) + u16(pdutype) + u16(source) + payload


def share_data(pdutype2, payload, share_id=66538):
    body = u32(share_id) + u8(0) + u8(1) + u16(len(payload) + 18 - 6 + 0) + u8(pdutype2) + u8(0) + u16(0) + payload
    return share_ctl(0x17, body)


def secsdrq(chan, ctl, user=1):
    return sdrq(chan, ctl, user)


def confirm_active(caps):
    src = b"MSTSC\0"
    capdata = u16(len(caps)) + u16(0) + b"".join(caps)
    body = u32(66538) + u16(1002) + u16(len(src)) + u16(len(capdata)) + src + capdata
    return secsdrq(1003, share_ctl(0x13, body))


def cap(t, body):
    return u16(t) + u16(len(body) + 4) + body


def caps_set(variant=0):
    c = []
    extra = 0x0405 if variant == 0 else 0x0000
    c.append(cap(1, u16(1) + u16(3) + u16(0x200) + u16(0) + u16(0) + u16(extra)
                 + u16(0) + u16(0) + u16(0) + u8(1) + u8(1)))
    c.append(cap(2, u16(24) + u16(1) + u16(1) + u16(1) + u16(1024) + u16(768)
                 + u16(0) + u16(1) + u16(1) + u16(0) + u16(0x0100)))
    orders = bytes([1]) * 32 if variant == 0 else bytes(32)
    c.append(cap(3, b"\0" * 20 + u16(20) + u16(20) + u16(0) + u16(1) + u16(0) + u16(0x002A)
                 + orders + u16(0) + u16(0x0006) + u32(0) + u32(0x38400) + u32(0) + u32(0)))
    if variant == 0:
        c.append(cap(4, b"\0" * 24 + u16(600) + u16(256) + u16(300) + u16(1024) + u16(262) + u16(4096)))
    else:
        c.append(cap(0x13, u16(1) + u16(3) + u32(120) + u32(120) + u32(336) + b"\0" * 20))
    c.append(cap(5, b"\0" * 8))
    c.append(cap(8, u16(1) + u16(25) + u16(25)))
    c.append(cap(0xD, u16(0x0001 | 0x0010 | 0x0020 | 0x0004) + b"\0" * 84))
    c.append(cap(0xF, u32(2)))
    c.append(cap(0x10, b"\0" * 40 + u32(0) + u16(2) + u16(0)))
    c.append(cap(0x11, u32(1) + u16(7680) + u16(100)))
    c.append(cap(0x14, u32(0) + u32(1600)))
    if variant == 0:
        c.append(cap(0x17, u32(1)))
        c.append(cap(0x18, u32(1) + u8(1) + u16(100)))
        c.append(cap(0x1C, u32(0x52) + u32(0)))
        c.append(cap(0x1E, u32(1) + u32(0)))
    return c


def data_pdus():
    sync = share_data(0x1F, u16(1) + u16(1002))
    coop = share_data(0x14, u16(4) + u16(0) + u32(0))
    req = share_data(0x14, u16(1) + u16(0) + u32(0))
    fontl = share_data(0x27, u16(0) + u16(0) + u16(3) + u16(50))
    inp = share_data(0x1C, u16(2) + u16(0)
                     + u32(0) + u16(0x0004) + u16(0x1E) + u16(0)  # key event
                     + u32(0) + u16(0x8001) + u16(100) + u16(100))
    refresh = share_data(0x21, u8(1) + b"\0\0\0" + i32(0) + i32(0) + i32(100) + i32(100))
    suppress = share_data(0x23, u8(1) + b"\0\0\0")
    shutdown = share_data(0x24, b"")
    ack = share_data(0x38, u32(1))
    return {"sync": sync, "coop": coop, "req": req, "fontl": fontl, "input": inp,
            "refresh": refresh, "suppress": suppress, "shutdown": shutdown, "ack": ack}


def write(d, name, data):
    path = os.path.join(OUT, d, "testsuite")
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, name), "wb") as f:
        f.write(data)


pre = prelude()
dp = data_pdus()
# raw connection target: arbitrary prefixes of a full sequence
write("fuzz_rdp_connect", "cr_only", pre[0])
write("fuzz_rdp_connect", "cr_ci", pre[0] + pre[1])
write("fuzz_rdp_connect", "to_attach", b"".join(pre[:4]))
write("fuzz_rdp_connect", "to_join", b"".join(pre[:-1]))
write("fuzz_rdp_connect", "to_info", b"".join(pre))
write("fuzz_rdp_connect", "full_active", b"".join(pre) + confirm_active(caps_set()) + secsdrq(1003, dp["sync"]) + secsdrq(1003, dp["coop"]) + secsdrq(1003, dp["req"]) + secsdrq(1003, dp["fontl"]) + secsdrq(1003, dp["input"]))
write("fuzz_rdp_connect", "nochan_nomon", b"".join(prelude(nchan=0, monitors=0, extended=False)))
write("fuzz_rdp_connect", "multimon", b"".join(prelude(monitors=3)))
write("fuzz_rdp_connect", "skipjoin", b"".join(prelude(early=0x0001 | 0x0008)))

# post-handshake target: PDUs only; the harness supplies the prelude
write("fuzz_rdp_session", "confirm_active", confirm_active(caps_set()))
write("fuzz_rdp_session", "confirm_active_v2", confirm_active(caps_set(1)))
for k, v in dp.items():
    write("fuzz_rdp_session", "data_" + k, secsdrq(1003, v))
write("fuzz_rdp_session", "active_sequence",
      confirm_active(caps_set()) + secsdrq(1003, dp["sync"]) + secsdrq(1003, dp["coop"])
      + secsdrq(1003, dp["req"]) + secsdrq(1003, dp["fontl"]) + secsdrq(1003, dp["input"]))
write("fuzz_rdp_session", "vchan_cliprdr", sdrq(1006, u32(0) + u32(8) + u32(3) + b"\0" * 8))
write("fuzz_rdp_session", "fastpath_key", bytes([0x00, 0x08, 0x01, 0x20, 0x1E]))
write("fuzz_rdp_session", "fastpath_mouse", bytes([0x00, 0x0A, 0x01, 0x20, 0x00, 0x08, 0x64, 0x00, 0x64, 0x00]))

# libipm: [ver=2][len][facility=1 SCP][msgno][reserved=0] + typed parameters
def ipm(msgno, params):
    body = b"".join(params)
    return u16(2) + u16(12 + len(body)) + u16(1) + u16(msgno) + u32(0) + body


P = {
    "y": lambda v: b"y" + u8(v), "b": lambda v: b"b" + u8(v), "n": lambda v: b"n" + u16(v),
    "q": lambda v: b"q" + u16(v), "i": lambda v: b"i" + u32(v), "u": lambda v: b"u" + u32(v),
    "x": lambda v: b"x" + struct.pack("<Q", v), "t": lambda v: b"t" + struct.pack("<Q", v),
    "s": lambda v: b"s" + v + b"\0", "B": lambda v: b"B" + u16(len(v)) + v, "h": lambda v: b"h",
}
write("fuzz_libipm", "all_types", ipm(1, [P["y"](89), P["b"](1), P["n"](0xFF71), P["q"](329),
      P["i"](0xFFFEE890), P["u"](150000), P["x"](0xFFFFFFFEF0A3D400), P["t"](8500000000),
      P["s"](b"libipm"), P["B"](bytes(range(16)))]))
write("fuzz_libipm", "short_blob", ipm(2, [P["B"](b"abcd"), P["s"](b"x")]))
write("fuzz_libipm", "string_only", ipm(3, [P["s"](b"/tmp/.xrdp/sesman")]))
write("fuzz_libipm", "empty_msg", ipm(4, []))
write("fuzz_libipm", "fd_param", ipm(5, [P["h"](0), P["u"](1)]))
write("fuzz_libipm", "two_msgs", ipm(6, [P["u"](7)]) + ipm(7, [P["s"](b"second"), P["b"](0)]))
write("fuzz_libipm", "bad_bool", ipm(8, [P["b"](0)])[:-1] + b"\x05")

# dechunkers: [mode][kind][total:u16][len:u16][payload]...
def rec(kind, total, payload):
    return u8(kind) + u16(total & 0xFFFF) + u16(len(payload)) + payload


write("fuzz_dechunker", "vc_inline", u8(0) + rec(3, 11, b"hello world"))
write("fuzz_dechunker", "vc_two_chunks", u8(0) + rec(1, 3000, b"A" * 1600) + rec(2, 3000, b"B" * 1400))
write("fuzz_dechunker", "vc_three_chunks", u8(0) + rec(1, 3500, b"A" * 1600) + rec(0, 3500, b"B" * 1600)
      + rec(2, 3500, b"C" * 300))
write("fuzz_dechunker", "vc_recover", u8(0) + rec(1, 100, b"A" * 1700) + rec(3, 4, b"okay"))
write("fuzz_dechunker", "dyn_inline", u8(1) + rec(0, 1600, b"D" * 1600))
write("fuzz_dechunker", "dyn_split", u8(1) + rec(0, 2000, b"D" * 1500) + rec(1, 0, b"E" * 500))
write("fuzz_dechunker", "dyn_bad_total", u8(1) + rec(0, 100, b"F" * 50))

# harness prelude as a C array (kept in sync via this generator)
raw = b"".join(pre)
with open(os.path.join(OUT, "prelude.inc"), "w") as f:
    f.write("/* generated by mayhem/gen_seeds.py: the client half of the handshake up to Client Info */\n")
    f.write("static const unsigned char k_prelude[] = {")
    for i, b in enumerate(raw):
        f.write("%s0x%02x," % ("\n    " if i % 16 == 0 else " ", b))
    f.write("\n};\n")
