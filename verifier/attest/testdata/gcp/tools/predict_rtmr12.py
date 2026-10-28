"""Predict RTMR1 and RTMR2 of a dstack UKI disk image booted by Google's TDX firmware on GCE.

usage: python3 -I predict_rtmr12.py <disk.raw> [getquote.json]

Reads the GPT and EFI/BOOT/BOOTX64.EFI (the UKI) from disk.raw, rebuilds the event sequences observed on
c3-standard-4 TDX (2026-10-28 spike), folds them from 48 zero bytes and prints RTMR1 and RTMR2. With a GetQuote
response it also compares each digest with the event log and the values with the quote.

RTMR1: EV_EFI_ACTION "Calling EFI Application from Boot Option", EV_SEPARATOR(0), EV_EFI_GPT_EVENT (boot disk
GPT), EV_EFI_BOOT_SERVICES_APPLICATION (SHA-384 Authenticode of the UKI), the same for the .linux PE inside it,
EV_EFI_ACTION "Exit Boot Services Invocation", EV_EFI_ACTION "Exit Boot Services Returned with Success".
RTMR2: EV_IPL from systemd-stub, sha384(section name + NUL) then sha384(section content) for .linux, .osrel,
.cmdline, .initrd, .uname, .sbat (in that order, sections that exist).
"""
import hashlib, json, struct, sys

disk_path = sys.argv[1]
cap = sys.argv[2] if len(sys.argv) > 2 else None


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


disk = open(disk_path, "rb")
disk.seek(512)
hdr = disk.read(512)
assert hdr[:8] == b"EFI PART"
ent_lba, n_ent, ent_sz = u64(hdr, 72), u32(hdr, 80), u32(hdr, 84)
disk.seek(ent_lba * 512)
ents = disk.read(n_ent * ent_sz)
used = [ents[i * ent_sz:(i + 1) * ent_sz] for i in range(n_ent) if any(ents[i * ent_sz:i * ent_sz + 16])]
gpt_event = hdr[:u32(hdr, 12)] + struct.pack("<Q", len(used)) + b"".join(used)
esp_first_lba = u64(used[0], 32)

# Minimal FAT32 reader for the ESP: find EFI/BOOT/BOOTX64.EFI.
base = esp_first_lba * 512
disk.seek(base)
bs = disk.read(512)
bps, spc, rsv, nfat = u16(bs, 11), bs[13], u16(bs, 14), bs[16]
fatsz, root_clus = u32(bs, 36), u32(bs, 44)
data_off = base + (rsv + nfat * fatsz) * bps
clus_sz = bps * spc


def fat_next(c):
    disk.seek(base + rsv * bps + c * 4)
    return u32(disk.read(4), 0) & 0x0FFFFFFF


def read_chain(c, size=None):
    out = bytearray()
    while c < 0x0FFFFFF8:
        disk.seek(data_off + (c - 2) * clus_sz)
        out += disk.read(clus_sz)
        c = fat_next(c)
    return bytes(out if size is None else out[:size])


def lookup(dir_clus, name83):
    d = read_chain(dir_clus)
    for i in range(0, len(d), 32):
        e = d[i:i + 32]
        if e[0] == 0:
            break
        if e[0] == 0xE5 or e[11] == 0x0F:
            continue
        if e[:11] == name83:
            return (u16(e, 20) << 16) | u16(e, 26), u32(e, 28)
    raise KeyError(name83)


c, _ = lookup(root_clus, b"EFI        ")
c, _ = lookup(c, b"BOOT       ")
c, size = lookup(c, b"BOOTX64 EFI")
uki = read_chain(c, size)


def authenticode384(d):
    coff = u32(d, 0x3C) + 4
    opt = coff + 20
    plus = u16(d, opt) == 0x20B
    ck = opt + 64
    cd = opt + (112 if plus else 96) + 4 * 8
    soh = u32(d, opt + 60)
    h = hashlib.sha384()
    h.update(d[:ck]); h.update(d[ck + 4:cd]); h.update(d[cd + 8:soh])
    secs = []
    for i in range(u16(d, coff + 2)):
        so = opt + u16(d, coff + 16) + 40 * i
        if u32(d, so + 16):
            secs.append((u32(d, so + 20), u32(d, so + 16)))
    secs.sort()
    s = soh
    for o, z in secs:
        h.update(d[o:o + z]); s += z
    ca, cs = u32(d, cd), u32(d, cd + 4)
    tl = len(d) - s - (cs if ca and cs else 0)
    if tl > 0:
        h.update(d[s:s + tl])
    return h.digest()


def sections(d):
    coff = u32(d, 0x3C) + 4
    opt = coff + 20
    out = {}
    for i in range(u16(d, coff + 2)):
        so = opt + u16(d, coff + 16) + 40 * i
        name = d[so:so + 8].rstrip(b"\0")
        vsize, ptr = u32(d, so + 8), u32(d, so + 20)
        out[name] = d[ptr:ptr + vsize]
    return out


sec = sections(uki)
H = lambda b: hashlib.sha384(b).digest()
rtmr1_events = [
    ("EV_EFI_ACTION", H(b"Calling EFI Application from Boot Option")),
    ("EV_SEPARATOR", H(bytes(4))),
    ("EV_EFI_GPT_EVENT", H(gpt_event)),
    ("EV_EFI_BOOT_SERVICES_APPLICATION uki", authenticode384(uki)),
    ("EV_EFI_BOOT_SERVICES_APPLICATION .linux", authenticode384(sec[b".linux"])),
    ("EV_EFI_ACTION", H(b"Exit Boot Services Invocation")),
    ("EV_EFI_ACTION", H(b"Exit Boot Services Returned with Success")),
]
rtmr2_events = []
for name in (b".linux", b".osrel", b".cmdline", b".initrd", b".uname", b".sbat"):
    if name in sec:
        rtmr2_events += [("EV_IPL name " + name.decode(), H(name + b"\0")), ("EV_IPL " + name.decode(), H(sec[name]))]


def fold(evs):
    acc = bytes(48)
    for _, d in evs:
        acc = hashlib.sha384(acc + d).digest()
    return acc.hex()


res = {"rtmr1": fold(rtmr1_events), "rtmr2": fold(rtmr2_events),
       "uki_sha256": hashlib.sha256(uki).hexdigest(), "uki_authenticode_sha384": authenticode384(uki).hex()}
ok = True
if cap:
    r = json.load(open(cap))
    log = json.loads(r["event_log"])
    q = bytes.fromhex(r["quote"])
    body = 48
    quote_rtmr = {i: q[body + 328 + 48 * i: body + 376 + 48 * i].hex() for i in range(4)}
    for imr, evs in ((1, rtmr1_events), (2, rtmr2_events)):
        got = [e["digest"].lower() for e in log if e["imr"] == imr]
        want = [d.hex() for _, d in evs]
        res[f"rtmr{imr}_event_digests_match_log"] = got == want
        res[f"rtmr{imr}_matches_quote"] = res[f"rtmr{imr}"] == quote_rtmr[imr]
        ok &= got == want and res[f"rtmr{imr}"] == quote_rtmr[imr]
print(json.dumps(res, indent=2))
sys.exit(0 if ok else 1)
