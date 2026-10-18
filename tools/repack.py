#!/usr/bin/env python3
"""
把 TWRP 的 ramdisk 塞进「官方 recovery.img」的容器里 —— 保留官方镜像的
kernel / dtb / recovery_dtbo / cmdline / 加载地址 / header 版本 / page size。

用途：官方 recovery 能起、我们自编的起不来时，用来一次性排除所有打包变量，
     只留 ramdisk 这一个未知。

用法：
  # 1) 从我们编的 recovery.img 里导出 TWRP ramdisk
  python3 tools/repack.py --extract-ramdisk out/recovery.img twrp-ramdisk.gz

  # 2) 用官方 recovery.img 当模板重打包
  python3 tools/repack.py --base official-recovery.img \
                          --ramdisk twrp-ramdisk.gz \
                          --out recovery-twrp.img

注意：如果官方镜像是 AVB 签名的（文件尾有 AVBf），重打包会让签名失效。
"""
import argparse
import hashlib
import struct
import sys

MAGIC = b"ANDROID!"


def align(x, p):
    return (x + p - 1) // p * p


def parse(d):
    if d[:8] != MAGIC:
        raise SystemExit("不是 Android boot image")
    hver = struct.unpack_from("<I", d, 40)[0]
    if hver not in (0, 1, 2):
        raise SystemExit(f"只支持 header v0/v1/v2，这个是 v{hver}")
    (ksize, kaddr, rsize, raddr, ssize, saddr,
     taddr, page, _h, osver) = struct.unpack_from("<10I", d, 8)
    hsize = struct.unpack_from("<I", d, 1644)[0] if hver >= 1 else 0
    rdtbo_size = struct.unpack_from("<I", d, 1632)[0] if hver >= 1 else 0
    dtb_size = struct.unpack_from("<I", d, 1648)[0] if hver >= 2 else 0
    off = page
    sec = {}
    sec["kernel"] = d[off:off + ksize]; off += align(ksize, page)
    sec["ramdisk"] = d[off:off + rsize]; off += align(rsize, page)
    if ssize:
        sec["second"] = d[off:off + ssize]; off += align(ssize, page)
    if rdtbo_size:
        sec["recovery_dtbo"] = d[off:off + rdtbo_size]; off += align(rdtbo_size, page)
    if dtb_size:
        sec["dtb"] = d[off:off + dtb_size]
    return dict(hver=hver, page=page, hsize=hsize, osver=osver, sec=sec,
                kaddr=kaddr, raddr=raddr, taddr=taddr,
                has_avb=b"AVBf" in d[-64:])


def build(tmpl_page, info, new_ramdisk):
    """按模板的 header page 重建镜像，只换 ramdisk"""
    page = info["page"]
    hdr = bytearray(tmpl_page)
    struct.pack_into("<I", hdr, 16, len(new_ramdisk))   # ramdisk_size
    sec = info["sec"]
    out = bytearray()
    out += bytes(hdr[:page])
    for name in ("kernel", "ramdisk", "second", "recovery_dtbo", "dtb"):
        if name == "ramdisk":
            blob = new_ramdisk
        elif name in sec:
            blob = sec[name]
        else:
            continue
        out += blob
        out += b"\x00" * (align(len(blob), page) - len(blob))
    # v0 需要重算 id（kernel/ramdisk/second 的 sha1）
    if info["hver"] == 0:
        h = hashlib.sha1()
        for n in ("kernel", "ramdisk", "second"):
            h.update(new_ramdisk if n == "ramdisk" else sec.get(n, b""))
        out[576:576 + 20] = h.digest()
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--extract-ramdisk", nargs=2, metavar=("IMG", "OUT"))
    ap.add_argument("--base")
    ap.add_argument("--ramdisk")
    ap.add_argument("--out", default="recovery-twrp.img")
    a = ap.parse_args()

    if a.extract_ramdisk:
        img, out = a.extract_ramdisk
        info = parse(open(img, "rb").read())
        open(out, "wb").write(info["sec"]["ramdisk"])
        print(f"导出 ramdisk -> {out}  ({len(info['sec']['ramdisk'])} B)")
        return

    if not (a.base and a.ramdisk):
        ap.error("需要 --base 与 --ramdisk（或使用 --extract-ramdisk）")

    base = open(a.base, "rb").read()
    info = parse(base)
    ram = open(a.ramdisk, "rb").read()
    print(f"模板: {a.base}  header v{info['hver']}  page={info['page']}  "
          f"kernel={len(info['sec'].get('kernel', b''))}  dtb={len(info['sec'].get('dtb', b''))}  "
          f"recovery_dtbo={len(info['sec'].get('recovery_dtbo', b''))}")
    print(f"原 ramdisk: {len(info['sec']['ramdisk'])} B  ->  新 ramdisk: {len(ram)} B")
    if info["has_avb"]:
        print("!! 模板带 AVB 签名，重打包后签名失效（如果设备强制校验就刷不进去）")
    out = build(base[:info["page"]], info, ram)
    open(a.out, "wb").write(out)
    print(f"输出: {a.out}  {len(out)} B  sha256={hashlib.sha256(out).hexdigest()}")


if __name__ == "__main__":
    main()
