#!/usr/bin/env python3
"""
从「当前固件」的 boot.img 里重新抽取 prebuilt，替换设备树里过期的 kernel / dtb / dtbo。

用途：OEM 更新内核后，设备树里旧的 prebuilt/kernel、prebuilt/dtb.img、prebuilt/dtbo.img
      就跟新固件对不上了（load address / cmdline / panel dtbo 全可能变），TWRP 会起不来。

用法：
  python3 tools/reprebuilt.py boot.img --dtbo dtbo.img \
      --device-dir device/iflytek/ctg3 [--apply]

  --apply  真的写入 device-dir/prebuilt/，并把 BoardConfig 需要的参数打印成 make 片段
  （默认只分析、不改文件）

不依赖 mkbootimg/unpack_bootimg，纯 python 解析 Android boot image header v0~v4。
"""
import argparse
import hashlib
import os
import struct
import sys


def align(x, p):
    return (x + p - 1) // p * p


def parse_boot(data):
    if data[:8] != b"ANDROID!":
        raise SystemExit("不是 Android boot image（magic 不是 ANDROID!）")
    hver = struct.unpack_from("<I", data, 40)[0]
    info = {"header_version": hver, "size": len(data)}

    if hver in (0, 1, 2):
        (ksize, kaddr, rsize, raddr, ssize, saddr,
         taddr, page, _hver, osver) = struct.unpack_from("<10I", data, 8)
        name = data[48:64].split(b"\x00")[0].decode(errors="replace")
        cmdline = data[64:576].split(b"\x00")[0].decode(errors="replace")
        extra = data[608:1632].split(b"\x00")[0].decode(errors="replace")
        rdtbo_size = rdtbo_off = hsize = dtb_size = 0
        if hver >= 1:
            rdtbo_size = struct.unpack_from("<I", data, 1632)[0]
            rdtbo_off = struct.unpack_from("<Q", data, 1636)[0]
            hsize = struct.unpack_from("<I", data, 1644)[0]
        if hver >= 2:
            dtb_size = struct.unpack_from("<I", data, 1648)[0]
        info.update(dict(kernel_size=ksize, kernel_addr=kaddr, ramdisk_size=rsize,
                         ramdisk_addr=raddr, second_size=ssize, second_addr=saddr,
                         tags_addr=taddr, page_size=page, os_version=osver,
                         name=name, cmdline=(cmdline + " " + extra).strip(),
                         recovery_dtbo_size=rdtbo_size, recovery_dtbo_offset=rdtbo_off,
                         header_size=hsize, dtb_size=dtb_size))
        off = page
        parts = {}
        parts["kernel"] = data[off:off + ksize]; off += align(ksize, page)
        parts["ramdisk"] = data[off:off + rsize]; off += align(rsize, page)
        if ssize:
            parts["second"] = data[off:off + ssize]; off += align(ssize, page)
        if rdtbo_size:
            parts["recovery_dtbo"] = data[off:off + rdtbo_size]; off += align(rdtbo_size, page)
        if dtb_size:
            parts["dtb"] = data[off:off + dtb_size]
        info["parts"] = parts
        return info

    if hver in (3, 4):
        rsize, osver, hsize = struct.unpack_from("<III", data, 12)
        cmdline = data[44:44 + 1536].split(b"\x00")[0].decode(errors="replace")
        info.update(dict(kernel_size=0, ramdisk_size=rsize, os_version=osver,
                         header_size=hsize, page_size=4096, cmdline=cmdline,
                         kernel_addr=0, ramdisk_addr=0, tags_addr=0,
                         second_size=0, dtb_size=0, recovery_dtbo_size=0))
        parts = {"ramdisk": data[4096:4096 + rsize]}
        info["parts"] = parts
        return info

    raise SystemExit(f"不支持的 header_version={hver}")



def probe(path):
    """识别手里这个文件到底是什么格式，避免拿错（RK 的 kernel.img / resource.img 不是 boot.img）"""
    d = open(path, "rb").read()
    print(f"文件: {path}  ({len(d)} B)")
    kind = None
    if d[:8] == b"ANDROID!":
        kind = "Android boot image（正确来源，可用 --apply 抽取）"
    elif len(d) > 64 and d[56:60] == b"ARM\x64":
        kind = "raw ARM64 Image（内核本体，可直接改名 prebuilt/kernel）"
    elif len(d) > 40 and d[0x24:0x28] in (b"\x18\x28\x6f\x01",):
        kind = "ARM32 zImage（32 位内核，不是这台机器的）"
    elif d[:4] in (b"RSCE",):
        kind = "Rockchip resource.img（里面才是 dtb，需要用 --from-resource 拆）"
    elif d[:4] == b"\xd0\x0d\xfe\xed":
        kind = "DTB / FIT 镜像（设备树，可作 prebuilt/dtb.img）"
    elif d[:4] == b"\x27\x05\x19\x56":
        kind = "uImage（旧式 U-Boot 镜像）"
    else:
        kind = "未知格式"
    print(f"判定: {kind}")
    i = d.find(b"Linux version ")
    if i >= 0:
        print("内核版本串:", d[i:i+110].split(b"\n")[0].split(b"#")[0].decode(errors="replace"))
    if d[:4] == b"RSCE":
        # Rockchip resource.img：连续 [size(4)][type(4)][name(256)] 的条目
        off = 4
        print("resource.img 条目:")
        while off + 264 + 4 <= len(d):
            size, typ = struct.unpack_from("<II", d, off)
            name = d[off+8:off+8+256].split(b"\x00")[0].decode(errors="replace")
            print(f"  {name:32s} type={typ} size={size}")
            off += 264
            off += (size + 511) // 512 * 512
            if off > len(d):
                break
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("boot_img", nargs="?")
    ap.add_argument("--probe", metavar="FILE", help="只识别文件格式，不做抽取")
    ap.add_argument("--dtbo", help="当前固件的 dtbo 分区镜像（可选，用来重建 recovery_dtbo）")
    ap.add_argument("--device-dir", default="device/iflytek/ctg3")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()

    if a.probe:
        probe(a.probe)
        return
    if not a.boot_img:
        ap.error("需要 boot.img 路径，或用 --probe 识别文件")

    data = open(a.boot_img, "rb").read()
    info = parse_boot(data)
    p = info["parts"]

    print("==== 当前固件 boot.img ====")
    for k in ("header_version", "header_size", "page_size", "os_version",
              "kernel_size", "ramdisk_size", "dtb_size", "recovery_dtbo_size",
              "second_size"):
        print(f"  {k:20s}= {info[k]}")
    for k in ("kernel_addr", "ramdisk_addr", "tags_addr"):
        print(f"  {k:20s}= {info[k]:#x}")
    print(f"  name                = {info.get('name','')}")
    print(f"  cmdline             = {info.get('cmdline','')}")

    if info["kernel_size"]:
        print(f"  kernel sha256       = {hashlib.sha256(p['kernel']).hexdigest()[:32]}")
        # 内核版本字符串，方便和旧 prebuilt 对比
        i = p["kernel"].find(b"Linux version ")
        if i >= 0:
            banner = p["kernel"][i:i+120].split(b"\n")[0].split(b"#")[0]
            print(f"  kernel banner       = {banner.decode(errors='replace')}")
    if "dtb" in p:
        print(f"  dtb magic           = {p['dtb'][:4].hex()} (d00dfeed 才对)")

    base = info["kernel_addr"] - 0x8000 if info["kernel_addr"] else 0
    print("\n==== BoardConfig.mk 建议值 ====")
    print(f"BOARD_KERNEL_PAGESIZE := {info['page_size']}")
    print(f"BOARD_BOOTIMG_HEADER_VERSION := {info['header_version']}")
    if base:
        print(f"BOARD_KERNEL_BASE := {base:#x}")
        print(f"BOARD_RAMDISK_OFFSET := {info['ramdisk_addr'] - base:#x}")
        print(f"BOARD_KERNEL_TAGS_OFFSET := {info['tags_addr'] - base:#x}")
    print(f"# os_version = {info['os_version']:#x}")

    pre = os.path.join(a.device_dir, "prebuilt")
    print("\n==== 与设备树现有 prebuilt 对比 ====")
    mapping = [("kernel", "kernel"), ("dtb", "dtb.img")]
    for key, fname in mapping:
        if key not in p:
            continue
        path = os.path.join(pre, fname)
        if os.path.exists(path):
            old = open(path, "rb").read()
            same = hashlib.sha256(old).hexdigest() == hashlib.sha256(p[key]).hexdigest()
            print(f"  prebuilt/{fname:9s} 旧 {len(old):>10d}B  新 {len(p[key]):>10d}B  "
                  f"{'一致 ✅' if same else '不一致 ❌ 需要替换'}")
        else:
            print(f"  prebuilt/{fname:9s} 不存在，会新建")

    if a.dtbo:
        newd = open(a.dtbo, "rb").read()
        path = os.path.join(pre, "dtbo.img")
        old = open(path, "rb").read() if os.path.exists(path) else b""
        print(f"  prebuilt/dtbo.img     旧 {len(old):>10d}B  新 {len(newd):>10d}B  "
              f"{'一致 ✅' if old == newd else '不一致 ❌ 需要替换'}")

    if not a.apply:
        print("\n（仅分析，未写入。确认无误后加 --apply 真正替换）")
        return

    os.makedirs(pre, exist_ok=True)
    if "kernel" in p:
        open(os.path.join(pre, "kernel"), "wb").write(p["kernel"])
        print(f"写入 prebuilt/kernel  ({len(p['kernel'])} B)")
    if "dtb" in p:
        open(os.path.join(pre, "dtb.img"), "wb").write(p["dtb"])
        print(f"写入 prebuilt/dtb.img ({len(p['dtb'])} B)")
    if a.dtbo:
        open(os.path.join(pre, "dtbo.img"), "wb").write(open(a.dtbo, "rb").read())
        print(f"写入 prebuilt/dtbo.img ({os.path.getsize(a.dtbo)} B)")
    print("完成。记得把上面 BoardConfig.mk 的地址/页大小/header 版本核对一遍再编译。")


if __name__ == "__main__":
    main()
