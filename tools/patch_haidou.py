#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
海斗一图流电脑版 —— 授权校验补丁工具（本地样本逆向 / 学习用途）

作用：把 PyInstaller onedir 打包的 exe 内嵌 PYZ 中的
      haidou_pc.licensing.License.status() 首个分支改为恒真，
      使 status() 永远返回 Status(ok=True, 'owner')，跳过 Ed25519 验签。

用法：
    python patch_haidou.py <原版 exe> <输出 exe>

要求：Python 3.11（pyc magic 必须与目标一致 a70d0d0a）。
原理见仓库 README。
"""
import sys, struct, marshal, zlib, dis, types

MAGIC = b'MEI\x0c\x0b\x0a\x0b\x0e'   # PyInstaller CArchive cookie magic
TARGET_MODULE = 'haidou_pc.licensing'
TARGET_FUNC = 'status'


# ---------- PYZ (ZlibArchive) ----------
def pyz_read(blob):
    assert blob[:4] == b'PYZ\x00', 'not a PYZ archive'
    bytemagic = blob[4:8]
    toc_pos = struct.unpack('!i', blob[8:12])[0]
    toc = marshal.loads(blob[toc_pos:])          # list of (name,(typecode,off,len))
    entries = [(name, (t, blob[off:off + ln])) for name, (t, off, ln) in toc]
    return bytemagic, entries


def pyz_write(bytemagic, entries, path):
    buf = bytearray(b'\0' * 17)                 # PyInstaller _HEADER_LENGTH = 12 + 5
    newtoc = []
    for name, (t, payload) in entries:
        off = len(buf)
        buf += payload
        newtoc.append((name, (t, off, len(payload))))
    toc_offset = len(buf)
    buf += marshal.dumps(newtoc)
    buf[0:4] = b'PYZ\x00'
    buf[4:8] = bytemagic
    buf[8:12] = struct.pack('!i', toc_offset)
    open(path, 'wb').write(buf)


def find_code(code, name):
    for k in code.co_consts:
        if isinstance(k, types.CodeType):
            if k.co_name == name:
                return k
            r = find_code(k, name)
            if r:
                return r
    return None


def rebuild_code(code, target, newcode):
    newconsts = []
    for k in code.co_consts:
        newconsts.append(rebuild_code(k, target, newcode) if isinstance(k, types.CodeType) else k)
    if code.co_name == target:
        return code.replace(co_code=newcode)
    return code.replace(co_consts=tuple(newconsts))


def patch_status(module_code):
    """
    把 status() 开头 `LOAD_FAST self; LOAD_ATTR owner` 换成 `LOAD_CONST True; NOP...`
    使 owner 判断恒真。偏移针对本版本（Py3.11）已验证。
    """
    status = find_code(module_code, TARGET_FUNC)
    if status is None:
        raise SystemExit('找不到 status()，目标文件不匹配')
    ins = list(dis.get_instructions(status))
    # 期望: RESUME, LOAD_FAST self, LOAD_ATTR owner, POP_JUMP_FORWARD_IF_FALSE ...
    assert ins[1].opname == 'LOAD_FAST' and ins[2].opname == 'LOAD_ATTR' and ins[2].argval == 'owner', \
        'status 头部结构不符，可能版本已变'
    b = bytearray(status.co_code)
    start, end = ins[1].offset, ins[3].offset  # 覆盖 LOAD_FAST + LOAD_ATTR(含CACHE)
    span = end - start
    # LOAD_CONST True (100,1) + NOP(9,0) 填满
    newbytes = bytes([100, 1]) + bytes([9, 0]) * ((span - 2) // 2)
    assert len(newbytes) == span
    b[start:end] = newbytes
    patched = rebuild_code(module_code, TARGET_FUNC, bytes(b))
    # 自检
    s2 = find_code(patched, TARGET_FUNC)
    assert [i.opname for i in list(dis.get_instructions(s2))[:3]][1] == 'LOAD_CONST'
    return patched


# ---------- CArchive (exe PKG) ----------
def parse_carchive(data):
    n = len(data)
    cs = n - 88
    assert data[cs:cs + 8] == MAGIC, 'CArchive cookie 未找到（不是 PyInstaller exe？）'
    pkg_len, toc_off, toc_len, pyver = struct.unpack('!iiii', data[cs + 8:cs + 24])
    pylib = data[cs + 24:cs + 88]
    pkg_start = n - pkg_len
    toc = bytearray(data[pkg_start + toc_off: pkg_start + toc_off + toc_len])
    return dict(pkg_len=pkg_len, toc_off=toc_off, toc_len=toc_len, pyver=pyver,
                pylib=pylib, pkg_start=pkg_start, toc=toc)


def rebuild_exe(data, ca, new_pyz_bytes):
    toc = ca['toc']
    pkg_start = ca['pkg_start']
    # 找 zPYZ.pyz 条目
    i = 0
    pz = None
    while i < len(toc):
        el = struct.unpack('!i', bytes(toc[i:i + 4]))[0]
        if el <= 0:
            break
        nm = bytes(toc[i + 17:i + el]).rstrip(b'\0')
        if nm == b'zPYZ.pyz':
            pz = i
            break
        i += el
    assert pz is not None, 'CArchive 中没有 PYZ.pyz 条目'
    off = struct.unpack('!i', bytes(toc[pz + 4:pz + 8]))[0]
    data_region = data[pkg_start:pkg_start + off] + new_pyz_bytes
    new_toc_off = len(data_region)
    toc[pz + 8:pz + 12] = struct.pack('!i', len(new_pyz_bytes))
    toc[pz + 12:pz + 16] = struct.pack('!i', len(new_pyz_bytes))
    new_pkg = bytes(data_region) + bytes(toc)
    new_pkg_len = len(new_pkg) + 88            # 原版 pkgLen 含 88 字节 cookie
    new_cookie = MAGIC + struct.pack('!iiii', new_pkg_len, new_toc_off, ca['toc_len'], ca['pyver']) + ca['pylib']
    return data[:pkg_start] + new_pkg + new_cookie


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    src, out = sys.argv[1], sys.argv[2]
    data = open(src, 'rb').read()
    ca = parse_carchive(data)
    # 取 PYZ 条目
    toc = ca['toc']
    i = 0
    pyz_bytes = None
    while i < len(toc):
        el = struct.unpack('!i', bytes(toc[i:i + 4]))[0]
        nm = bytes(toc[i + 17:i + el]).rstrip(b'\0')
        if nm == b'zPYZ.pyz':
            off, dl = struct.unpack('!ii', bytes(toc[i + 4:i + 12]))
            pyz_bytes = data[ca['pkg_start'] + off: ca['pkg_start'] + off + dl]
            break
        i += el
    assert pyz_bytes, 'PYZ 未定位'
    bytemagic, entries = pyz_read(pyz_bytes)
    # 打补丁
    new_entries = []
    for name, (t, payload) in entries:
        if name == TARGET_MODULE:
            raw = zlib.decompress(payload) if t == 0 else payload
            module_code = marshal.loads(raw)
            patched = patch_status(module_code)
            payload = zlib.compress(marshal.dumps(patched), 6)
            t = 0
        new_entries.append((name, (t, payload)))
    tmp_pyz = out + '.pyz'
    pyz_write(bytemagic, new_entries, tmp_pyz)
    new_pyz = open(tmp_pyz, 'rb').read()
    new_exe = rebuild_exe(data, ca, new_pyz)
    open(out, 'wb').write(new_exe)
    print(f'[OK] {src} -> {out}  ({len(data)} -> {len(new_exe)} bytes)')
    print('[OK] licensing.status() 已改为恒真，授权校验放行。')


if __name__ == '__main__':
    main()
