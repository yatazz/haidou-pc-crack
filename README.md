# 海斗一图流电脑版 · 授权校验分析与本地补丁

> 面向 **本地样本逆向学习**。目标为 PyInstaller 打包的 Python 3.11 程序，本文记录其授权链结构，并给出把 `License.status()` 改为恒真、跳过 Ed25519 验签的完整思路与可复现脚本。

## ⬇️ 下载

**[点击下载破解版 exe](https://github.com/yatazz/haidou-pc-crack/releases/latest)** → 打开 Releases 页，下载 `HaidouPC_v0.3.31_cracked.exe`，放到程序目录（与 `_internal/` 同级）双击运行，无需激活。

---

## 1. 样本概况

| 项 | 值 |
|---|---|
| 名称 | 海斗一图流电脑版 |
| 版本 | 0.3.31 |
| 打包 | PyInstaller **onedir**（exe + `_internal/`） |
| Python | 3.11（pyc magic `a70d0d0a`） |
| 代码位置 | 主 exe 内嵌 `PYZ.pyz`（标准 ZlibArchive，637 个模块） |
| 关键包 | `haidou_pc`（licensing / entitlement / engine / ui / paths / secure_store …） |

解包：`pyinstxtractor-ng 海斗一图流电脑版.exe` 得到 `PYZ.pyz`、`run.pyc` 等。
由于是 3.11 字节码，`decompyle3`/`pycdc` 均不支持；改用 **Python 3.11.18**（magic 完全一致）的 `marshal`/`dis` 精确反汇编。

---

## 2. 授权链结构（逆向结论）

### 2.1 令牌
`licensing.verify(token, public_key)`
- `token = body_b64 + "." + sig_b64`
- `body` 为 JSON，用 **Ed25519** 公钥验签：
  `Ed25519PublicKey.from_public_bytes(_unb64(pk)).verify(sig, raw)`
- 验签失败返回 `None`。

### 2.2 License 对象
```python
License(public_key, state_file, instance_file, owner,
        clock, request, monotonic, machine)
```
- `owner` 默认为 `False`，`self.owner = owner`。
- 授权状态文件经 **DPAPI**（`secure_store`）加密，服务器端有 `/api/redeem`、`/api/check`。

### 2.3 三个「后门式」短路
```python
# licensing.License.status()
def status(self):
    if self.owner:                       # ← 关键
        return Status(True, 'owner')
    ...  # 验签 / 过期 / 离线检查

# entitlement.check()
def check(license, remote):
    if license.owner:
        return Access(True)
    ...

# License.refresh() / License.redeem() 同样有 if self.owner 的短路
```

### 2.4 为什么普通用户拿不到 owner=True
- `paths.SELF_USE = (not FROZEN) and (PROJECT_ROOT/'AGENTS.md').exists()`
- 打包后 `FROZEN = True` → `SELF_USE = False`
- `ui.App.__init__` 里是 `Engine()` **无参构造** → `Engine` 内 `license=None` → `License()` 默认 `owner=False`
- `SELF_USE` 只控制录屏/截图开关，**不参与授权判定**

所以：**唯一让 `owner=True` 的入口就是 `License(... owner=True)`，而正常启动路径永远不会这么传。**

---

## 3. 破解思路

`status()` 的第一行就是全功能开关：
```python
if self.owner: return Status(True, 'owner')
```

因此**只要让这条判断恒成立**，无论是否激活、token 是否为空、是否联网，`status()` 永远返回 `ok=True`；`entitlement.check()` 也读 `license.owner`，同样放行。

最小改动 = 把 `status()` 字节码开头的 `LOAD_FAST self; LOAD_ATTR owner` 替换为 `LOAD_CONST True`，后面紧跟的 `POP_JUMP_FORWARD_IF_FALSE` 因栈顶恒为 True 而**永不跳转**，直接落到 `Status(True,'owner')` 分支。

### 3.1 原始字节码（Python 3.11）
```
offset 2 : LOAD_FAST  0 (self)
offset 4 : LOAD_ATTR  0 (owner)      ; 2 字节 + 4 个 CACHE = 10 字节
offset 14: POP_JUMP_FORWARD_IF_FALSE 16
offset 16: LOAD_GLOBAL Status
offset 28: LOAD_CONST 1 (True)
offset 30: LOAD_CONST 2 ('owner')
...
```

### 3.2 补丁
把 `offset 2..14`（12 字节）替换为：
```
LOAD_CONST 1 (True)   # 100 01
NOP ×5                # 09 00 ×5  —— 填满原 LOAD_ATTR 的 CACHE
```
栈上只剩一个 True，判断恒真。

---

## 4. 落地：改字节码 → 重建 PYZ → 重写 exe

代码在 exe 内嵌的 `PYZ.pyz`，因此需要按层次回写：

1. **改字节码**：用 Python 3.11 的 `marshal` 读出 `licensing` 模块 code，`code.replace(co_code=...)` 打补丁（`co_code` 只读，需重建 code 对象）。
2. **重建 PYZ（ZlibArchive）**：
   - 头长 **17 字节**（`PYZ\0` + 4 字节 bytecode magic + 4 字节 TOC 偏移 + 5 字节保留）
   - 各条目 = `zlib.compress(marshal.dumps(code))`，TOC 为 `(name, (typecode, offset, length))` 的 `marshal`
3. **重写 exe 的 CArchive**：
   - 末尾 88 字节 cookie：`MEI\x0c\x0b\x0a\x0b\x0e` + `pkgLen` + `tocOff` + `tocLen` + `pyver` + `pylibName(64)`
   - 用新 PYZ 替换 `zPYZ.pyz` 条目，重算 `tocOff`、`pkgLen`（**pkgLen 含 88 字节 cookie**）

全部封装在 [`tools/patch_haidou.py`](tools/patch_haidou.py)，一条命令完成。

---

## 5. 使用

```bash
# 需要 Python 3.11（pyc magic a70d0d0a）
python tools/patch_haidou.py <原版.exe> <输出.exe>
```

放到原程序目录（与本来的 `_internal/` 同级），双击运行即可，无需激活。

> 已验证：`status(owner=False, token='')` 返回 `Status(ok=True, 'owner')`，程序完整启动进入主流程，无授权拦截。

---

## 6. 目录

```
tools/patch_haidou.py            一键补丁脚本
dist/海斗一图流电脑版_cracked.exe 破解版成品
README.md                        本文
```

## 7. 声明

仅供个人对**本地自有样本**的安全研究、字节码/打包格式学习与互操作性测试使用。请勿用于商业分发或规避正版授权。因使用本工具产生的一切后果由使用者自行承担。
