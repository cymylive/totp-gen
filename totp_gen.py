# -*- coding: utf-8 -*-
"""TotpGen — 本地离线 TOTP 验证码生成器

- 纯标准库实现 RFC 6238 TOTP（无第三方依赖）
- Windows DPAPI 加密存储 secret（绑定当前 Windows 用户，拷走解不开）
- tkinter GUI，完全离线，不联网

用法：
    TotpGen.exe                      直接启动 GUI
    TotpGen.exe --add "GitHub" SECRET   命令行添加账号
    TotpGen.exe --code GitHub        命令行打印当前验证码（脚本调用）
    TotpGen.exe --list               列出所有账号
"""
import base64
import ctypes
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import tkinter as tk
from ctypes import wintypes
from tkinter import messagebox, ttk
from urllib.parse import parse_qs, unquote, urlparse

APP_NAME = "TotpGen"
VAULT_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP_NAME)
VAULT_FILE = os.path.join(VAULT_DIR, "vault.dat")
MAGIC = b"TOTPv1"


# ============================================================
# TOTP 算法（RFC 6238 / RFC 4226）
# ============================================================
def b32decode_padded(s):
    """Base32 解码，自动补齐 padding 并容错大小写/空格。"""
    s = s.strip().replace(" ", "").replace("-", "").upper().rstrip("=")
    if not s:
        raise ValueError("secret 为空")
    pad = (-len(s)) % 8
    return base64.b32decode(s + "=" * pad)


def hotp(key, counter, digits=6):
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret, at=None, period=30, digits=6):
    if at is None:
        at = time.time()
    return hotp(b32decode_padded(secret), int(at) // period, digits)


def totp_remaining(period=30):
    return period - int(time.time()) % period


def parse_otpauth(uri):
    """解析 otpauth://totp/... 链接，失败返回 None。"""
    try:
        u = urlparse(uri.strip())
    except Exception:
        return None
    if u.scheme.lower() != "otpauth":
        return None
    label = unquote(u.path.lstrip("/"))
    q = parse_qs(u.query)
    secret = (q.get("secret") or [""])[0].strip()
    if not secret:
        return None
    try:
        digits = int((q.get("digits") or ["6"])[0])
        period = int((q.get("period") or ["30"])[0])
    except ValueError:
        digits, period = 6, 30
    if digits not in (6, 8):
        digits = 6
    if period <= 0:
        period = 30
    return {"name": label or "未命名", "secret": secret, "digits": digits, "period": period}


# ============================================================
# Windows DPAPI 加密（绑定当前用户，无需密码）
# ============================================================
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _make_blob(data):
    buf = ctypes.create_string_buffer(data, len(data))
    blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def _read_blob(blob):
    return ctypes.string_at(blob.pbData, blob.cbData)


_crypt32 = ctypes.windll.crypt32
_kernel32 = ctypes.windll.kernel32


def dpapi_encrypt(data):
    in_blob, _buf = _make_blob(data)
    out_blob = DATA_BLOB()
    ok = _crypt32.CryptProtectData(
        ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
    )
    if not ok:
        raise OSError("CryptProtectData 失败，错误码 %d" % ctypes.get_last_error())
    try:
        return _read_blob(out_blob)
    finally:
        _kernel32.LocalFree(out_blob.pbData)


def dpapi_decrypt(data):
    in_blob, _buf = _make_blob(data)
    out_blob = DATA_BLOB()
    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
    )
    if not ok:
        raise OSError(
            "CryptUnprotectData 失败：vault 可能由其他 Windows 用户创建，或文件已损坏"
        )
    try:
        return _read_blob(out_blob)
    finally:
        _kernel32.LocalFree(out_blob.pbData)


# ============================================================
# 存储
# ============================================================
def load_accounts():
    if not os.path.exists(VAULT_FILE):
        return []
    with open(VAULT_FILE, "rb") as f:
        raw = f.read()
    if not raw.startswith(MAGIC):
        raise ValueError("vault 文件格式不符（不是本程序生成的）")
    plain = dpapi_decrypt(raw[len(MAGIC):])
    data = json.loads(plain.decode("utf-8"))
    return data.get("accounts", [])


def save_accounts(accounts):
    os.makedirs(VAULT_DIR, exist_ok=True)
    plain = json.dumps({"accounts": accounts}, ensure_ascii=False).encode("utf-8")
    blob = MAGIC + dpapi_encrypt(plain)
    tmp = VAULT_FILE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, VAULT_FILE)


# ============================================================
# GUI
# ============================================================
class AddDialog(tk.Toplevel):
    def __init__(self, master, on_save):
        super().__init__(master)
        self.on_save = on_save
        self.title("添加账号")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        pad = {"padx": 12, "pady": 6}
        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, padx=16, pady=12)

        ttk.Label(frm, text="账号名称（如 GitHub）").grid(row=0, column=0, sticky="w", **pad)
        self.name_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.name_var, width=42).grid(row=1, column=0, sticky="we", **pad)

        ttk.Label(frm, text="Secret（Base32）或 otpauth:// 链接").grid(row=2, column=0, sticky="w", **pad)
        self.secret_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.secret_var, width=42).grid(row=3, column=0, sticky="we", **pad)
        ttk.Label(
            frm, text="提示：粘贴 otpauth:// 链接时会自动解析名称和 secret", foreground="#666"
        ).grid(row=4, column=0, sticky="w", padx=12)

        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, sticky="e", pady=(12, 0))
        ttk.Button(btns, text="取消", command=self.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(btns, text="保存", command=self._save).pack(side="right")

        self.name_var.set("")
        self.secret_var.set("")
        self.bind("<Return>", lambda e: self._save())
        self.bind("<Escape>", lambda e: self.destroy())

    def _save(self):
        name = self.name_var.get().strip()
        secret = self.secret_var.get().strip()
        if not name and not secret:
            messagebox.showwarning("提示", "请填写名称和 secret", parent=self)
            return

        if secret.lower().startswith("otpauth://"):
            parsed = parse_otpauth(secret)
            if not parsed:
                messagebox.showerror("错误", "otpauth 链接解析失败，请检查格式", parent=self)
                return
            name = name or parsed["name"]
            secret = parsed["secret"]
            digits, period = parsed["digits"], parsed["period"]
        else:
            digits, period = 6, 30

        if not name:
            messagebox.showwarning("提示", "请填写账号名称", parent=self)
            return

        try:
            b32decode_padded(secret)
        except Exception as e:
            messagebox.showerror("错误", "secret 不是合法的 Base32：%s" % e, parent=self)
            return

        self.on_save({"name": name, "secret": secret, "digits": digits, "period": period})
        self.destroy()


class TotpApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TotpGen — 本地验证码生成器")
        self.geometry("520x420")
        self.minsize(460, 320)

        self.accounts = []
        self._load_error = None
        try:
            self.accounts = load_accounts()
        except Exception as e:
            self._load_error = str(e)

        self._build_ui()
        if self._load_error:
            self.after(200, lambda: messagebox.showerror("读取失败", self._load_error))

        self._tick()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=(12, 6))

        ttk.Button(top, text="＋ 添加账号", command=self._add).pack(side="left")
        ttk.Button(top, text="－ 删除选中", command=self._delete).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="复制验证码", command=self._copy_selected).pack(side="left", padx=(8, 0))

        self.status_var = tk.StringVar(value="")
        ttk.Label(top, textvariable=self.status_var, foreground="#0a7d32").pack(side="right")

        # 列表
        style = ttk.Style(self)
        style.configure("Treeview", rowheight=30, font=("Consolas", 12))
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))

        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, padx=12, pady=6)

        cols = ("name", "code", "remain")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("name", text="名称")
        self.tree.heading("code", text="验证码")
        self.tree.heading("remain", text="剩余")
        self.tree.column("name", width=200, anchor="w")
        self.tree.column("code", width=140, anchor="center")
        self.tree.column("remain", width=70, anchor="center")

        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", lambda e: self._copy_selected())
        self.tree.bind("<Return>", lambda e: self._copy_selected())
        self.tree.bind("<Delete>", lambda e: self._delete())

        # 总进度条
        self.progress = ttk.Progressbar(self, mode="determinate", maximum=30)
        self.progress.pack(fill="x", padx=12, pady=(0, 6))

        self.hint_var = tk.StringVar(value="双击行或按回车复制验证码")
        ttk.Label(self, textvariable=self.hint_var, foreground="#888").pack(anchor="w", padx=12, pady=(0, 8))

        self._refresh_tree()

    def _refresh_tree(self):
        selected = self._selected_name()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for idx, acc in enumerate(self.accounts):
            self.tree.insert(
                "", "end", iid=str(idx), values=(acc["name"], "------", "--")
            )
        if selected is not None:
            for idx, acc in enumerate(self.accounts):
                if acc["name"] == selected:
                    self.tree.selection_set(str(idx))
                    break

    def _selected_index(self):
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            return int(sel[0])
        except ValueError:
            return None

    def _selected_name(self):
        idx = self._selected_index()
        if idx is None or idx >= len(self.accounts):
            return None
        return self.accounts[idx]["name"]

    def _tick(self):
        now = time.time()
        for idx, acc in enumerate(self.accounts):
            iid = str(idx)
            if not self.tree.exists(iid):
                continue
            try:
                code = totp(acc["secret"], now, acc.get("period", 30), acc.get("digits", 6))
                rem = acc.get("period", 30) - int(now) % acc.get("period", 30)
                self.tree.item(iid, values=(acc["name"], code, "%ds" % rem))
            except Exception:
                self.tree.item(iid, values=(acc["name"], "ERROR", "--"))
        rem = totp_remaining()
        self.progress["value"] = rem
        self.after(500, self._tick)

    def _copy_selected(self):
        idx = self._selected_index()
        if idx is None or idx >= len(self.accounts):
            self.hint_var.set("请先选中一行")
            return
        acc = self.accounts[idx]
        code = totp(acc["secret"], time.time(), acc.get("period", 30), acc.get("digits", 6))
        self.clipboard_clear()
        self.clipboard_append(code)
        self.status_var.set("已复制：%s → %s" % (acc["name"], code))
        self.after(2500, lambda: self.status_var.set(""))

    def _add(self):
        def on_save(acc):
            for existing in self.accounts:
                if existing["name"] == acc["name"]:
                    if not messagebox.askyesno("重名", "已存在同名账号 %s，是否覆盖？" % acc["name"]):
                        return
                    existing.update(acc)
                    break
            else:
                self.accounts.append(acc)
            try:
                save_accounts(self.accounts)
            except Exception as e:
                messagebox.showerror("保存失败", str(e))
                return
            self._refresh_tree()

        AddDialog(self, on_save)

    def _delete(self):
        idx = self._selected_index()
        if idx is None or idx >= len(self.accounts):
            messagebox.showinfo("提示", "请先选中要删除的账号")
            return
        acc = self.accounts[idx]
        if not messagebox.askyesno("确认", "删除账号 %s ？" % acc["name"]):
            return
        del self.accounts[idx]
        try:
            save_accounts(self.accounts)
        except Exception as e:
            messagebox.showerror("保存失败", str(e))
            return
        self._refresh_tree()


# ============================================================
# CLI 模式（给脚本调用，不弹 GUI）
# ============================================================
def cli_main(argv):
    if not argv:
        return None
    cmd = argv[0]
    if cmd == "--list":
        try:
            accounts = load_accounts()
        except Exception as e:
            print("读取失败：%s" % e)
            return 1
        if not accounts:
            print("（无账号）")
            return 0
        for acc in accounts:
            code = totp(acc["secret"], time.time(), acc.get("period", 30), acc.get("digits", 6))
            print("%s	%s	%s" % (acc["name"], code, acc["secret"]))
        return 0
    if cmd == "--code" and len(argv) >= 2:
        target = argv[1]
        try:
            accounts = load_accounts()
        except Exception as e:
            print("读取失败：%s" % e)
            return 1
        for acc in accounts:
            if acc["name"].lower() == target.lower():
                print(totp(acc["secret"], time.time(), acc.get("period", 30), acc.get("digits", 6)))
                return 0
        print("未找到账号：%s" % target, file=sys.stderr)
        return 2
    if cmd == "--add" and len(argv) >= 3:
        name, secret = argv[1], argv[2]
        if secret.lower().startswith("otpauth://"):
            parsed = parse_otpauth(secret)
            if not parsed:
                print("otpauth 解析失败", file=sys.stderr)
                return 1
            name = name or parsed["name"]
            secret = parsed["secret"]
            digits, period = parsed["digits"], parsed["period"]
        else:
            digits, period = 6, 30
        b32decode_padded(secret)
        accounts = load_accounts()
        for acc in accounts:
            if acc["name"] == name:
                acc.update({"secret": secret, "digits": digits, "period": period})
                break
        else:
            accounts.append({"name": name, "secret": secret, "digits": digits, "period": period})
        save_accounts(accounts)
        print("已保存：%s" % name)
        return 0
    if cmd == "--remove" and len(argv) >= 2:
        target = argv[1]
        accounts = load_accounts()
        before = len(accounts)
        accounts = [a for a in accounts if a["name"].lower() != target.lower()]
        if len(accounts) == before:
            print("未找到账号：%s" % target, file=sys.stderr)
            return 2
        save_accounts(accounts)
        print("已删除：%s" % target)
        return 0
    print(__doc__)
    return 0


def main():
    if len(sys.argv) > 1:
        rc = cli_main(sys.argv[1:])
        if rc is not None:
            sys.exit(rc)
    app = TotpApp()
    app.mainloop()


if __name__ == "__main__":
    main()
