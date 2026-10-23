# -*- coding: utf-8 -*-
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from totp_gen import totp, hotp, b32decode_padded, parse_otpauth

BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"

print("=== RFC 6238 官方向量（SHA1, 6位）===")
vectors = [
    (59,          "287082"),
    (1111111109,  "081804"),
    (1111111111,  "050471"),
    (1234567890,  "005924"),
    (2000000000,  "279037"),
    (20000000000, "353130"),
]
ok = 0
for t, expect in vectors:
    got = totp(BASE32, at=t, period=30, digits=6)
    mark = "OK " if got == expect else "FAIL"
    print(f"  T={t:<12} expect={expect}  got={got}  {mark}")
    if got == expect:
        ok += 1

print(f"\n结果: {ok}/{len(vectors)} 通过")

print("\n=== otpauth 解析测试 ===")
uri = "otpauth://totp/GitHub:cymylive?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30"
p = parse_otpauth(uri)
print("  解析:", p)
assert p and p["secret"] == "JBSWY3DPEHPK3PXP", "otpauth 解析失败"
print("  OK")

print("\n=== 带空格的 secret 容错 ===")
c1 = totp("JBSW Y3DP EHPK 3PXP", at=1700000000)
c2 = totp("JBSWY3DPEHPK3PXP", at=1700000000)
print(f"  带空格={c1}  无空格={c2}  {'OK' if c1==c2 else 'FAIL'}")

sys.exit(0 if ok == len(vectors) else 1)
