# TotpGen — 本地离线验证码生成器

在 Windows 上离线生成 TOTP（两步验证）验证码，不联网、不依赖任何网页或云服务。

## 特性

- **纯标准库实现**：RFC 6238 / RFC 4226 算法，SHA1 + 6/8 位，30/60 秒周期
- **加密存储**：secret 用 Windows DPAPI 加密，绑定当前 Windows 用户；vault 文件拷到别人电脑解不开
- **完全离线**：程序不发起任何网络请求
- **单文件 exe**：约 15MB，双击即用，无需安装 Python
- **命令行模式**：可供脚本调用（--code / --list / --add / --remove）

## 快速开始

### 图形界面

双击 `TotpGen.exe`，然后：

1. 点「＋ 添加账号」
2. 名称填 `GitHub`
3. Secret 填你的 Base32 secret（GitHub 重新配置 2FA 时给的那串），或直接粘贴 `otpauth://` 链接（会自动解析）
4. 保存后列表里实时显示验证码和倒计时
5. 双击行 / 按回车 → 验证码复制到剪贴板

### 命令行（给脚本用）

```bat
TotpGen.exe --add "GitHub" JBSWY3DPEHPK3PXP
TotpGen.exe --code GitHub
TotpGen.exe --list
TotpGen.exe --remove GitHub
```

## 数据位置

`%APPDATA%\TotpGen\vault.dat`（DPAPI 加密的二进制，非明文）

- 备份：直接复制该文件
- 迁移到新电脑：**无法直接使用**（DPAPI 绑当前 Windows 用户），需在新机器用 `--add` 重新导入 secret
- 删除：删掉该文件即清空所有账号

## 安全说明

- secret 就是第二因素的根密钥，泄露等于 2FA 失效
- vault.dat 只在本机、本 Windows 用户下可解密
- 不要把这个 exe 和 vault.dat 一起发给别人
- 建议同时在手机验证器 App 里保留一份，避免单点丢失

## 重新绑定 GitHub 2FA

如果旧 secret 丢了（比如只在 totp.app 里），按以下步骤重新绑定，不影响账号：

1. 登录 GitHub → Settings → Password and authentication
2. 找到 Two-factor authentication → 点 **Reconfigure two-factor authentication**
3. 选择 **Authenticator app** → 页面显示 QR 码和 secret
4. 点「enter this text code instead」可看到明文 secret
5. 把这个 secret 用 `TotpGen.exe --add "GitHub" <secret>` 添加
6. 用 TotpGen 生成的验证码填入 GitHub 完成确认
7. 保存好新的恢复代码

## 开发

```bat
:: 跑测试
E:\python\python-V\python3.14\python.exe -X utf8 test_totp.py

:: 打包
build.bat
```

## 文件说明

| 文件 | 说明 |
|---|---|
| `totp_gen.py` | 主程序（GUI + CLI + DPAPI） |
| `test_totp.py` | RFC 6238 官方向量测试 |
| `build.bat` | PyInstaller 打包脚本 |
| `dist/TotpGen.exe` | 打包产物 |
