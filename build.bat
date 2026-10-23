@echo off
chcp 65001 >nul
setlocal

cd /d "%~dp0"

set PY=E:\python\python-V\python3.14\python.exe

echo [1/2] 清理旧产物...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist TotpGen.spec del /q TotpGen.spec

echo [2/2] PyInstaller 打包（单文件、无控制台）...
"%PY%" -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --onefile ^
  --windowed ^
  --name TotpGen ^
  --hidden-import tkinter ^
  --hidden-import tkinter.ttk ^
  --hidden-import tkinter.messagebox ^
  totp_gen.py

if errorlevel 1 (
  echo.
  echo [失败] 打包出错
  exit /b 1
)

echo.
echo [完成] 产物: dist\TotpGen.exe
dir /b dist
endlocal
