# Changelog

## 0.1.0 — 2026-11-17

首个公开版本。

- 路径层拦截：`tools/pre-execute` 命中受保护目录时弹出 Windows 原生认证窗
- 内容层拦截：`tools/post-execute` 命中身份证（校验位）、银行卡（Luhn）、手机号、邮箱、密码、API Key、私钥等时阻断/放行
- 加密隐私库：scrypt（N=32768）+ AES-256-GCM，密码不落盘
- `/privacy` 命令族：setup / lock / unlock / scan / vault / paths / addpath / rmpath / on / off / strict / audit / test
- 授权有效期、弹窗频率限制、连续错误锁定
- 审计只记录类型/路径/时间，不记录值
- 20 项自动化自检
