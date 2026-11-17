# 发布清单

## 1. 发布前检查

- [x] 仓库内**不含**任何个人数据：无本机路径、无姓名/学号/邮箱、无截图、无盘点产物
- [x] `src/` 与开发版一致，`node test/selftest.mjs` 20/20 通过
- [x] 仅支持 Windows（`package.json` 的 `os: ["win32"]`）
- [x] 把 `README.md` / `README.en.md` 里的 GitHub 用户名替换为 `KaBanei`
- [x] `package.json` 已补齐 `repository` / `homepage` / `bugs`

## 2. 建仓

```powershell
cd dsh-privacy-guard
git init
git add .
git commit -m "feat: dsh-privacy-guard 0.1.0"
git branch -M main
git remote add origin https://github.com/KaBanei/dsh-privacy-guard.git
git push -u origin main
```

> 注意：`git commit` 会写入你的 git 用户名/邮箱。本仓库已固定为
> `KaBanei <KaBanei@users.noreply.github.com>`，不会暴露私人邮箱。

## 3. 本地安装验证

```powershell
dsh plugin --profile desktop add .\dsh-privacy-guard
# 重启 DSH 后
/privacy test
```

也可以直接用 GitHub 地址安装：

```powershell
dsh plugin --profile desktop add github:KaBanei/dsh-privacy-guard
```

## 4. 发布 npm（可选）

```powershell
npm login
npm publish
```

发布后安装方式变为：

```powershell
dsh plugin --profile desktop add dsh-privacy-guard
```

## 5. 提交到 DSH 插件社区 / 市场

- 确认仓库带 `dsh-plugin`、`deepseek-harness` 等 topic，便于市场索引；
- 按市场要求提交仓库地址（通常只需一个公开的 GitHub 仓库 + `package.json` 里的 `dsh` 字段）；
- 建议打 tag：`git tag v0.1.0 && git push --tags`，并在 GitHub Release 里附上 `dist/dsh-privacy-guard-0.1.0.tgz`。

## 6. 后续版本

- 修改 `package.json` 的 `version` 与 `CHANGELOG.md`；
- 重新跑 `node test/selftest.mjs`；
- 打 tag 并发布。
