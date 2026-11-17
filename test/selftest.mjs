/**
 * dsh-privacy-guard 自检（不弹窗、不联网、只写临时目录）
 * 运行：node test/selftest.mjs
 */
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const ROOT = await mkdtemp(join(tmpdir(), 'pg-selftest-'))
process.env.DSH_HOME = ROOT
process.env.USERPROFILE = ROOT

let passed = 0
let failed = 0
const failures = []

async function test(name, fn) {
  try {
    await fn()
    passed++
    console.log(`✅ ${name}`)
  } catch (error) {
    failed++
    failures.push({ name, error })
    console.error(`❌ ${name}\n   ${error?.stack || error}`)
  }
}

/* ---------------- crypto ---------------- */
const crypto = await import('../src/crypto.mjs')

await test('scrypt 派生稳定且不可逆', async () => {
  const salt = crypto.randomSalt()
  const a = await crypto.deriveKek('Correct-Horse-9', salt)
  const b = await crypto.deriveKek('Correct-Horse-9', salt)
  const c = await crypto.deriveKek('Correct-Horse-8', salt)
  assert.equal(a.toString('hex'), b.toString('hex'))
  assert.notEqual(a.toString('hex'), c.toString('hex'))
  assert.equal(a.length, 32)
})

await test('AES-256-GCM 往返 + 错误密钥失败', async () => {
  const key = crypto.randomKey()
  const other = crypto.randomKey()
  const blob = crypto.seal(key, '张三 13800138000')
  assert.ok(blob.length > 28)
  assert.equal(crypto.open(key, blob).toString('utf8'), '张三 13800138000')
  assert.throws(() => crypto.open(other, blob))
  const tampered = Buffer.from(blob)
  tampered[tampered.length - 1] ^= 0xff
  assert.throws(() => crypto.open(key, tampered))
})

/* ---------------- detect ---------------- */
const detect = await import('../src/detect.mjs')

await test('身份证校验位', async () => {
  assert.equal(detect.isValidIdCard('11010519491231002X'), true)
  assert.equal(detect.isValidIdCard('110105194912310021'), false)
  assert.equal(detect.isValidIdCard('11010519491331002X'), false) // 13 月
})

await test('银行卡 Luhn', async () => {
  assert.equal(detect.luhnOk('4111111111111111'), true)
  assert.equal(detect.luhnOk('4111111111111112'), false)
})

await test('检测：身份证/手机/姓名/密码/邮箱', async () => {
  const text = '姓名：李四\n身份证：11010519491231002X\n手机 13800138000\npassword: Abc!2345\n邮箱 lisi@example.com'
  const scan = detect.detectSensitive(text)
  const types = new Set(scan.findings.map((f) => f.type))
  for (const type of ['idcard', 'phone', 'name', 'password', 'email']) assert.ok(types.has(type), `缺少 ${type}`)
  assert.equal(scan.highest, 'high')
})

await test('银行卡带空格也能识别', async () => {
  const scan = detect.detectSensitive('卡号 4111 1111 1111 1111 请妥善保管')
  assert.ok(scan.findings.some((f) => f.type === 'bankcard'))
})

await test('脱敏不泄露原文', async () => {
  const scan = detect.detectSensitive('身份证 11010519491231002X')
  const idcard = scan.findings.find((f) => f.type === 'idcard')
  assert.ok(idcard)
  assert.ok(!idcard.masked.includes('110105'))
  assert.ok(detect.redactText('身份证 11010519491231002X', [idcard]).includes('已隐藏'))
})

await test('普通文本不误报', async () => {
  const scan = detect.detectSensitive('今天写了一个 3000 行的脚本，运行时间 1234 毫秒。')
  assert.equal(scan.findings.length, 0)
})

/* ---------------- paths ---------------- */
const paths = await import('../src/paths.mjs')

await test('路径归一化与家目录展开', async () => {
  assert.equal(paths.normalizeForCompare('C:\\Users\\A\\B\\'), 'c:/users/a/b')
  assert.equal(paths.expandHome('~/Desktop/个人'), join(ROOT, 'Desktop', '个人'))
  assert.ok(paths.isAbsoluteAnyPlatform('D:\\data'))
  assert.ok(paths.isAbsoluteAnyPlatform('\\\\server\\share'))
})

await test('受保护目录匹配（含通配符）', async () => {
  const root = paths.compileProtectedRoot(join(ROOT, 'Desktop', '个人'))
  assert.ok(root)
  assert.ok(paths.matchProtected(join(ROOT, 'Desktop', '个人', '简历.pdf'), [root]))
  assert.ok(paths.matchProtected(join(ROOT, 'Desktop', '个人'), [root]))
  assert.equal(paths.matchProtected(join(ROOT, 'Desktop', 'work', 'a.txt'), [root]), null)
  const glob = paths.compileProtectedRoot(join(ROOT, 'Documents', '**', '证件'))
  assert.ok(paths.matchProtected(join(ROOT, 'Documents', 'a', 'b', '证件', 'x.txt'), [glob]))
})

await test('shell 命令里的受保护路径识别', async () => {
  const root = paths.compileProtectedRoot(join(ROOT, 'Desktop', '个人'))
  const hits1 = paths.matchProtectedInText(`Get-Content "${join(ROOT, 'Desktop', '个人', 'a.txt')}"`, [root])
  assert.equal(hits1.length, 1)
  const hits2 = paths.matchProtectedInText(`cd ~/Desktop/个人 && dir`, [root], ROOT)
  assert.equal(hits2.length, 1)
  const hits3 = paths.matchProtectedInText('echo hello', [root], ROOT)
  assert.equal(hits3.length, 0)
  // 家目录相对写法：即使根目录只有一段（~/个人），也能识别
  const homeLevel = paths.compileProtectedRoot(join(ROOT, '个人'))
  assert.equal(paths.matchProtectedInText('cd ~/个人 && ls', [homeLevel], ROOT).length, 1)
})

await test('参数抽取：file_path / command', async () => {
  const { paths: p, commands: c } = paths.extractTargets({
    file_path: join(ROOT, 'Desktop', '个人', 'a.txt'),
    offset: 1,
    limit: 20,
  })
  assert.equal(p.length, 1)
  const shell = paths.extractTargets({ command: `type "${join(ROOT, 'Desktop', '个人', 'a.txt')}"` })
  assert.equal(shell.commands.length, 1)
})

/* ---------------- store ---------------- */
const store = await import('../src/store.mjs')

await test('配置默认值与持久化', async () => {
  const config = await store.loadConfig({ force: true })
  assert.equal(typeof config.enabled, 'boolean')
  assert.ok(Array.isArray(config.protectedPaths))
  await store.saveConfig({ enabled: false })
  const reloaded = await store.loadConfig({ force: true })
  assert.equal(reloaded.enabled, false)
  await store.saveConfig({ enabled: true })
  const raw = JSON.parse(await readFile(store.CONFIG_PATH, 'utf8'))
  assert.equal(raw.enabled, true)
})

/* ---------------- 拦截管线 ---------------- */
await test('pre-execute 拦截受保护路径 / 放行普通路径', async () => {
  const { PrivacyGuard } = await import('../src/index.mjs')
  const protectedDir = join(ROOT, 'Desktop', '个人')
  await mkdir(protectedDir, { recursive: true })
  await store.saveConfig({ protectedPaths: [protectedDir] })

  const guard = new PrivacyGuard({ get: () => undefined, on: () => {}, effect: () => {} }, {})
  await guard.reloadConfig()
  let asked = 0
  guard.authorize = async () => {
    asked++
    return { allow: false, remember: false, reason: '测试拒绝' }
  }
  const exec = (name, args) => ({ name, arguments: args, callId: 'c1', agent: { id: 's1' } })

  const denied = await guard.beforeTool(exec('read', { file_path: join(protectedDir, '简历.pdf') }), async () => ({ kind: 'allow' }))
  assert.equal(denied.kind, 'deny')
  assert.equal(asked, 1)

  const allowed = await guard.beforeTool(exec('read', { file_path: join(ROOT, 'work', 'note.md') }), async () => ({ kind: 'allow' }))
  assert.equal(allowed.kind, 'allow')
  assert.equal(asked, 1)
})

await test('post-execute：命中敏感内容默认阻断，授权后放行', async () => {
  const { PrivacyGuard } = await import('../src/index.mjs')
  const guard = new PrivacyGuard({ get: () => undefined, on: () => {}, effect: () => {} }, {})
  await guard.reloadConfig()
  const result = {
    isError: false,
    value: null,
    content: [{ type: 'text', text: '身份证 11010519491231002X 手机 13800138000' }],
  }
  const exec = { name: 'read', arguments: { file_path: join(ROOT, 'Downloads', 'a.txt') }, callId: 'c2', agent: { id: 's2' } }

  guard.authorize = async () => ({ allow: false, remember: false, reason: '测试拒绝' })
  const blocked = await guard.afterTool(exec, result, async () => ({ kind: 'accept' }))
  assert.equal(blocked.kind, 'block')
  assert.ok(String(blocked.feedback[0].text).includes('隐私守卫'))

  guard.authorize = async () => ({ allow: true, remember: true, reason: 'approved' })
  const accepted = await guard.afterTool({ ...exec, callId: 'c3' }, result, async () => ({ kind: 'accept' }))
  assert.equal(accepted.kind, 'accept')
  assert.ok(guard.hasGrant(guard.contentGrantKey('s2', ['idcard'])))

  // 不同类型集合的授权互不覆盖：批准了身份证，不代表也批准了密码
  assert.equal(guard.hasGrant(guard.contentGrantKey('s2', ['password'])), false)

  // 有授权后，同一会话第二次直接放行，不再询问
  let askedAgain = false
  guard.authorize = async () => {
    askedAgain = true
    return { allow: false, remember: false, reason: 'x' }
  }
  const second = await guard.afterTool({ ...exec, callId: 'c4' }, result, async () => ({ kind: 'accept' }))
  assert.equal(second.kind, 'accept')
  assert.equal(askedAgain, false)
})

await test('post-execute：一次性授权不复用', async () => {
  const { PrivacyGuard } = await import('../src/index.mjs')
  const guard = new PrivacyGuard({ get: () => undefined, on: () => {}, effect: () => {} }, {})
  await guard.reloadConfig()
  const result = { isError: false, value: null, content: [{ type: 'text', text: 'password: Abc!2345' }] }
  const exec = { name: 'read', arguments: { file_path: join(ROOT, 'Downloads', 'b.txt') }, callId: 'once-1', agent: { id: 's3' } }
  guard.authorize = async () => ({ allow: true, remember: false, reason: 'approved' })
  guard.oneShotCalls.add('once-1')
  const first = await guard.afterTool(exec, result, async () => ({ kind: 'accept' }))
  assert.equal(first.kind, 'accept')
  assert.equal(guard.hasGrant(guard.contentGrantKey('s3', ['password'])), false)
})

await test('密码设置 / 解锁 / 错误密码 / 锁定', async () => {
  const { PrivacyGuard } = await import('../src/index.mjs')
  const guard = new PrivacyGuard({ get: () => undefined, on: () => {}, effect: () => {} }, {})
  await guard.reloadConfig()
  // 直接构造 secrets，绕过弹窗
  const salt = crypto.randomSalt()
  const dek = crypto.randomKey()
  const kek = await crypto.deriveKek('Test-Pass-123', salt)
  await store.saveSecrets({
    version: 1,
    salt: salt.toString('base64'),
    params: { ...crypto.DEFAULT_KDF },
    wrappedKey: crypto.seal(kek, dek).toString('base64'),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  })
  await store.writeVault(dek, { version: 1, entries: [] })

  const wrong = await guard.unlockWithPassword('nope')
  assert.equal(wrong.ok, false)
  const right = await guard.unlockWithPassword('Test-Pass-123')
  assert.equal(right.ok, true)
  assert.equal(guard.isUnlocked(), true)
  const vault = await store.readVault(guard.vaultKey)
  assert.equal(vault.entries.length, 0)
})

await test('收集：元数据与加密值入库', async () => {
  const { PrivacyGuard } = await import('../src/index.mjs')
  const collectDir = join(ROOT, 'Desktop', '个人')
  await mkdir(collectDir, { recursive: true })
  await writeFile(join(collectDir, 'info.txt'), '姓名：王五\n手机：13900139000\n身份证：11010519491231002X\n', 'utf8')
  await store.saveConfig({ collectRoots: [collectDir], collectMaxFiles: 50, autoCollect: true })

  const guard = new PrivacyGuard({ get: () => undefined, on: () => {}, effect: () => {} }, {})
  await guard.reloadConfig()
  await guard.unlockWithPassword('Test-Pass-123')
  const result = await guard.collect({ withValues: true })
  assert.equal(result.ok, true)
  assert.ok(result.findings >= 3, `findings=${result.findings}`)
  const vault = await store.readVault(guard.vaultKey)
  assert.ok(vault.entries.length >= 3)
  const index = await store.loadIndex()
  assert.ok(Object.keys(index.sources).some((p) => p.endsWith('info.txt')))
  assert.ok(Object.keys(index.totals).length > 0)
})

await test('授权令牌过期后失效', async () => {
  const { PrivacyGuard } = await import('../src/index.mjs')
  const guard = new PrivacyGuard({ get: () => undefined, on: () => {}, effect: () => {} }, {})
  await guard.reloadConfig()
  guard.issueGrant('k', 0.01)
  assert.equal(guard.hasGrant('k'), true)
  await new Promise((r) => setTimeout(r, 30))
  assert.equal(guard.hasGrant('k'), false)
})

await test('认证对话框脚本可读（不弹窗）', async () => {
  const dialog = await import('../src/dialog.mjs')
  const probe = await dialog.probeDialog()
  if (process.platform === 'win32') {
    assert.equal(probe.okExe, true, `找不到 PowerShell: ${probe.exe}`)
  }
  assert.equal(probe.okScript, true)
})

await rm(ROOT, { recursive: true, force: true })
console.log(`\n合计：通过 ${passed}，失败 ${failed}`)
if (failed > 0) {
  for (const f of failures) console.error(`- ${f.name}: ${f.error?.message || f.error}`)
  process.exitCode = 1
}
