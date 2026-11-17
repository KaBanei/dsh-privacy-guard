/**
 * dsh-privacy-guard — 主机端插件
 *
 * 目标：AI（工具调用）一旦要读写「个人隐私数据」，必须先通过本机身份认证
 * （用户单独设置的隐私密码）并明确同意；平时自动收集敏感信息，只在本机加密保存。
 *
 * 拦截点：
 *   tools/pre-execute   路径命中受保护目录 → 弹原生窗口做密码认证 + 授权
 *   tools/post-execute  工具返回内容里出现高敏感信息（或来自受保护目录）→ 同样拦截，
 *                       拒绝时整段结果被阻断，模型拿不到原文
 *
 * 命令（人工输入，模型不可调用）：
 *   /privacy status|setup|lock|unlock|scan|vault|paths|addpath|rmpath|on|off|strict|audit|test
 */
import { createHash } from 'node:crypto'
import { readdir, stat, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { detectSensitive, describeFindings } from './detect.mjs'
import { deriveKek, open as openSealed, randomKey, randomSalt, seal, wipe, DEFAULT_KDF } from './crypto.mjs'
import * as store from './store.mjs'
import {
  compileProtectedRoot,
  extractTargets,
  getHome,
  matchProtected,
  matchProtectedInText,
  normalizeForCompare,
  toAbsolute,
} from './paths.mjs'
import { probeDialog, showDialog } from './dialog.mjs'

export const name = 'dsh-privacy-guard'
export const inject = ['commands']

export const PRIVACY_GUARD_VERSION = '0.1.0'
const LOG_PREFIX = '[privacy-guard]'
const CONTENT_GRANT = 'content'

function log(...args) {
  try {
    console.log(LOG_PREFIX, ...args)
  } catch {
    /* ignore */
  }
}

function warn(...args) {
  try {
    console.warn(LOG_PREFIX, ...args)
  } catch {
    /* ignore */
  }
}

function sha256Short(value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 24)
}

function nowMs() {
  return Date.now()
}

function normalizeDecision(value) {
  return String(value || '').trim().toLowerCase()
}

/** 把毫秒格式化成 "12 分钟" 这类短文本 */
function formatDuration(ms) {
  const total = Math.max(0, Math.round(ms / 1000))
  if (total < 60) return `${total} 秒`
  const minutes = Math.floor(total / 60)
  if (minutes < 60) return `${minutes} 分钟`
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  return rest ? `${hours} 小时 ${rest} 分钟` : `${hours} 小时`
}

class PrivacyGuard {
  constructor(ctx, pluginConfig = {}) {
    this.ctx = ctx
    this.pluginConfig = pluginConfig && typeof pluginConfig === 'object' ? pluginConfig : {}
    this.config = null
    this.compiledRoots = []
    this.vaultKey = null
    this.keyExpiresAt = 0
    this.grants = new Map()
    this.oneShotCalls = new Set()
    this.promptTimes = []
    this.promptChain = Promise.resolve()
    this.vaultChain = Promise.resolve()
    this.disposed = false
    this.collecting = false
    this.lastCollectAt = 0
    this.timers = []
    this.collectTimer = null
  }

  /* ---------------------------------------------------------------- */
  /* 生命周期                                                          */
  /* ---------------------------------------------------------------- */

  start() {
    this.reloadConfig().catch((error) => warn('加载配置失败', error))
    this.timers.push(startCollector(this))
    log(`已启用（v${PRIVACY_GUARD_VERSION}），数据目录：${store.DATA_DIR}`)
  }

  dispose() {
    if (this.disposed) return
    this.disposed = true
    for (const timer of this.timers) {
      try {
        timer()
      } catch {
        /* ignore */
      }
    }
    this.timers = []
    this.lock('plugin-disposed')
  }

  /* ---------------------------------------------------------------- */
  /* 配置与索引                                                        */
  /* ---------------------------------------------------------------- */

  async reloadConfig() {
    const loaded = await store.loadConfig()
    const merged = { ...loaded, ...this.pluginConfig }
    // 插件行里的显式配置优先于磁盘配置（便于部署时锁定策略）
    this.config = merged
    this.compiledRoots = (Array.isArray(merged.protectedPaths) ? merged.protectedPaths : [])
      .map((root) => compileProtectedRoot(root))
      .filter(Boolean)
    return this.config
  }

  isEnabled() {
    return Boolean(this.config && this.config.enabled !== false)
  }

  /* ---------------------------------------------------------------- */
  /* 密钥状态                                                          */
  /* ---------------------------------------------------------------- */

  hasSecrets() {
    return store.loadSecrets().then((secrets) => Boolean(secrets && secrets.salt && secrets.wrappedKey))
  }

  isUnlocked() {
    if (!this.vaultKey) return false
    if (nowMs() >= this.keyExpiresAt) {
      this.lock('key-cache-expired')
      return false
    }
    return true
  }

  async unlockWithPassword(password) {
    const secrets = await store.loadSecrets()
    if (!secrets || !secrets.salt || !secrets.wrappedKey) {
      return { ok: false, reason: '尚未设置隐私密码' }
    }
    const state = await store.loadState()
    if (state.lockedUntil && state.lockedUntil > nowMs()) {
      return { ok: false, reason: `尝试次数过多，请在 ${formatDuration(state.lockedUntil - nowMs())} 后重试`, locked: true }
    }
    const salt = Buffer.from(String(secrets.salt), 'base64')
    let kek
    try {
      kek = await deriveKek(String(password), salt, secrets.params || DEFAULT_KDF)
      const dek = openSealed(kek, Buffer.from(String(secrets.wrappedKey), 'base64'))
      if (!Buffer.isBuffer(dek) || dek.length !== 32) throw new Error('密钥长度异常')
      // 真正解密一次隐私库，确认密钥可用（也顺带验证文件未损坏）
      try {
        await store.readVault(dek)
      } catch (error) {
        if (String(error?.message || '').includes('密文损坏')) throw error
      }
      wipe(this.vaultKey)
      this.vaultKey = dek
      this.keyExpiresAt = nowMs() + Math.max(1, Number(this.config?.keyCacheMinutes ?? 15)) * 60_000
      await store.saveState({ failedAttempts: 0, lockedUntil: 0 })
      return { ok: true }
    } catch {
      const failedAttempts = Number(state.failedAttempts || 0) + 1
      let lockedUntil = 0
      if (failedAttempts >= 5) {
        const backoff = Math.min(30 * 60_000, 30_000 * 2 ** (failedAttempts - 5))
        lockedUntil = nowMs() + backoff
      }
      await store.saveState({ failedAttempts, lockedUntil })
      return {
        ok: false,
        reason: failedAttempts >= 5 ? '密码错误次数过多，已暂时锁定' : '密码错误',
        failedAttempts,
        locked: failedAttempts >= 5,
      }
    } finally {
      if (kek) wipe(kek)
    }
  }

  touchKey() {
    if (this.vaultKey) this.keyExpiresAt = nowMs() + Math.max(1, Number(this.config?.keyCacheMinutes ?? 15)) * 60_000
  }

  lock(reason = 'manual') {
    if (this.vaultKey) {
      wipe(this.vaultKey)
      this.vaultKey = null
    }
    this.keyExpiresAt = 0
    this.grants.clear()
    this.oneShotCalls.clear()
    if (reason !== 'plugin-disposed') log(`已锁定（${reason}）`)
  }

  requireKey() {
    if (!this.isUnlocked()) return { ok: false, reason: '隐私库未解锁，请先运行 /privacy unlock 或完成一次认证' }
    return { ok: true, key: this.vaultKey }
  }

  /* ---------------------------------------------------------------- */
  /* 授权令牌（grants）                                                 */
  /* ---------------------------------------------------------------- */

  grantKey(root, sessionId) {
    return `path:${root.normalized}:${sessionId || 'system'}`
  }

  contentGrantKey(sessionId, types) {
    // 按「命中的敏感类型集合」发放：批准了手机号，不等于也批准了身份证号。
    const normalized = (Array.isArray(types) ? types : [types]).filter(Boolean).sort().join(',')
    return `content:${normalized}:${sessionId || 'system'}`
  }

  hasGrant(key) {
    const expiresAt = this.grants.get(key)
    if (!expiresAt) return false
    if (expiresAt <= nowMs()) {
      this.grants.delete(key)
      return false
    }
    return true
  }

  issueGrant(key, ttlSeconds) {
    const ttl = Number(ttlSeconds)
    if (!Number.isFinite(ttl) || ttl <= 0) return
    this.grants.set(key, nowMs() + ttl * 1000)
  }

  /* ---------------------------------------------------------------- */
  /* 工具调用分析                                                      */
  /* ---------------------------------------------------------------- */

  sessionIdOf(exec) {
    try {
      const agent = exec?.agent
      if (!agent) return 'system'
      return String(agent.id ?? agent.session?.id ?? agent.session ?? 'system')
    } catch {
      return 'system'
    }
  }

  baseDirOf(exec) {
    try {
      const workingDirectory = this.ctx.get('workingDirectory')
      const agent = exec?.agent
      const session = agent?.session ?? agent
      if (workingDirectory && session && typeof workingDirectory.get === 'function') {
        const dir = workingDirectory.get(session)
        if (dir) return dir
      }
      if (workingDirectory?.defaultDirectory) return workingDirectory.defaultDirectory
    } catch {
      /* 服务不可用时退回进程目录 */
    }
    return process.cwd()
  }

  classify(exec) {
    const toolName = String(exec?.name ?? '')
    const baseDir = this.baseDirOf(exec)
    const { paths, commands } = extractTargets(exec?.arguments ?? {})
    const absPaths = []
    const seen = new Set()
    for (const raw of paths) {
      const abs = toAbsolute(raw, baseDir)
      if (!abs || seen.has(abs)) continue
      seen.add(abs)
      absPaths.push(abs)
    }
    const matchedRoots = new Map()
    const matchedPaths = []
    for (const abs of absPaths) {
      const root = matchProtected(abs, this.compiledRoots)
      if (root) {
        matchedRoots.set(root.normalized, root)
        matchedPaths.push(abs)
      }
    }
    for (const command of commands) {
      for (const root of matchProtectedInText(command, this.compiledRoots)) {
        matchedRoots.set(root.normalized, root)
      }
    }
    return {
      toolName,
      op: classifyOperation(toolName),
      paths: absPaths,
      matchedPaths,
      roots: [...matchedRoots.values()],
      protected: matchedRoots.size > 0,
    }
  }

  /* ---------------------------------------------------------------- */
  /* 拦截：pre-execute                                                 */
  /* ---------------------------------------------------------------- */

  async beforeTool(exec, next) {
    try {
      if (this.disposed) return next()
      await this.reloadConfig()
      if (!this.isEnabled()) return next()
      const info = this.classify(exec)
      if (!info.protected) return next()
      const sessionId = this.sessionIdOf(exec)
      const missing = info.roots.filter((root) => !this.hasGrant(this.grantKey(root, sessionId)))
      if (missing.length === 0) {
        this.touchKey()
        return next()
      }
      const decision = await this.authorize({
        kind: 'path',
        sessionId,
        exec,
        info,
        roots: missing,
        findings: [],
        signal: exec?.signal,
      })
      if (!decision.allow) {
        return denyDecision(decision.reason, 'PRIVACY_DENIED')
      }
      if (decision.remember) {
        for (const root of missing) this.issueGrant(this.grantKey(root, sessionId), this.config.grantTtlSeconds)
      } else {
        // 一次性授权：只放行当前这次调用。设个上限，防止调用被取消后
        // callId 长期堆积（数量级很小，纯防泄漏）。
        if (this.oneShotCalls.size > 500) this.oneShotCalls.clear()
        this.oneShotCalls.add(String(exec?.callId ?? ''))
      }
      return next()
    } catch (error) {
      warn('pre-execute 处理失败（放行本次调用）', error)
      return next()
    }
  }

  /* ---------------------------------------------------------------- */
  /* 拦截：post-execute                                                */
  /* ---------------------------------------------------------------- */

  async afterTool(exec, result, next) {
    try {
      if (this.disposed) return next()
      const callId = String(exec?.callId ?? '')
      if (this.oneShotCalls.delete(callId)) return next()
      await this.reloadConfig()
      if (!this.isEnabled()) return next()
      const toolName = String(exec?.name ?? '')
      if (isSearchOrWebTool(toolName) && !this.config.scanWebResults) return next()
      const text = extractResultText(result)
      if (!text) return next()

      const scan = detectSensitive(text, { extraPatterns: this.config.extraPatterns })
      if (scan.findings.length === 0) return next()

      const info = this.classify(exec)
      const sessionId = this.sessionIdOf(exec)
      const relevant = info.protected || this.config.strictScan
        ? scan.findings
        : scan.findings.filter((finding) => finding.severity === 'high')
      if (relevant.length === 0) return next()

      const contentKey = this.contentGrantKey(sessionId, relevant.map((finding) => finding.type))
      if (this.hasGrant(contentKey)) return next()
      if (info.roots.length > 0 && info.roots.every((root) => this.hasGrant(this.grantKey(root, sessionId)))) {
        return next()
      }

      const decision = await this.authorize({
        kind: 'content',
        sessionId,
        exec,
        info,
        roots: info.roots,
        findings: relevant,
        signal: exec?.signal,
      })
      if (decision.allow) {
        this.issueGrant(contentKey, this.config.grantTtlSeconds)
        return next()
      }

      const masked = summarizeMasked(relevant)
      const feedback = [
        {
          type: 'text',
          text:
            `[隐私守卫] 本次工具结果包含个人隐私信息，已按用户意愿阻断，原文没有返回给模型。\n` +
            `检测到：${describeFindings(relevant)}\n` +
            (masked ? `脱敏示例：${masked}\n` : '') +
            `处理建议：不要重复重试同一读取；如果需要该信息，请用户运行 /privacy unlock 或明确授权后重新发起。`,
        },
      ]
      // 审计已在 authorize() 里按 allow/deny 记录一次，这里不再重复写
      return { kind: 'block', feedback, info: { name: 'PrivacyGuard', code: 'PRIVACY_BLOCKED' } }
    } catch (error) {
      warn('post-execute 处理失败（放行本次结果）', error)
      return next()
    }
  }

  /* ---------------------------------------------------------------- */
  /* 认证 + 授权                                                       */
  /* ---------------------------------------------------------------- */

  async authorize(request) {
    const { sessionId, exec, info, roots, findings, signal } = request
    const toolName = String(exec?.name ?? '')

    // 频率限制：避免被连续工具调用刷屏
    const cutoff = nowMs() - 60_000
    this.promptTimes = this.promptTimes.filter((t) => t > cutoff)
    if (this.promptTimes.length >= Math.max(1, Number(this.config.maxPromptsPerMinute ?? 6))) {
      await store.appendAudit({ kind: 'auth', sessionId, tool: toolName, decision: 'deny', reason: 'rate-limit' })
      return { allow: false, remember: false, reason: '隐私守卫：认证请求过于频繁，已自动拒绝，请稍后再试' }
    }

    // 串行化：同一时间只显示一个认证窗口
    const run = async () => {
      // 等锁期间可能已经授权过
      if (request.kind === 'path' && roots.every((root) => this.hasGrant(this.grantKey(root, sessionId)))) {
        return { allow: true, remember: true, reason: 'granted-while-waiting' }
      }

      const firstRun = await this.ensureInitialized({ signal })
      if (!firstRun.ok) {
        return { allow: false, remember: false, reason: firstRun.reason }
      }

      const details = buildDialogDetails({ kind: request.kind, op: info.op, tool: toolName, paths: info.matchedPaths, roots, findings })
      const ttlMinutes = Math.max(1, Math.round(Number(this.config.grantTtlSeconds ?? 600) / 60))
      let error = ''
      for (let attempt = 0; attempt < 3; attempt++) {
        this.promptTimes.push(nowMs())
        const response = await showDialog(
          {
            mode: 'auth',
            title: '隐私守卫 — 身份认证',
            heading: request.kind === 'path' ? 'AI 请求访问受保护的隐私数据' : 'AI 读取到个人隐私信息',
            sub: '请确认下方内容，输入隐私密码后才允许本次访问。',
            details,
            error,
            allowRemember: true,
            rememberText: `记住本次授权（${ttlMinutes} 分钟内同一位置不再询问）`,
            timeoutSec: Math.max(10, Number(this.config.promptTimeoutSeconds ?? 120)),
            okText: '允许本次',
            cancelText: '拒绝',
          },
          { signal },
        )

        const verdict = normalizeDecision(response?.decision)
        if (verdict === 'allow') {
          const verification = await this.unlockWithPassword(response.password)
          if (verification.ok) {
            this.touchKey()
            await store.appendAudit({
              kind: request.kind,
              sessionId,
              tool: toolName,
              callId: String(exec?.callId ?? ''),
              decision: 'allow',
              remember: Boolean(response.remember),
              types: (findings || []).reduce((acc, f) => ((acc[f.type] = (acc[f.type] || 0) + 1), acc), {}),
              paths: info.matchedPaths.slice(0, 5),
            })
            return { allow: true, remember: Boolean(response.remember), reason: 'approved' }
          }
          if (verification.locked) {
            await store.appendAudit({ kind: request.kind, sessionId, tool: toolName, decision: 'deny', reason: 'locked-out' })
            return { allow: false, remember: false, reason: `隐私守卫：${verification.reason}，请稍后再试` }
          }
          error = verification.reason + '，请重试'
          await new Promise((r) => setTimeout(r, 350))
          continue
        }
        if (verdict === 'timeout') {
          await store.appendAudit({ kind: request.kind, sessionId, tool: toolName, decision: 'deny', reason: 'timeout' })
          return { allow: false, remember: false, reason: '隐私守卫：认证超时，已拒绝本次访问' }
        }
        if (verdict === 'unavailable') {
          await store.appendAudit({ kind: request.kind, sessionId, tool: toolName, decision: 'deny', reason: 'dialog-unavailable' })
          return {
            allow: false,
            remember: false,
            reason: `隐私守卫：无法弹出认证窗口（${response?.error || '未知原因'}），已拒绝本次访问`,
          }
        }
        // cancel / deny
        if (verdict === 'cancelled') {
          await store.appendAudit({ kind: request.kind, sessionId, tool: toolName, decision: 'deny', reason: 'cancelled' })
          return { allow: false, remember: false, reason: '隐私守卫：操作已取消' }
        }
        await store.appendAudit({ kind: request.kind, sessionId, tool: toolName, decision: 'deny', reason: 'user-rejected' })
        return { allow: false, remember: false, reason: '隐私守卫：用户拒绝访问该隐私数据' }
      }
      return { allow: false, remember: false, reason: `隐私守卫：${error || '认证失败'}` }
    }

    const chained = this.promptChain.then(run, run)
    this.promptChain = chained.then(
      () => undefined,
      () => undefined,
    )
    return chained
  }

  /** 首次使用时引导设置密码；已设置则直接通过 */
  async ensureInitialized({ signal } = {}) {
    const secrets = await store.loadSecrets()
    if (secrets && secrets.salt && secrets.wrappedKey) return { ok: true }
    const setup = await this.runSetup({ signal, firstRun: true })
    if (!setup.ok) return { ok: false, reason: `隐私守卫尚未初始化：${setup.reason}` }
    await store.appendAudit({ kind: 'setup', decision: 'allow', reason: 'first-run' })
    return { ok: true }
  }

  /** 设置 / 更换隐私密码。已存在密码时先验证旧密码。 */
  async runSetup({ signal, firstRun = false } = {}) {
    const existing = await this.hasSecrets()
    let oldKey = this.isUnlocked() ? this.vaultKey : null

    if (existing && !oldKey) {
      const verify = await this.askPasswordOnly({ signal, heading: '修改隐私密码前，请先验证当前密码' })
      if (!verify.ok) return { ok: false, reason: verify.reason }
      oldKey = verify.key
    }

    const response = await showDialog(
      {
        mode: 'setup',
        title: firstRun ? '隐私守卫 — 首次使用' : '隐私守卫 — 修改隐私密码',
        heading: firstRun ? '欢迎使用隐私守卫' : '设置新的隐私密码',
        intro: firstRun
          ? 'AI 每次读写个人隐私数据前都需要这个密码。它只保存在本机，用于加密隐私库；请务必牢记，忘记后无法找回隐私库内容。'
          : '请输入新的隐私密码。更换密码不会重新加密隐私库，只会重新封装隐私库密钥。',
        minLength: 8,
        timeoutSec: 120,
        okText: '保存密码',
        cancelText: '取消',
      },
      { signal },
    )
    const verdict = normalizeDecision(response?.decision)
    if (verdict !== 'ok' || !response.password) {
      return { ok: false, reason: verdict === 'timeout' ? '设置密码超时' : '已取消设置密码' }
    }

    const password = String(response.password)
    const salt = randomSalt()
    const kek = await deriveKek(password, salt, DEFAULT_KDF)
    try {
      // 必须先复制一份：换密码时要 wipe 掉旧密钥，不能把同一个 Buffer 也清零
      const dek = oldKey ? Buffer.from(oldKey) : randomKey()
      const wrappedKey = seal(kek, dek)
      const previous = await store.loadSecrets()
      await store.saveSecrets({
        version: 1,
        salt: salt.toString('base64'),
        params: { ...DEFAULT_KDF },
        wrappedKey: wrappedKey.toString('base64'),
        createdAt: previous?.createdAt || new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      })
      wipe(this.vaultKey)
      this.vaultKey = dek
      this.keyExpiresAt = nowMs() + Math.max(1, Number(this.config?.keyCacheMinutes ?? 15)) * 60_000
      // 新建时写一个空库，确保后续读路径一致
      if (!oldKey) await store.writeVault(this.vaultKey, { version: 1, entries: [] })
      return { ok: true }
    } finally {
      wipe(kek)
    }
  }

  /** 只验证密码（不发起具体资源授权），成功后缓存隐私库密钥 */
  async askPasswordOnly({ signal, heading = '请输入隐私密码', sub = '验证后隐私库会在本机内存中解锁一段时间。' } = {}) {
    for (let attempt = 0; attempt < 3; attempt++) {
      const response = await showDialog(
        {
          mode: 'auth',
          title: '隐私守卫 — 身份认证',
          heading,
          sub,
          details: '',
          allowRemember: false,
          timeoutSec: Math.max(10, Number(this.config?.promptTimeoutSeconds ?? 120)),
          okText: '验证',
          cancelText: '取消',
        },
        { signal },
      )
      const verdict = normalizeDecision(response?.decision)
      if (verdict === 'allow') {
        const verification = await this.unlockWithPassword(response.password)
        if (verification.ok) {
          this.touchKey()
          return { ok: true, key: this.vaultKey }
        }
        continue
      }
      if (verdict === 'timeout') return { ok: false, reason: '认证超时' }
      if (verdict === 'unavailable') return { ok: false, reason: `无法弹出认证窗口：${response?.error || '未知原因'}` }
      return { ok: false, reason: '已取消' }
    }
    return { ok: false, reason: '密码错误' }
  }

  /* ---------------------------------------------------------------- */
  /* 自动收集（加密入库）                                               */
  /* ---------------------------------------------------------------- */

  async collect({ withValues = false, signal } = {}) {
    if (this.collecting) return { ok: false, reason: '正在收集' }
    if (this.disposed) return { ok: false, reason: '插件已卸载' }
    await this.reloadConfig()
    if (!this.isEnabled() || this.config.autoCollect === false) return { ok: false, reason: '自动收集已关闭' }
    // 未设置隐私密码前不扫描个人目录：先让用户明确启用，再做任何读取
    if (!(await this.hasSecrets())) return { ok: false, reason: '尚未设置隐私密码，暂不自动收集' }
    this.collecting = true
    try {
      const roots = (Array.isArray(this.config.collectRoots) ? this.config.collectRoots : [])
        .map((value) => String(value).trim())
        .filter(Boolean)
      if (roots.length === 0) return { ok: true, scanned: 0, files: 0, findings: 0 }
      const maxFiles = Math.max(1, Number(this.config.collectMaxFiles ?? 400))
      const maxBytes = Math.max(16 * 1024, Number(this.config.collectMaxBytes ?? 512 * 1024))
      const files = []
      for (const root of roots) {
        await walkFiles(root, { maxFiles, maxBytes, files, signal })
        if (files.length >= maxFiles) break
      }

      const index = await store.loadIndex()
      if (!index.sources || typeof index.sources !== 'object') index.sources = {}
      let findingCount = 0
      let scanned = 0
      const collected = []
      for (const file of files) {
        if (signal?.aborted) break
        let text
        try {
          const info = await stat(file)
          if (info.size > maxBytes) continue
          text = await readFile(file, 'utf8')
        } catch {
          continue
        }
        if (text.includes('\u0000')) continue
        scanned += 1
        const scan = detectSensitive(text, { extraPatterns: this.config.extraPatterns })
        if (scan.findings.length === 0) {
          delete index.sources[file]
          continue
        }
        findingCount += scan.findings.length
        index.sources[file] = {
          types: scan.byType,
          updatedAt: new Date().toISOString(),
        }
        if (withValues && this.isUnlocked()) {
          for (const finding of scan.findings) collected.push({ finding, source: file })
        }
      }
      // totals 按当前 sources 重算（而不是在旧值上累加），否则每轮扫描都会重复计数
      const totals = {}
      for (const entry of Object.values(index.sources)) {
        for (const [type, count] of Object.entries(entry?.types || {})) {
          totals[type] = (totals[type] || 0) + Number(count || 0)
        }
      }
      index.totals = totals
      index.updatedAt = new Date().toISOString()
      await store.saveIndex(index)

      if (withValues && this.isUnlocked() && collected.length > 0) {
        await this.enqueueVaultWrite(async () => {
          const vault = await store.readVault(this.vaultKey)
          const byId = new Map(vault.entries.map((entry) => [entry.id, entry]))
          for (const item of collected) {
            const id = `${item.finding.type}:${sha256Short(item.finding.value)}`
            const existing = byId.get(id)
            const timestamp = new Date().toISOString()
            if (existing) {
              existing.lastSeen = timestamp
              existing.count = Number(existing.count || 1) + 1
              if (!existing.source) existing.source = item.source
            } else {
              byId.set(id, {
                id,
                type: item.finding.type,
                label: item.finding.label,
                value: item.finding.value,
                source: item.source,
                count: 1,
                firstSeen: timestamp,
                lastSeen: timestamp,
              })
            }
          }
          await store.writeVault(this.vaultKey, { version: 1, entries: [...byId.values()] })
        })
      }

      this.lastCollectAt = nowMs()
      return { ok: true, scanned, files: files.length, findings: findingCount, withValues }
    } finally {
      this.collecting = false
    }
  }

  enqueueVaultWrite(task) {
    const run = this.vaultChain.then(task, task)
    this.vaultChain = run.then(
      () => undefined,
      () => undefined,
    )
    return run
  }

  /* ---------------------------------------------------------------- */
  /* 命令                                                              */
  /* ---------------------------------------------------------------- */

  async runCommand(invocation) {
    const raw = String(invocation?.rawInput ?? '').trim()
    const cleaned = raw.replace(/^\/?privacy\s*/i, '').trim()
    const [verbRaw, ...restParts] = cleaned.split(/\s+/)
    const verb = (verbRaw || 'status').toLowerCase()
    const rest = restParts.join(' ').trim()
    const signal = invocation?.signal
    try {
      switch (verb) {
        case 'status':
        case '':
          return textResult(await this.buildStatus())
        case 'setup':
        case 'init':
          return this.commandSetup({ signal })
        case 'lock':
          this.lock('command')
          return textResult('🔒 隐私守卫已锁定：内存中的隐私库密钥与已发放的授权已清除。')
        case 'unlock':
          return this.commandUnlock({ signal })
        case 'scan':
          return this.commandScan({ signal })
        case 'vault':
          return this.commandVault({ signal })
        case 'paths':
          return textResult(this.buildPathsText())
        case 'addpath':
          return this.commandAddPath(rest)
        case 'rmpath':
          return this.commandRemovePath(rest)
        case 'on':
        case 'off':
          return this.commandToggle(verb === 'on')
        case 'strict':
          return this.commandStrict(rest)
        case 'audit':
          return this.commandAudit(rest)
        case 'test':
          return this.commandTest()
        default:
          return textResult(`未知子命令「${verb}」。可用：status / setup / lock / unlock / scan / vault / paths / addpath <路径> / rmpath <路径> / on / off / strict on|off / audit [n] / test`)
      }
    } catch (error) {
      return { kind: 'error', text: `隐私守卫执行失败：${error?.message || error}` }
    }
  }

  async buildStatus() {
    const config = await this.reloadConfig()
    const secrets = await store.loadSecrets()
    const index = await store.loadIndex()
    const stats = await store.auditStats()
    const lines = [
      `🛡️  隐私守卫 v${PRIVACY_GUARD_VERSION}`,
      `状态：${config.enabled === false ? '已停用' : '已启用'}${secrets ? '｜已初始化密码' : '｜尚未设置密码'}`,
      `隐私库：${this.isUnlocked() ? `已解锁（剩余约 ${formatDuration(this.keyExpiresAt - nowMs())}）` : '已锁定'}`,
      `受保护路径：${this.compiledRoots.length} 个`,
      ...this.compiledRoots.slice(0, 8).map((root) => `  • ${root.expanded}`),
      this.compiledRoots.length > 8 ? `  … 其余 ${this.compiledRoots.length - 8} 个` : '',
      `自动收集：${config.autoCollect === false ? '关闭' : `开启（每 ${config.collectIntervalMinutes} 分钟）`}`,
      `敏感元数据：${Object.entries(index.totals || {}).map(([k, v]) => `${k}×${v}`).join('、') || '暂无'}`,
      `近 24 小时：授权 ${stats.allowed} 次｜拒绝 ${stats.denied} 次`,
      `数据目录：${store.DATA_DIR}`,
      '',
      '命令：/privacy setup | unlock | lock | scan | vault | paths | addpath <路径> | rmpath <路径> | on | off | strict on|off | audit [n] | test',
    ]
    return lines.filter(Boolean).join('\n')
  }

  buildPathsText() {
    if (this.compiledRoots.length === 0) {
      return '当前没有受保护路径。用 /privacy addpath <路径> 添加，例如 /privacy addpath ~/Desktop/个人'
    }
    return ['受保护路径：', ...this.compiledRoots.map((root) => `  • ${root.expanded}`)].join('\n')
  }

  async commandSetup({ signal }) {
    const hadSecrets = await this.hasSecrets()
    const result = await this.runSetup({ signal, firstRun: !hadSecrets })
    if (!result.ok) return { kind: 'error', text: `设置密码失败：${result.reason}` }
    await store.appendAudit({ kind: 'setup', decision: 'allow', reason: hadSecrets ? 'change-password' : 'create' })
    // 顺手做一次带值的收集（此刻密钥在内存中）
    this.collect({ withValues: true }).catch(() => {})
    return textResult(
      `✅ 隐私密码已${hadSecrets ? '更新' : '设置'}。\n现在 AI 读写受保护路径时会弹出系统认证窗口；认证通过且你点「允许本次」才会放行。\n建议：立刻运行 /privacy scan 立即收集一次敏感信息。`,
    )
  }

  async commandUnlock({ signal }) {
    if (this.isUnlocked()) return textResult('隐私库当前已解锁。')
    const result = await this.askPasswordOnly({ signal })
    if (!result.ok) return { kind: 'error', text: `解锁失败：${result.reason}` }
    this.collect({ withValues: true }).catch(() => {})
    return textResult(`🔓 隐私库已解锁（${formatDuration(this.keyExpiresAt - nowMs())} 内有效）。`)
  }

  async commandScan({ signal }) {
    if (!this.isUnlocked()) {
      const unlocked = await this.askPasswordOnly({ signal })
      if (!unlocked.ok) return { kind: 'error', text: `需要先解锁隐私库：${unlocked.reason}` }
    }
    const result = await this.collect({ withValues: true, signal })
    if (!result.ok) return { kind: 'error', text: `收集失败：${result.reason}` }
    return textResult(
      `✅ 扫描完成：检查 ${result.scanned}/${result.files} 个文件，发现 ${result.findings} 处敏感信息（已加密写入本机隐私库）。`,
    )
  }

  async commandVault({ signal }) {
    if (!this.isUnlocked()) {
      const unlocked = await this.askPasswordOnly({ signal })
      if (!unlocked.ok) return { kind: 'error', text: `需要先解锁隐私库：${unlocked.reason}` }
    }
    const vault = await store.readVault(this.vaultKey)
    if (vault.entries.length === 0) return textResult('隐私库为空。运行 /privacy scan 收集敏感信息。')
    const byType = new Map()
    for (const entry of vault.entries) {
      const key = entry.label || entry.type
      const stat = byType.get(key) || { count: 0, sources: new Set() }
      stat.count += 1
      if (entry.source) stat.sources.add(entry.source)
      byType.set(key, stat)
    }
    const lines = [`🔐 隐私库（已加密，仅本机）：共 ${vault.entries.length} 条`]
    for (const [label, stat] of byType) lines.push(`  • ${label}：${stat.count} 条，来自 ${stat.sources.size} 个文件`)
    lines.push('（为避免泄露，此处不显示具体值；如需删除请手动清理数据目录中的 vault.enc）')
    return textResult(lines.join('\n'))
  }

  async commandAddPath(input) {
    const target = input.trim()
    if (!target) return { kind: 'error', text: '用法：/privacy addpath <路径>' }
    const expanded = toAbsolute(target, getHome())
    const config = await this.reloadConfig()
    const paths = [...new Set([...(config.protectedPaths || []), expanded])]
    await store.saveConfig({ protectedPaths: paths })
    await this.reloadConfig()
    return textResult(`已加入受保护路径：${expanded}`)
  }

  async commandRemovePath(input) {
    const compiled = compileProtectedRoot(toAbsolute(input.trim(), getHome()))
    if (!compiled) return { kind: 'error', text: '用法：/privacy rmpath <路径>' }
    const target = compiled.normalized
    const config = await this.reloadConfig()
    const paths = (config.protectedPaths || []).filter((value) => {
      const candidate = compileProtectedRoot(value)
      return !candidate || candidate.normalized !== target
    })
    await store.saveConfig({ protectedPaths: paths })
    await this.reloadConfig()
    return textResult(`已移除受保护路径：${input.trim()}`)
  }

  async commandToggle(enabled) {
    await store.saveConfig({ enabled })
    await this.reloadConfig()
    if (!enabled) this.lock('disabled')
    return textResult(enabled ? '🛡️ 隐私守卫已启用。' : '⏸️ 隐私守卫已停用（AI 将不再被拦截）。')
  }

  async commandStrict(input) {
    const value = String(input || '').trim().toLowerCase()
    const enable = value === 'on' || value === '1' || value === 'true' || value === ''
    await store.saveConfig({ strictScan: enable })
    await this.reloadConfig()
    return textResult(enable ? '严格模式：任何敏感信息命中都会要求认证。' : '普通模式：仅高敏感信息（证件/银行卡/密码等）会强制认证。')
  }

  async commandAudit(input) {
    const limit = Math.min(100, Math.max(1, Number.parseInt(input, 10) || 15))
    const entries = await store.readAudit(limit)
    if (entries.length === 0) return textResult('暂无审计记录。')
    const lines = [`最近 ${entries.length} 条审计：`]
    for (const entry of entries) {
      const time = String(entry.ts || '').replace('T', ' ').slice(0, 19)
      const verdict = entry.decision === 'allow' ? '✅' : entry.decision === 'deny' ? '⛔' : '•'
      const detail = [
        entry.tool || entry.kind,
        entry.reason ? `(${entry.reason})` : '',
        Array.isArray(entry.paths) && entry.paths.length ? entry.paths[0] : '',
      ].filter(Boolean).join(' ')
      lines.push(`${verdict} ${time}  ${detail}`)
    }
    return textResult(lines.join('\n'))
  }

  async commandTest() {
    const lines = [`🧪 隐私守卫自检 v${PRIVACY_GUARD_VERSION}`]
    try {
      const salt = randomSalt()
      const key = randomKey()
      const blob = seal(key, 'hello 隐私')
      const plain = openSealed(key, blob).toString('utf8')
      lines.push(plain === 'hello 隐私' ? '✅ 加密/解密往返正常（AES-256-GCM）' : '❌ 加密自检失败')
    } catch (error) {
      lines.push(`❌ 加密自检异常：${error?.message || error}`)
    }
    try {
      const sample = '姓名：张三 手机：13800138000 身份证：11010519491231002X'
      const scan = detectSensitive(sample)
      lines.push(scan.findings.length >= 3 ? `✅ 检测器正常：${describeFindings(scan.findings)}` : `❌ 检测器异常：${describeFindings(scan.findings)}`)
    } catch (error) {
      lines.push(`❌ 检测器异常：${error?.message || error}`)
    }
    try {
      const probe = await probeDialog()
      lines.push(probe.okExe ? `✅ PowerShell：${probe.exe}` : `❌ 找不到 PowerShell：${probe.exe}`)
      lines.push(probe.okScript ? '✅ 认证对话框脚本可读' : '❌ 认证对话框脚本不可读')
    } catch (error) {
      lines.push(`❌ 对话框自检异常：${error?.message || error}`)
    }
    try {
      const secrets = await store.loadSecrets()
      lines.push(secrets ? '✅ 隐私密码已设置' : '⚠️ 尚未设置隐私密码（运行 /privacy setup）')
      const index = await store.loadIndex()
      lines.push(`✅ 元数据索引：${Object.keys(index.sources || {}).length} 个来源文件`)
    } catch (error) {
      lines.push(`❌ 存储自检异常：${error?.message || error}`)
    }
    return textResult(lines.join('\n'))
  }
}

/* ------------------------------------------------------------------ */
/* 辅助函数                                                            */
/* ------------------------------------------------------------------ */

function classifyOperation(toolName) {
  const name = String(toolName || '').toLowerCase()
  if (/(^|_)(write|edit|patch|create|append|replace|save|upload|move|copy|rename)/.test(name)) return 'write'
  if (/(^|_)(delete|remove|rm|trash)/.test(name)) return 'delete'
  if (/(read|cat|view|open|download|export|show|get)/.test(name)) return 'read'
  if (/(bash|pwsh|powershell|shell|terminal|exec|command|wsl|run_code|script)/.test(name)) return 'shell'
  if (/(glob|grep|search|find|list|ls|dir)/.test(name)) return 'list'
  return 'other'
}

function isSearchOrWebTool(toolName) {
  return /(web|search|fetch|browser|http)/i.test(String(toolName || ''))
}

function extractResultText(result) {
  if (!result) return ''
  const blocks = Array.isArray(result.content) ? result.content : []
  let out = ''
  for (const block of blocks) {
    if (!block) continue
    if (block.type === 'text' && typeof block.text === 'string') out += block.text + '\n'
  }
  if (!out && typeof result.value === 'string') out = result.value
  return out.length > 1024 * 1024 ? out.slice(0, 1024 * 1024) : out
}

function summarizeMasked(findings) {
  const seen = new Set()
  const parts = []
  for (const finding of findings) {
    if (parts.length >= 4) break
    const text = `${finding.label} ${finding.masked}`
    if (seen.has(text)) continue
    seen.add(text)
    parts.push(text)
  }
  return parts.join('；')
}

function buildDialogDetails({ kind, op, tool, paths, roots, findings }) {
  const lines = []
  if (kind === 'path') {
    const opText = { read: '读取', write: '修改', delete: '删除', shell: '通过命令行访问', list: '列出', other: '访问' }[op] || '访问'
    lines.push(`操作：${opText}`)
    lines.push(`工具：${tool}`)
    if (paths.length > 0) {
      lines.push('目标路径：')
      for (const path of paths.slice(0, 6)) lines.push(`  ${path}`)
      if (paths.length > 6) lines.push(`  … 其余 ${paths.length - 6} 个`)
    }
    if (roots.length > 0) {
      lines.push('命中受保护目录：')
      for (const root of roots.slice(0, 4)) lines.push(`  ${root.expanded}`)
    }
  } else {
    lines.push(`工具：${tool}`)
    lines.push(`检测到：${describeFindings(findings)}`)
    if (paths.length > 0) lines.push(`来源：${paths[0]}`)
    const masked = summarizeMasked(findings)
    if (masked) lines.push('脱敏示例：'), lines.push(`  ${masked}`)
    lines.push('')
    lines.push('允许后，本次工具结果中的这些信息会原样交给 AI 处理；拒绝则整段结果被阻断。')
  }
  lines.push('')
  lines.push('密码只在本机校验，不会出现在对话记录或模型上下文中。')
  return lines.join('\r\n')
}

function textResult(text) {
  return { kind: 'success', text }
}

function denyDecision(reason, code) {
  return { kind: 'deny', reason, info: { name: 'PrivacyGuard', code } }
}

async function walkFiles(root, { maxFiles, maxBytes, files, signal, depth = 0 } = {}) {
  if (!root || files.length >= maxFiles || signal?.aborted) return
  let entries
  try {
    entries = await readdir(root, { withFileTypes: true })
  } catch {
    return
  }
  for (const entry of entries) {
    if (files.length >= maxFiles || signal?.aborted) return
    const full = join(root, entry.name)
    if (entry.isDirectory()) {
      if (depth >= 4) continue
      if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'privacy-guard') continue
      if (normalizeForCompare(full).startsWith(normalizeForCompare(store.DATA_DIR))) continue
      await walkFiles(full, { maxFiles, maxBytes, files, signal, depth: depth + 1 })
      continue
    }
    if (!entry.isFile()) continue
    if (!TEXT_EXTENSIONS.has(extnameLower(entry.name))) continue
    try {
      const info = await stat(full)
      if (info.size > maxBytes || info.size === 0) continue
    } catch {
      continue
    }
    files.push(full)
  }
}

const TEXT_EXTENSIONS = new Set([
  '.txt', '.md', '.markdown', '.csv', '.tsv', '.json', '.jsonl', '.log', '.ini', '.cfg', '.conf',
  '.yml', '.yaml', '.toml', '.xml', '.html', '.htm', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.py', '.java', '.c', '.h', '.cpp', '.cs', '.go', '.rs', '.sh', '.bat', '.ps1', '.sql', '.env',
])

function extnameLower(fileName) {
  const name = String(fileName || '')
  const idx = name.lastIndexOf('.')
  return idx >= 0 ? name.slice(idx).toLowerCase() : ''
}

function startCollector(guard) {
  const run = () => {
    if (guard.disposed) return
    guard.collect({ withValues: guard.isUnlocked() }).catch((error) => warn('自动收集失败', error))
  }
  const intervalMinutes = Math.max(5, Number(guard.config?.collectIntervalMinutes ?? 30))
  const timer = setInterval(run, intervalMinutes * 60_000)
  if (typeof timer.unref === 'function') timer.unref()
  const kickoff = setTimeout(run, 20_000)
  if (typeof kickoff.unref === 'function') kickoff.unref()
  return () => {
    clearInterval(timer)
    clearTimeout(kickoff)
  }
}

/* ------------------------------------------------------------------ */
/* 插件入口                                                            */
/* ------------------------------------------------------------------ */

export function apply(ctx, pluginConfig = {}) {
  const guard = new PrivacyGuard(ctx, pluginConfig)
  guard.start()

  ctx.on('tools/pre-execute', (exec, next) => guard.beforeTool(exec, next), { prepend: true })
  ctx.on('tools/post-execute', (exec, result, next) => guard.afterTool(exec, result, next), { prepend: true })

  const commands = ctx.get('commands')
  if (commands && typeof commands.register === 'function') {
    commands.register({
      name: 'privacy',
      description: '隐私守卫：查看状态、设置隐私密码、锁定/解锁、收集敏感信息、审计',
      input: {
        hint: 'status | setup | unlock | lock | scan | vault | paths | addpath <路径> | rmpath <路径> | on | off | strict on|off | audit [n] | test',
      },
      handler: (invocation) => guard.runCommand(invocation),
    })
  } else {
    warn('commands 服务不可用，/privacy 命令未注册')
  }

  ctx.effect(() => () => guard.dispose())
  return guard
}

export default {
  name,
  inject,
  apply,
}

export { PrivacyGuard }
