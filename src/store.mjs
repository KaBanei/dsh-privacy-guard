/**
 * dsh-privacy-guard — 本地存储层
 *
 * 目录：$DSH_HOME/privacy-guard/（默认 ~/.dsh/privacy-guard/）
 *   config.json   非敏感配置（受保护路径、开关、超时……）
 *   secrets.json  密码盐、scrypt 参数、被密码封装的隐私库密钥（0600）
 *   vault.enc     隐私库密文（只有解锁后才可读写）
 *   index.json    敏感信息「元数据」索引（类型/计数/来源，不含原始值）
 *   audit.log     审计日志（JSONL，追加式，自动轮转）
 *   state.json    运行期状态（失败次数、锁定截止时间）
 */
import { mkdir, readFile, writeFile, rename, stat, appendFile, readdir, rm } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { open, seal } from './crypto.mjs'

export const DSH_HOME = process.env.DSH_HOME || join(homedir(), '.dsh')
export const DATA_DIR = join(DSH_HOME, 'privacy-guard')
export const CONFIG_PATH = join(DATA_DIR, 'config.json')
export const SECRETS_PATH = join(DATA_DIR, 'secrets.json')
export const VAULT_PATH = join(DATA_DIR, 'vault.enc')
export const INDEX_PATH = join(DATA_DIR, 'index.json')
export const AUDIT_PATH = join(DATA_DIR, 'audit.log')
export const STATE_PATH = join(DATA_DIR, 'state.json')

const AUDIT_MAX_BYTES = 2 * 1024 * 1024

/** 常见个人隐私目录候选（存在才纳入默认值） */
export function candidateProtectedPaths(home = process.env.USERPROFILE || homedir()) {
  const bases = [
    ['Desktop', ['个人', '隐私', '私人', '证件', '资料']],
    ['Documents', ['个人', '隐私', '私人', '证件', '资料']],
    ['Pictures', ['个人', '隐私', '私人', '证件', '资料']],
    ['Downloads', []],
  ]
  const out = []
  const seen = new Set()
  for (const [folder, names] of bases) {
    for (const name of names) {
      const full = join(home, folder, name)
      if (existsSync(full) && !seen.has(full)) {
        seen.add(full)
        out.push(full)
      }
    }
  }
  return out
}

export function defaultConfig() {
  return {
    version: 1,
    enabled: true,
    protectedPaths: candidateProtectedPaths(),
    autoCollect: true,
    collectRoots: candidateProtectedPaths(),
    collectIntervalMinutes: 30,
    collectMaxFiles: 400,
    collectMaxBytes: 512 * 1024,
    grantTtlSeconds: 600,
    keyCacheMinutes: 15,
    promptTimeoutSeconds: 120,
    maxPromptsPerMinute: 6,
    scanWebResults: false,
    strictScan: false,
    extraPatterns: [],
    redactDeniedPreview: true,
  }
}

export async function ensureDataDir() {
  await mkdir(DATA_DIR, { recursive: true })
}

async function readJson(filePath, fallback) {
  try {
    const raw = await readFile(filePath, 'utf8')
    return JSON.parse(raw)
  } catch {
    return fallback
  }
}

/** 原子写：临时文件 + rename，避免进程被杀留下截断文件 */
async function writeFileAtomic(filePath, text, mode) {
  const tmp = `${filePath}.tmp-${process.pid}-${Date.now().toString(36)}`
  await writeFile(tmp, text, typeof mode === 'number' ? { encoding: 'utf8', mode } : 'utf8')
  await rename(tmp, filePath)
}

/* ------------------------------------------------------------------ */
/* 配置                                                                 */
/* ------------------------------------------------------------------ */

let cachedConfig = null
let cachedConfigSignature = ''

function mergeConfig(patch) {
  const base = defaultConfig()
  const merged = { ...base, ...(patch || {}) }
  merged.version = 1
  // 数组字段做空值兜底，避免 undefined 进入检测循环
  for (const key of ['protectedPaths', 'collectRoots', 'extraPatterns']) {
    if (!Array.isArray(merged[key])) merged[key] = base[key]
  }
  return merged
}

export async function loadConfig({ force = false } = {}) {
  await ensureDataDir()
  if (!force) {
    try {
      const info = await stat(CONFIG_PATH)
      const signature = `${info.mtimeMs}:${info.size}`
      if (cachedConfig && signature === cachedConfigSignature) return cachedConfig
    } catch {
      // 文件不存在：继续走下面
    }
  }
  const stored = await readJson(CONFIG_PATH, {})
  cachedConfig = mergeConfig(stored)
  try {
    const info = await stat(CONFIG_PATH)
    cachedConfigSignature = `${info.mtimeMs}:${info.size}`
  } catch {
    cachedConfigSignature = ''
  }
  // 首次运行把默认配置落盘，让用户能看到/修改
  if (!existsSync(CONFIG_PATH)) {
    await writeFileAtomic(CONFIG_PATH, JSON.stringify(cachedConfig, null, 2))
    try {
      const info = await stat(CONFIG_PATH)
      cachedConfigSignature = `${info.mtimeMs}:${info.size}`
    } catch {
      /* ignore */
    }
  }
  return cachedConfig
}

export async function saveConfig(patch) {
  await ensureDataDir()
  const next = mergeConfig({ ...(cachedConfig || (await loadConfig())), ...(patch || {}) })
  await writeFileAtomic(CONFIG_PATH, JSON.stringify(next, null, 2))
  cachedConfig = next
  try {
    const info = await stat(CONFIG_PATH)
    cachedConfigSignature = `${info.mtimeMs}:${info.size}`
  } catch {
    cachedConfigSignature = ''
  }
  return next
}

/* ------------------------------------------------------------------ */
/* 密钥材料                                                              */
/* ------------------------------------------------------------------ */

export async function loadSecrets() {
  return readJson(SECRETS_PATH, null)
}

export async function saveSecrets(secrets) {
  await ensureDataDir()
  await writeFileAtomic(SECRETS_PATH, JSON.stringify(secrets, null, 2), 0o600)
}

export async function loadState() {
  return readJson(STATE_PATH, { failedAttempts: 0, lockedUntil: 0 })
}

export async function saveState(state) {
  await ensureDataDir()
  await writeFileAtomic(STATE_PATH, JSON.stringify(state, null, 2), 0o600)
}

/* ------------------------------------------------------------------ */
/* 隐私库                                                                */
/* ------------------------------------------------------------------ */

export async function readVault(key) {
  if (!existsSync(VAULT_PATH)) return { version: 1, entries: [] }
  const blob = await readFile(VAULT_PATH)
  const plain = open(key, blob)
  const parsed = JSON.parse(plain.toString('utf8'))
  if (!parsed || !Array.isArray(parsed.entries)) return { version: 1, entries: [] }
  return parsed
}

export async function writeVault(key, vault) {
  await ensureDataDir()
  const payload = JSON.stringify({ version: 1, entries: Array.isArray(vault?.entries) ? vault.entries : [] })
  const blob = seal(key, payload)
  await writeFileAtomic(VAULT_PATH, blob)
}

/* ------------------------------------------------------------------ */
/* 元数据索引（不含原始值）                                                */
/* ------------------------------------------------------------------ */

export async function loadIndex() {
  return readJson(INDEX_PATH, { version: 1, totals: {}, sources: {} })
}

export async function saveIndex(index) {
  await ensureDataDir()
  await writeFileAtomic(INDEX_PATH, JSON.stringify(index, null, 2))
}

/* ------------------------------------------------------------------ */
/* 审计                                                                  */
/* ------------------------------------------------------------------ */

export async function appendAudit(entry) {
  try {
    await ensureDataDir()
    try {
      const info = await stat(AUDIT_PATH)
      if (info.size > AUDIT_MAX_BYTES) await rm(`${AUDIT_PATH}.1`, { force: true })
      if (info.size > AUDIT_MAX_BYTES) await rename(AUDIT_PATH, `${AUDIT_PATH}.1`)
    } catch {
      /* 文件不存在 */
    }
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n'
    await appendFile(AUDIT_PATH, line, 'utf8')
  } catch {
    /* 审计失败不能影响主流程 */
  }
}

export async function readAudit(limit = 20) {
  try {
    const raw = await readFile(AUDIT_PATH, 'utf8')
    const lines = raw.split('\n').filter(Boolean)
    return lines.slice(-limit).map((line) => {
      try {
        return JSON.parse(line)
      } catch {
        return null
      }
    }).filter(Boolean)
  } catch {
    return []
  }
}

export async function auditStats(sinceMs = 24 * 60 * 60 * 1000) {
  const cutoff = Date.now() - sinceMs
  const entries = await readAudit(4000)
  let allowed = 0
  let denied = 0
  for (const entry of entries) {
    const t = Date.parse(entry.ts)
    if (!Number.isFinite(t) || t < cutoff) continue
    // 只统计真正的访问判定，setup/lock 这类状态变更不算「授权」
    if (entry.kind !== 'path' && entry.kind !== 'content' && entry.kind !== 'auth') continue
    if (entry.decision === 'allow') allowed++
    else if (entry.decision === 'deny') denied++
  }
  return { allowed, denied, total: entries.length }
}

export async function listDataFiles() {
  try {
    return (await readdir(DATA_DIR)).sort()
  } catch {
    return []
  }
}
