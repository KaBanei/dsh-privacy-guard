/**
 * dsh-privacy-guard — 原生认证对话框驱动
 *
 * 为什么用系统原生窗口而不是网页弹窗：
 *   1. 密码不会经过会话日志 / 模型上下文，也不会被页面脚本截获；
 *   2. 认证提示由独立的系统窗口呈现，网页内容无法伪造；
 *   3. 不依赖 Web GUI 是否打开（CLI 会话同样可用）。
 */
import { spawn } from 'node:child_process'
import { readFile, writeFile, unlink, mkdir, access } from 'node:fs/promises'
import { constants as fsConstants } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'

const HERE = dirname(fileURLToPath(import.meta.url))
const ASSETS_DIR = join(HERE, '..', 'assets')
const SCRIPT_PATH = join(ASSETS_DIR, 'dialog.ps1')

/** 带 BOM 的脚本副本缓存：PowerShell 5.1 只有看到 BOM 才会按 UTF-8 解析中文 */
let bomScriptPath = null
let bomScriptSignature = ''

export function powershellPath() {
  const root = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows'
  return join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
}

async function exists(filePath) {
  try {
    await access(filePath, fsConstants.F_OK)
    return true
  } catch {
    return false
  }
}

async function ensureBomScript() {
  if (bomScriptPath && (await exists(bomScriptPath))) return bomScriptPath
  const raw = await readFile(SCRIPT_PATH)
  const hasBom = raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf
  const body = hasBom ? raw : Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), raw])
  const target = join(process.env.TEMP || process.env.TMP || HERE, `dsh-privacy-guard-dialog-${process.pid}.ps1`)
  await writeFile(target, body)
  bomScriptPath = target
  bomScriptSignature = `${raw.length}`
  return target
}

function runProcess(exe, args, { timeoutMs, signal }) {
  return new Promise((resolve) => {
    let child
    try {
      // 注意：不能传 windowsHide: true。它会让子进程的第一次 ShowWindow 使用 SW_HIDE，
      // 结果 WinForms 对话框被系统隐藏（进程活着但窗口不可见）。
      // 控制台窗口交给 powershell 的 -WindowStyle Hidden 自己隐藏。
      child = spawn(exe, args, { windowsHide: false, stdio: ['ignore', 'ignore', 'pipe'] })
    } catch (error) {
      resolve({ error })
      return
    }
    let settled = false
    let stderr = ''
    let timer = null
    let onAbort = null
    const cleanup = () => {
      if (timer) clearTimeout(timer)
      if (onAbort && signal) signal.removeEventListener('abort', onAbort)
    }
    const finish = (value) => {
      if (settled) return
      settled = true
      cleanup()
      resolve(value)
    }
    const kill = () => {
      try {
        child.kill()
      } catch {
        /* 已退出 */
      }
    }
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        kill()
        finish({ timedOut: true, stderr })
      }, timeoutMs)
    }
    if (signal) {
      onAbort = () => {
        kill()
        finish({ aborted: true, stderr })
      }
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    }
    child.stderr?.on('data', (chunk) => {
      if (stderr.length < 8192) stderr += String(chunk)
    })
    child.on('error', (error) => finish({ error, stderr }))
    child.on('exit', (code) => finish({ code, stderr }))
  })
}

async function readResponse(responsePath, attempts = 20) {
  for (let i = 0; i < attempts; i++) {
    try {
      const raw = await readFile(responsePath, 'utf8')
      if (raw && raw.trim()) return JSON.parse(raw)
    } catch {
      /* 还没写出来 */
    }
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  return null
}

/**
 * 显示原生对话框。
 * @param {object} spec 见 assets/dialog.ps1 顶部说明
 * @param {{ timeoutMs?: number, signal?: AbortSignal }} [options]
 * @returns {Promise<{decision: string, password?: string, remember?: boolean, error?: string, timedOut?: boolean}>}
 */
export async function showDialog(spec, options = {}) {
  const timeoutSec = Number(spec.timeoutSec) > 0 ? Number(spec.timeoutSec) : 0
  const hardTimeoutMs = options.timeoutMs ?? (timeoutSec > 0 ? timeoutSec * 1000 + 20000 : 0)
  const tempDir = join(process.env.TEMP || process.env.TMP || HERE, 'dsh-privacy-guard')
  await mkdir(tempDir, { recursive: true }).catch(() => {})
  const id = randomBytes(8).toString('hex')
  const requestPath = join(tempDir, `${id}.req.json`)
  const responsePath = join(tempDir, `${id}.res.json`)
  try {
    await writeFile(requestPath, JSON.stringify(spec), 'utf8')
    const script = await ensureBomScript()
    const child = await runProcess(
      powershellPath(),
      [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-WindowStyle',
        'Hidden',
        '-File',
        script,
        '-RequestPath',
        requestPath,
        '-ResponsePath',
        responsePath,
      ],
      { timeoutMs: hardTimeoutMs, signal: options.signal },
    )

    if (child.aborted) return { decision: 'cancelled' }
    if (child.timedOut) return { decision: 'timeout' }
    if (child.error) {
      return { decision: 'unavailable', error: String(child.error?.message || child.error) }
    }
    const response = await readResponse(responsePath)
    if (!response) {
      return {
        decision: child.code === 0 ? 'unavailable' : 'unavailable',
        error: child.stderr ? String(child.stderr).slice(0, 500) : '对话框没有返回结果',
      }
    }
    return response
  } finally {
    await unlink(requestPath).catch(() => {})
    await unlink(responsePath).catch(() => {})
  }
}

/** 环境自检：PowerShell 是否存在、对话框脚本是否可读 */
export async function probeDialog() {
  const exe = powershellPath()
  const okExe = await exists(exe)
  let okScript = false
  try {
    await ensureBomScript()
    okScript = true
  } catch {
    okScript = false
  }
  return { exe, okExe, okScript }
}
