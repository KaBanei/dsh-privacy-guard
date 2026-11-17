/**
 * dsh-privacy-guard — 路径识别与匹配
 *
 * 负责三件事：
 *   1. 把工具参数里「像路径的字符串」找出来（含 shell 命令串里的路径片段）；
 *   2. 把相对路径解析成绝对路径；
 *   3. 判断绝对路径是否落在受保护根目录/通配模式内。
 */
import { homedir } from 'node:os'
import { isAbsolute, join, resolve, sep } from 'node:path'

export function getHome() {
  return process.env.USERPROFILE || homedir()
}

export function expandHome(value) {
  const s = String(value ?? '')
  if (!s) return s
  if (s === '~') return getHome()
  if (s.startsWith('~/') || s.startsWith('~\\')) return join(getHome(), s.slice(2))
  return s
}

/** 统一成用于比较的形式：正斜杠、小写、去尾斜杠、合并重复分隔符 */
export function normalizeForCompare(value) {
  let s = String(value ?? '')
  if (!s) return ''
  s = s.replace(/\\/g, '/')
  s = s.replace(/\/{2,}/g, '/')
  if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1)
  return s.toLowerCase()
}

export function basenameAny(value) {
  const s = String(value ?? '').replace(/\\/g, '/').replace(/\/+$/, '')
  const idx = s.lastIndexOf('/')
  return idx >= 0 ? s.slice(idx + 1) : s
}

export function lastSegments(value, count = 2) {
  const parts = String(value ?? '').replace(/\\/g, '/').split('/').filter(Boolean)
  return parts.slice(Math.max(0, parts.length - count)).join('/')
}

export function isAbsoluteAnyPlatform(value) {
  const s = String(value ?? '')
  return s.startsWith('/') || s.startsWith('\\\\') || /^[a-zA-Z]:[\\/]/.test(s)
}

/** 相对路径依次尝试 baseDir；都不存在时返回 baseDir 下的结果 */
export function toAbsolute(value, baseDir) {
  const s = expandHome(String(value ?? '').trim())
  if (!s) return ''
  if (isAbsoluteAnyPlatform(s)) return resolve(s)
  if (baseDir && isAbsoluteAnyPlatform(baseDir)) return resolve(baseDir, s)
  return resolve(s)
}

/* ------------------------------------------------------------------ */
/* 受保护根目录：支持 * 与 ** 两种通配                                     */
/* ------------------------------------------------------------------ */

function globToRegExp(pattern) {
  const normalized = normalizeForCompare(expandHome(pattern))
  let out = '^'
  for (let i = 0; i < normalized.length; i++) {
    const ch = normalized[i]
    if (ch === '*') {
      if (normalized[i + 1] === '*') {
        out += '.*'
        i += 1
      } else {
        out += '[^/]*'
      }
    } else if (ch === '?') {
      out += '[^/]'
    } else if ('\\^$.|+()[]{}'.includes(ch)) {
      out += '\\' + ch
    } else {
      out += ch
    }
  }
  out += '(?:/.*)?$'
  return new RegExp(out)
}

export function compileProtectedRoot(root) {
  const expanded = expandHome(String(root ?? '').trim())
  if (!expanded) return null
  const hasGlob = /[*?]/.test(expanded)
  const normalized = normalizeForCompare(expanded)
  const homeNorm = normalizeForCompare(getHome())
  return {
    raw: String(root).trim(),
    expanded,
    normalized,
    regex: hasGlob ? globToRegExp(expanded) : null,
    basename: basenameAny(expanded),
    tail: normalizeForCompare(lastSegments(expanded, 2)),
    // 家目录相对写法（~/Desktop/个人）只在 shell 命令里出现，需要单独识别
    homeRelative: normalized.startsWith(homeNorm + '/') ? normalized.slice(homeNorm.length + 1) : null,
  }
}

/** 判断绝对路径是否命中受保护根；返回命中的 compileProtectedRoot 或 null */
export function matchProtected(absPath, compiledRoots) {
  if (!absPath || !Array.isArray(compiledRoots)) return null
  const normalized = normalizeForCompare(absPath)
  for (const root of compiledRoots) {
    if (!root) continue
    if (root.regex) {
      if (root.regex.test(normalized)) return root
      continue
    }
    if (normalized === root.normalized || normalized.startsWith(root.normalized + '/')) return root
  }
  return null
}

/**
 * 在 shell 命令文本里找受保护路径的痕迹。
 * 先把常见的家目录写法归一化，再用「完整路径」和「末两段」两种粒度匹配：
 * 完整路径误报最低；末两段（如 desktop/个人）用于 `cd ~/Desktop/个人 && ...`
 * 这类被 shell 变量/引号拆开但仍可识别的写法。
 */
export function matchProtectedInText(text, compiledRoots, home = getHome()) {
  const source = String(text ?? '')
  if (!source || !Array.isArray(compiledRoots)) return []
  const homeNorm = normalizeForCompare(home)
  let normalized = normalizeForCompare(source)
  normalized = normalized
    .replace(/%userprofile%/g, homeNorm)
    .replace(/\$env:userprofile/g, homeNorm)
    .replace(/\$home/g, homeNorm)
    .replace(/\$\{home\}/g, homeNorm)
  const hits = []
  for (const root of compiledRoots) {
    if (!root) continue
    if (normalized.includes(root.normalized)) {
      hits.push(root)
      continue
    }
    // `~/Desktop/个人` 这类家目录相对写法：~ 不会被上面的替换处理，单独匹配
    if (root.homeRelative && normalized.includes(`~/${root.homeRelative}`)) {
      hits.push(root)
      continue
    }
    if (root.tail && root.tail.includes('/') && normalized.includes(root.tail)) {
      hits.push(root)
    }
  }
  return hits
}

/* ------------------------------------------------------------------ */
/* 从工具参数里抽取字符串                                                */
/* ------------------------------------------------------------------ */

const PATH_KEY_HINTS = [
  'path', 'file_path', 'filepath', 'filename', 'file', 'dir', 'directory',
  'cwd', 'target', 'source', 'dest', 'destination', 'root', 'folder',
]
const COMMAND_KEY_HINTS = ['command', 'cmd', 'script', 'args', 'shell', 'input', 'code', 'stdin']

function looksLikePath(value) {
  const s = String(value ?? '')
  if (!s || s.length < 3 || s.length > 2048) return false
  if (/[\r\n\t]/.test(s)) return false
  if (/^(https?:|data:|blob:|mailto:|file:\/\/)/i.test(s)) return false
  return s.includes('/') || s.includes('\\') || /^~/.test(s) || /^[a-zA-Z]:/.test(s)
}

/**
 * 深度受限地遍历参数对象，收集「像路径」的字符串与「命令类」字符串。
 * @returns {{ paths: string[], commands: string[] }}
 */
export function extractTargets(args, options = {}) {
  const maxDepth = Number.isInteger(options.maxDepth) ? options.maxDepth : 4
  const maxStrings = Number.isInteger(options.maxStrings) ? options.maxStrings : 200
  const paths = []
  const commands = []
  const seen = new Set()
  let visited = 0

  const visit = (value, key, depth) => {
    if (visited++ > 500 || depth > maxDepth) return
    if (typeof value === 'string') {
      if (seen.has(value)) return
      seen.add(value)
      const keyLower = String(key ?? '').toLowerCase()
      if (COMMAND_KEY_HINTS.includes(keyLower) && value.length >= 3) {
        commands.push(value)
        return
      }
      if (looksLikePath(value) && paths.length < maxStrings) paths.push(value)
      return
    }
    if (Array.isArray(value)) {
      for (const item of value) visit(item, key, depth + 1)
      return
    }
    if (value && typeof value === 'object') {
      for (const [childKey, childValue] of Object.entries(value)) visit(childValue, childKey, depth + 1)
    }
  }

  visit(args, '', 0)
  return { paths, commands }
}
