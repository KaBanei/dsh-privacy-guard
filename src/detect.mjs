/**
 * dsh-privacy-guard — 敏感信息检测器
 *
 * 纯函数模块：不读写任何文件，方便单独测试。
 * 检测结果统一为 { type, label, severity, index, length, value, masked }。
 *
 * 分级：
 *   high   —— 一旦出现就必须拦截（证件号/银行卡/密码/私钥/API Key）
 *   medium —— 结合上下文（受保护路径、strict 模式）才拦截（手机号/邮箱/姓名/账号）
 */

const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
const ID_CHECK = '10X98765432'

/** 18 位中国居民身份证校验位验证（同时校验出生日期范围） */
export function isValidIdCard(value) {
  const s = String(value || '')
  if (!/^[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]$/.test(s)) return false
  const year = Number(s.slice(6, 10))
  const month = Number(s.slice(10, 12))
  const day = Number(s.slice(12, 14))
  if (year < 1900 || year > 2100) return false
  const date = new Date(Date.UTC(year, month - 1, day))
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return false
  let sum = 0
  for (let i = 0; i < 17; i++) sum += Number(s[i]) * ID_WEIGHTS[i]
  return ID_CHECK[sum % 11] === s[17].toUpperCase()
}

/** Luhn 校验（银行卡/信用卡号） */
export function luhnOk(digits) {
  const s = String(digits || '').replace(/\D/g, '')
  if (s.length < 12 || s.length > 19) return false
  let sum = 0
  let double = false
  for (let i = s.length - 1; i >= 0; i--) {
    let n = Number(s[i])
    if (double) {
      n *= 2
      if (n > 9) n -= 9
    }
    sum += n
    double = !double
  }
  return sum % 10 === 0
}

export function maskValue(type, value) {
  const s = String(value || '')
  const tail = (n) => s.slice(-n)
  switch (type) {
    case 'idcard':
      return s.length > 4 ? `${'*'.repeat(s.length - 4)}${tail(4)}` : '***'
    case 'bankcard': {
      const d = s.replace(/\D/g, '')
      return d.length >= 12 ? `${d.slice(0, 4)} **** **** ${d.slice(-4)}` : '****'
    }
    case 'phone':
      return s.length >= 11 ? `${s.slice(0, 3)}****${tail(4)}` : '***'
    case 'email': {
      const at = s.indexOf('@')
      return at > 0 ? `${s.slice(0, 1)}***${s.slice(at)}` : '***'
    }
    case 'name':
      return s.length > 1 ? `${s.slice(0, 1)}${'*'.repeat(s.length - 1)}` : '*'
    default:
      return '********'
  }
}

/**
 * 检测器定义。
 * - `group`：真正要保护的是第几个捕获组（默认整段匹配）
 * - `pattern` 必须带 g 标志
 * - `validate`：拿到（可选 transform 后的）原始值，返回是否接受
 */
const DETECTORS = [
  {
    type: 'private_key',
    label: '私钥文件内容',
    severity: 'high',
    pattern: /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----/g,
  },
  {
    type: 'api_key',
    label: 'API 密钥 / 访问令牌',
    severity: 'high',
    pattern:
      /\b(?:sk-[A-Za-z0-9_-]{16,}|sk-proj-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})\b/g,
  },
  {
    type: 'idcard',
    label: '身份证号',
    severity: 'high',
    pattern: /(?<![0-9A-Za-z])[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![0-9A-Za-z])/g,
    validate: isValidIdCard,
  },
  {
    type: 'password',
    label: '密码 / 口令',
    severity: 'high',
    // 标签后必须跟分隔符，值不含空白；避免把 "password: 请妥善保管" 这类说明当密码
    pattern: /(?:密\s*码|口令|\bpassword\b|\bpasswd\b|\bpwd\b|\bsecret\b)[^\S\r\n]*[:：=][^\S\r\n]*([^\s,，;；、'"“”]{4,128})/gi,
    group: 1,
  },
  {
    type: 'bankcard',
    label: '银行卡 / 信用卡号',
    severity: 'high',
    pattern: /(?<!\d)(?:\d[ -]?){15,19}(?!\d)/g,
    transform: (s) => s.replace(/[ -]/g, ''),
    validate: (v) => /^\d{16,19}$/.test(v) && luhnOk(v),
  },
  {
    type: 'phone',
    label: '手机号',
    severity: 'medium',
    pattern: /(?<!\d)1[3-9]\d{9}(?!\d)/g,
  },
  {
    type: 'email',
    label: '电子邮箱',
    severity: 'medium',
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g,
  },
  {
    type: 'name',
    label: '姓名',
    severity: 'medium',
    // 只认标签明示的姓名，避免把普通中文词语当人名
    pattern: /(?:姓\s*名|名字|姓\s*氏|联系人|收件人|户名|开户人)[^\S\r\n]*[:：=]?[^\S\r\n]*([\u4e00-\u9fa5·]{2,6})/g,
    group: 1,
  },
  {
    type: 'account',
    label: '账号 / 用户名',
    severity: 'medium',
    pattern: /(?:账\s*号|账\s*户|用户名|\busername\b|\baccount\b|\blogin\b|\buserid\b)[^\S\r\n]*[:：=][^\S\r\n]*([A-Za-z0-9_.@+-]{3,64})/gi,
    group: 1,
  },
]

const SEVERITY_RANK = { high: 2, medium: 1 }

/**
 * 扫描文本。
 * @param {string} text
 * @param {{ extraPatterns?: string[], limit?: number }} [options]
 * @returns {{ findings: Array<object>, byType: Record<string, number>, highest: 'high'|'medium'|null }}
 */
export function detectSensitive(text, options = {}) {
  const input = String(text ?? '')
  const limit = Number.isInteger(options.limit) && options.limit > 0 ? options.limit : 200
  const findings = []
  if (!input) return { findings, byType: {}, highest: null }
  // 超过 1 MiB 的文本只扫描前 1 MiB，避免正则回溯拖垮主线程
  const scoped = input.length > 1024 * 1024 ? input.slice(0, 1024 * 1024) : input

  for (const detector of DETECTORS) {
    detector.pattern.lastIndex = 0
    let match
    let guard = 0
    while ((match = detector.pattern.exec(scoped)) !== null) {
      if (guard++ > 2000) break
      if (match[0] === '') {
        detector.pattern.lastIndex += 1
        continue
      }
      const raw = detector.group ? match[detector.group] : match[0]
      if (raw === undefined || raw === null) continue
      const value = detector.transform ? detector.transform(raw) : raw
      if (!value) continue
      if (detector.validate && !detector.validate(value)) continue
      // 计算真实位置：group 时用 match 里的索引偏移
      let index = match.index
      if (detector.group) {
        const found = match[0].indexOf(raw)
        if (found >= 0) index += found
      }
      findings.push({
        type: detector.type,
        label: detector.label,
        severity: detector.severity,
        index,
        length: String(raw).length,
        value,
        masked: maskValue(detector.type, value),
      })
      if (findings.length > limit * 4) break
    }
    if (findings.length > limit * 4) break
  }

  // 自定义正则：用户追加的规则统一按 high 处理
  for (const source of Array.isArray(options.extraPatterns) ? options.extraPatterns : []) {
    if (typeof source !== 'string' || !source.trim()) continue
    let pattern
    try {
      pattern = new RegExp(source, 'g')
    } catch {
      continue
    }
    let match
    let guard = 0
    while ((match = pattern.exec(scoped)) !== null) {
      if (guard++ > 500) break
      if (match[0] === '') {
        pattern.lastIndex += 1
        continue
      }
      findings.push({
        type: 'custom',
        label: '自定义敏感规则',
        severity: 'high',
        index: match.index,
        length: match[0].length,
        value: match[0],
        masked: maskValue('custom', match[0]),
      })
    }
  }

  // 去重 + 去重叠：按起点排序，同起点/重叠区域保留 severity 更高、长度更长的
  findings.sort((a, b) => a.index - b.index || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.length - a.length)
  const accepted = []
  let cursor = -1
  for (const finding of findings) {
    if (finding.index < cursor) continue
    if (finding.index + finding.length <= finding.index) continue
    accepted.push(finding)
    cursor = finding.index + finding.length
    if (accepted.length >= limit) break
  }

  const byType = {}
  let highest = null
  for (const finding of accepted) {
    byType[finding.type] = (byType[finding.type] || 0) + 1
    if (highest !== 'high' && finding.severity === 'high') highest = 'high'
    if (highest === null) highest = 'medium'
  }
  return { findings: accepted, byType, highest }
}

/** findings → 人类可读摘要，例如 "身份证号 ×1、手机号 ×2" */
export function describeFindings(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return ''
  const counter = new Map()
  for (const finding of findings) {
    const label = finding.label || finding.type
    counter.set(label, (counter.get(label) || 0) + 1)
  }
  return [...counter.entries()].map(([label, n]) => `${label} ×${n}`).join('、')
}

/** 是否包含需要强制拦截的内容（用于结果扫描的默认策略） */
export function hasHighSeverity(findings) {
  return Array.isArray(findings) && findings.some((f) => f.severity === 'high')
}

/** 生成脱敏后的文本（把每条命中替换为掩码） */
export function redactText(text, findings) {
  if (!Array.isArray(findings) || findings.length === 0) return String(text ?? '')
  const sorted = [...findings].sort((a, b) => b.index - a.index)
  let out = String(text ?? '')
  for (const finding of sorted) {
    if (finding.index < 0 || finding.length <= 0) continue
    out = out.slice(0, finding.index) + `[${finding.label}已隐藏]` + out.slice(finding.index + finding.length)
  }
  return out
}
