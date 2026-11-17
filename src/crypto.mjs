/**
 * dsh-privacy-guard — 加密原语
 *
 * 设计：
 *   - 隐私库密钥（DEK）是 32 字节随机数，只在解锁期间存在于进程内存。
 *   - DEK 用「隐私密码」经 scrypt 派生的 KEK 以 AES-256-GCM 封装后落盘（secrets.json）。
 *   - 隐私库文件本体用 DEK 加密（vault.enc），格式 [iv 12][tag 16][ciphertext]。
 *   - 密码错误由 GCM 认证失败判定，不需要单独存密码哈希。
 *
 * 这些决定意味着：即使拿到磁盘上的全部文件，没有密码也无法解密隐私库内容——
 * 这是本插件与「仅用 DPAPI 保护」方案的关键区别（后者同机同用户进程可解）。
 */
import { randomBytes, scrypt as scryptCallback, createCipheriv, createDecipheriv } from 'node:crypto'
import { promisify } from 'node:util'

const scrypt = promisify(scryptCallback)

/** scrypt 参数：约 32 MiB 内存、单次约 100ms（本机实测） */
export const DEFAULT_KDF = Object.freeze({ N: 1 << 15, r: 8, p: 1 })
const MAXMEM = 256 * 1024 * 1024

export const KEY_BYTES = 32
export const IV_BYTES = 12
export const TAG_BYTES = 16

/** 从密码派生 32 字节 KEK。调用方负责尽快清空密码字符串引用。 */
export async function deriveKek(password, salt, params = DEFAULT_KDF) {
  if (!Buffer.isBuffer(salt) || salt.length < 16) throw new Error('salt 无效')
  const { N, r, p } = { ...DEFAULT_KDF, ...(params || {}) }
  const key = await scrypt(Buffer.from(String(password), 'utf8'), salt, KEY_BYTES, { N, r, p, maxmem: MAXMEM })
  return Buffer.from(key)
}

/** AES-256-GCM 封装：返回 [iv|tag|ciphertext] */
export function seal(key, plaintext) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) throw new Error('密钥无效')
  const iv = randomBytes(IV_BYTES)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const data = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8')
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, tag, ciphertext])
}

/** 解开 [iv|tag|ciphertext]；密码/密钥不对时抛错（GCM 认证失败） */
export function open(key, blob) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) throw new Error('密钥无效')
  const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob)
  if (buf.length < IV_BYTES + TAG_BYTES + 1) throw new Error('密文损坏')
  const iv = buf.subarray(0, IV_BYTES)
  const tag = buf.subarray(IV_BYTES, IV_BYTES + TAG_BYTES)
  const ciphertext = buf.subarray(IV_BYTES + TAG_BYTES)
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

export function randomKey() {
  return randomBytes(KEY_BYTES)
}

export function randomSalt() {
  return randomBytes(16)
}

/** 尽力清空内存中的密钥副本 */
export function wipe(buffer) {
  if (Buffer.isBuffer(buffer)) buffer.fill(0)
}

/** 常数时间比较，供 verifier 类校验使用 */
export { timingSafeEqual } from 'node:crypto'
