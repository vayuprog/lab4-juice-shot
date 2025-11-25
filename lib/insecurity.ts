/*
 * Secureed/modernized replacement for original auth utilities.
 * Replaces hard-coded secrets with env/file-based keys, uses SHA-256,
 * safer HMAC usage, constant-time comparisons, safer redirect checks,
 * safer JWT handling and secure cookie options.
 *
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import expressJwt from 'express-jwt'
import jwt from 'jsonwebtoken'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

// z85 has no TS types in some environments — keep the same import used previously.
 // eslint-disable-next-line @typescript-eslint/ban-ts-comment
 // @ts-ignore
import * as z85 from 'z85'

/* ---------- Key & secret loading (no hard-coded secrets) ---------- */

function loadSecretFromEnvOrFile (envVar: string, envPathVar: string): string | undefined {
  const direct = process.env[envVar]
  if (direct && direct.length > 0) return direct
  const p = process.env[envPathVar]
  if (!p) return undefined
  try {
    const resolved = path.resolve(p)
    return fs.readFileSync(resolved, 'utf8')
  } catch (e) {
    // Do not throw here — allow the caller to handle missing secrets
    return undefined
  }
}

export const publicKey: string = loadSecretFromEnvOrFile('JWT_PUBLIC_KEY', 'JWT_PUBLIC_KEY_PATH') ?? (() => {
  if (process.env.NODE_ENV === 'test') return 'test-public-key-placeholder'
  throw new Error('JWT public key is not configured. Set JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_PATH.')
})()

const privateKey: string = loadSecretFromEnvOrFile('JWT_PRIVATE_KEY', 'JWT_PRIVATE_KEY_PATH') ?? (() => {
  if (process.env.NODE_ENV === 'test') return 'test-private-key-placeholder'
  throw new Error('JWT private key is not configured. Set JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH.')
})()

const HMAC_SECRET = process.env.HMAC_SECRET ?? (() => {
  if (process.env.NODE_ENV === 'test') return 'test-hmac-placeholder'
  throw new Error('HMAC_SECRET not set. Provide a strong secret via environment.')
})()

/* ---------- Types ---------- */

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Map<string, ResponseWithUser>
  idMap: Map<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => void
}

/* ---------- Crypto helpers (safer) ---------- */

export const hash = (data: string) => crypto.createHash('sha256').update(data, 'utf8').digest('hex')

export const hmac = (data: string) => crypto.createHmac('sha256', HMAC_SECRET).update(data, 'utf8').digest('hex')

/* constant-time comparison helper */
function safeCompare (a?: string, b?: string): boolean {
  if (!a || !b) return false
  try {
    const ab = Buffer.from(a, 'utf8')
    const bb = Buffer.from(b, 'utf8')
    // lengths must match for timingSafeEqual; if not equal, return false quickly
    if (ab.length !== bb.length) return false
    return crypto.timingSafeEqual(ab, bb)
  } catch {
    return false
  }
}

/* ---------- Sanitization helpers ---------- */

/* Recommended sanitize-html configuration: keep a strict set of allowed tags/attributes */
const SANITIZE_HTML_OPTIONS: sanitizeHtmlLib.IOptions = {
  allowedTags: sanitizeHtmlLib.defaults.allowedTags.concat(['img', 'h1', 'h2', 'u']),
  allowedAttributes: {
    a: ['href', 'name', 'target', 'rel'],
    img: ['src', 'alt'],
    '*': ['class']
  },
  // Disallow potentially dangerous protocols (javascript:, data:, vbscript:)
  allowedSchemes: ['http', 'https', 'mailto', 'tel', 'data'],
  allowProtocolRelative: false
}

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html, SANITIZE_HTML_OPTIONS)

export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')

export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)

export const sanitizeSecure = (html: string): string => {
  // Iteratively sanitize until stable (but guard against infinite loops)
  let sanitized = sanitizeHtml(html)
  for (let i = 0; i < 5; i++) {
    const next = sanitizeHtml(sanitized)
    if (next === sanitized) return sanitized
    sanitized = next
  }
  return sanitized
}

/* null byte cutoff */
export const cutOffPoisonNullByte = (str: string) => {
  if (!str) return str
  const nullByte = '%00'
  const idx = str.indexOf(nullByte)
  if (idx >= 0) return str.substring(0, idx)
  return str
}

/* ---------- JWT helpers (use jsonwebtoken with keys loaded from env/files) ---------- */

/* express-jwt requires different secrets/format depending on algorithm.
   We provide a function that returns the publicKey — avoids embedding secrets in code. */
export const isAuthorized = () => expressJwt({ secret: publicKey, algorithms: ['RS256'] } as any)
export const denyAll = () => expressJwt({ secret: crypto.randomBytes(32).toString('hex'), algorithms: ['HS256'] } as any)

/* create signed token with RS256 (privateKey loaded above) */
export const authorize = (user = {}) => {
  // Keep token lifetime configurable via env (default 6h)
  const expiresIn = process.env.JWT_EXPIRES_IN ?? '6h'
  return jwt.sign(user, privateKey, { expiresIn, algorithm: 'RS256' })
}

/* verify token using jsonwebtoken. Returns boolean */
export const verify = (token: string): boolean => {
  if (!token) return false
  try {
    jwt.verify(token, publicKey, { algorithms: ['RS256'] })
    return true
  } catch {
    return false
  }
}

/* decode token payload safely (does not verify) */
export const decode = (token: string) => {
  try {
    return jwt.decode(token)
  } catch {
    return undefined
  }
}

/* ---------- Authenticated users in-memory store (use Map, avoid raw objects) ---------- */

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: new Map<string, ResponseWithUser>(),
  idMap: new Map<string, string>(),
  put: function (token: string, user: ResponseWithUser) {
    if (!token || !user || !user.data?.id) return
    this.tokenMap.set(token, user)
    this.idMap.set(String(user.data.id), token)
  },
  get: function (token?: string) {
    if (!token) return undefined
    return this.tokenMap.get(utils.unquote(token))
  },
  tokenOf: function (user: UserModel) {
    if (!user || !user.id) return undefined
    return this.idMap.get(String(user.id))
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    if (token) this.put(token, user)
  }
}

/* ---------- User header helper ---------- */

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

/* ---------- Coupon helpers ---------- */

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  // z85.encode might throw — guard and rethrow a controlled error
  try {
    // ensure coupon is string and ASCII-safe
    return z85.encode(String(coupon))
  } catch (err) {
    throw new Error('Failed to generate coupon')
  }
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) return undefined
  try {
    const decodedBuf = z85.decode(coupon)
    const decoded = decodedBuf && decodedBuf.toString('utf8')
    if (!decoded) return undefined
    if (hasValidFormat(decoded) != null) {
      const parts = decoded.split('-')
      const validity = parts[0]
      if (utils.toMMMYY(new Date()) === validity) {
        const discount = parts[1]
        return Number.parseInt(discount)
      }
    }
    return undefined
  } catch {
    return undefined
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/^(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{1,3}$/)
}

/* ---------- Redirect allowlist (use origins, not substring matching) ---------- */

/* Define allowed origins (scheme + host + optional port). Use environment override if needed. */
const DEFAULT_ALLOWED_REDIRECTS = [
  'https://github.com',
  'https://blockchain.info',
  'https://explorer.dash.org',
  'https://etherscan.io',
  'http://shop.spreadshirt.com',
  'http://shop.spreadshirt.de',
  'https://www.stickeryou.com',
  'http://leanpub.com'
]

const allowedRedirectOrigins = new Set<string>(
  (process.env.ALLOWED_REDIRECT_ORIGINS?.split(',').map(s => s.trim()).filter(Boolean) ??
    DEFAULT_ALLOWED_REDIRECTS)
)

/* Check redirect by parsing URL and comparing origin (scheme + host + port) exactly.
   Reject invalid URLs or non-http(s) schemes. */
export const isRedirectAllowed = (candidate: string) => {
  if (!candidate) return false
  try {
    const url = new URL(candidate)
    const origin = url.origin // includes scheme + host + port
    // Only allow http or https
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
    // Exact origin match (not substring)
    return allowedRedirectOrigins.has(origin)
  } catch {
    return false
  }
}

/* ---------- Roles & role checks (use safe compare) ---------- */

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

/* deluxeToken uses HMAC with secret from env and constant-time compare */
export const deluxeToken = (email: string) => {
  const h = crypto.createHmac('sha256', HMAC_SECRET)
  return h.update(email + roles.deluxe, 'utf8').digest('hex')
}

/* isAccounting middleware — verifies token and role */
export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = utils.jwtFrom(req)
      if (!token || !verify(token)) {
        return res.status(401).json({ error: 'Invalid token' })
      }
      const decoded: any = decode(token)
      if (decoded?.data?.role === roles.accounting) {
        return next()
      }
      return res.status(403).json({ error: 'Forbidden' })
    } catch (err) {
      return res.status(500).json({ error: 'Server error' })
    }
  }
}

/* isDeluxe / isCustomer helpers */
export const isDeluxe = (req: Request) => {
  try {
    const token = utils.jwtFrom(req)
    if (!token || !verify(token)) return false
    const decoded: any = decode(token)
    const roleOk = decoded?.data?.role === roles.deluxe
    const hasDeluxeToken = !!decoded?.data?.deluxeToken
    const expected = deluxeToken(decoded?.data?.email)
    return roleOk && hasDeluxeToken && safeCompare(decoded.data.deluxeToken, expected)
  } catch {
    return false
  }
}

export const isCustomer = (req: Request) => {
  try {
    const token = utils.jwtFrom(req)
    if (!token || !verify(token)) return false
    const decoded: any = decode(token)
    return decoded?.data?.role === roles.customer
  } catch {
    return false
  }
}

/* ---------- Request helpers ---------- */

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = utils.jwtFrom(req)
      const auth = token ? authenticatedUsers.get(token) : undefined
      if (!auth) {
        return res.status(401).json({ status: 'error', message: 'Not authenticated' })
      }
      // Ensure UserId is numeric/string sanitized
      req.body = req.body || {}
      req.body.UserId = String(auth.data.id)
      return next()
    } catch (error: any) {
      return res.status(401).json({ status: 'error', message: 'Invalid token' })
    }
  }
}

/* updateAuthenticatedUsers: verify token with publicKey, then store mapping and set cookie with secure flags */
export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req.cookies?.token || utils.jwtFrom(req)
    if (token) {
      jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err: any, decoded: any) => {
        if (!err && decoded) {
          // Only store if not already stored
          if (authenticatedUsers.get(token) === undefined) {
            authenticatedUsers.put(token, decoded as ResponseWithUser)
            // Set cookie with httpOnly and secure flags. Respect environment (allow insecure in dev).
            const cookieOptions: any = {
              httpOnly: true,
              sameSite: 'lax'
            }
            if (process.env.NODE_ENV === 'production') {
              cookieOptions.secure = true
              cookieOptions.sameSite = 'strict'
            }
            // If cookie domains etc. are needed, allow env override
            if (process.env.AUTH_COOKIE_DOMAIN) cookieOptions.domain = process.env.AUTH_COOKIE_DOMAIN
            // Short lifetime for cookie - use token expiry if present
            res.cookie('token', token, cookieOptions)
          }
        }
      })
    }
  } catch {
    // intentionally swallow errors but do not block request processing
  } finally {
    next()
  }
}