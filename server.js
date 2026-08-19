#!/usr/bin/env node
'use strict';
/*
 * ContactOut 逆向 API 服务 (v1)
 * 零依赖 Node 服务：多账号 cookie 轮换查询 LinkedIn → 邮箱/电话
 *
 * 环境变量：
 *   PORT            监听端口 (默认 8787)
 *   ACCESS_TOKEN    访问令牌 (设置后请求需带 x-co-token)
 *   SESSIONS_FILE   sessions.json 路径 (默认 ./sessions.json)
 *   MAX_CONCURRENCY 并发上限 (默认 3)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');

const PORT = parseInt(process.env.PORT || '8787', 10);
const TOKENS = (process.env.ACCESS_TOKEN || '').split(',').map(s => s.trim()).filter(Boolean);
// 管理员口令: 用于管理后台 (创建/删除 token, 看用量)。默认 = ACCESS_TOKEN 第一个
const MASTER_TOKENS = (process.env.MASTER_TOKEN || '').split(',').map(s => s.trim()).filter(Boolean);
const SESSIONS_FILE = process.env.SESSIONS_FILE || path.join(__dirname, 'sessions.json');
const MAX_CONCURRENCY = parseInt(process.env.MAX_CONCURRENCY || '3', 10);
const VERSION = '5.6.18';

// —— 令牌与用量存储 ——
const TOKENS_FILE = process.env.TOKENS_FILE || path.join(__dirname, 'tokens.json');
const USAGE_FILE = process.env.USAGE_FILE || path.join(__dirname, 'usage.json');
let CUSTOM_TOKENS = {};   // key -> { name, email_limit, phone_limit, email_used, phone_used, day, created, active }
let USAGE_LOG = [];       // [{ ts, token, name, profile, kind, email, phone, ok }]

function loadJSONFile(file, fallback) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {}
  return fallback;
}
function saveJSONFile(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data, null, 2)); } catch (e) {}
}
CUSTOM_TOKENS = loadJSONFile(TOKENS_FILE, {});
USAGE_LOG = loadJSONFile(USAGE_FILE, []);
if (USAGE_LOG.length > 20000) USAGE_LOG = USAGE_LOG.slice(-20000); // 只留最近 2 万条

function dayKey() { return new Date().toISOString().slice(0, 10); }

// 每日用量重置（按天滚动）
function tokenUsage(tk) {
  const d = dayKey();
  const t = CUSTOM_TOKENS[tk];
  if (!t) return null;
  if (t.day !== d) { t.day = d; t.email_used = 0; t.phone_used = 0; saveJSONFile(TOKENS_FILE, CUSTOM_TOKENS); }
  return t;
}
function tokenOK(req, u) {
  const tk = req.headers['x-co-token'] || u.searchParams.get('token') || '';
  // 开放模式: 无任何 token 配置时允许访问 (本地用)
  if (!TOKENS.length && !Object.keys(CUSTOM_TOKENS).length) return true;
  if (!tk) return false;
  if (TOKENS.indexOf(tk) !== -1) return true;
  if (CUSTOM_TOKENS[tk] && CUSTOM_TOKENS[tk].active !== false) return true;
  return false;
}
function masterOK(req, u) {
  const tk = req.headers['x-co-token'] || u.searchParams.get('token') || '';
  if (MASTER_TOKENS.length) return MASTER_TOKENS.indexOf(tk) !== -1;
  if (TOKENS.length) return TOKENS.indexOf(tk) !== -1;
  return false;
}
// 记录一次用量 (查询成功或尝试都记; consumedEmail/consumedPhone 表示是否扣额度)
function logUsage(req, tk, info) {
  try {
    USAGE_LOG.push(Object.assign({ ts: Date.now(), token: tk, name: (CUSTOM_TOKENS[tk] || {}).name || 'env', ip: (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress }, info));
    if (USAGE_LOG.length > 20000) USAGE_LOG = USAGE_LOG.slice(-20000);
    saveJSONFile(USAGE_FILE, USAGE_LOG);
  } catch (e) {}
}
// 检查 token 当日邮箱/电话额度
function tokenQuotaOK(tk, kind) {
  const t = tokenUsage(tk);
  if (!t) return { ok: true };
  const used = kind === 'email' ? (t.email_used || 0) : (t.phone_used || 0);
  const limit = kind === 'email' ? (t.email_limit || 0) : (t.phone_limit || 0);
  if (limit <= 0) return { ok: true }; // 不限
  if (used >= limit) return { ok: false, limit, used };
  return { ok: true };
}
function consumeQuota(tk, kind, n = 1) {
  const t = tokenUsage(tk);
  if (!t) return;
  if (kind === 'email') t.email_used = (t.email_used || 0) + n;
  else t.phone_used = (t.phone_used || 0) + n;
  saveJSONFile(TOKENS_FILE, CUSTOM_TOKENS);
}
function genTokenKey() {
  return 'co_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

// —— 账号池: 内存中维护, 每次查询更新额度 ——
let SESSIONS = [];
function loadSessions() {
  try {
    let raw = null;
    if (process.env.SESSIONS_JSON) {
      raw = process.env.SESSIONS_JSON;
    } else {
      raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
    }
    SESSIONS = Array.isArray(JSON.parse(raw)) ? JSON.parse(raw) : [JSON.parse(raw)];
  } catch (e) {
    console.error('sessions 加载失败:', e.message);
    SESSIONS = [];
  }
}
function saveSessions() {
  // 环境变量模式不写回 (cookie 由环境变量管理); 本地文件模式写回
  if (process.env.SESSIONS_JSON) return;
  try { fs.writeFileSync(SESSIONS_FILE, JSON.stringify(SESSIONS, null, 2)); } catch (e) {}
}
loadSessions();

// —— Cookie 预热: 定期调 user/info 保持会话活跃 + 检测失效 ——
const WARMUP_INTERVAL = parseInt(process.env.WARMUP_INTERVAL || '21600000', 10); // 默认 6 小时
let warmupState = { lastRun: 0, ok: 0, bad: [] };

async function warmupOnce() {
  const results = { ok: 0, bad: [], time: Date.now() };
  for (const s of SESSIONS) {
    if (!s.cookie) { results.bad.push({ email: s.email || '?', reason: 'no_cookie' }); continue; }
    try {
      const r = await fetch('https://contactout.com/api/user/info?version=5.6.18', {
        headers: { 'Cookie': s.cookie, 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0 Safari/537.36' },
        signal: AbortSignal.timeout(15000),
      });
      const t = await r.text();
      let d = null; try { d = JSON.parse(t); } catch (e) {}
      if (r.status === 200 && d && d.user_id && d.user_id > 0) {
        // 更新额度（顺便同步）
        if (typeof d.credit === 'number') s.credit = d.credit;
        if (typeof d.phoneCredit === 'number') s.phoneCredit = d.phoneCredit;
        results.ok++;
      } else if (r.status === 200 && d && d.user_id === -1) {
        results.bad.push({ email: s.email || '?', reason: 'not_logged_in' });
      } else {
        results.bad.push({ email: s.email || '?', reason: 'http_' + r.status });
      }
    } catch (e) {
      results.bad.push({ email: s.email || '?', reason: e.name === 'TimeoutError' ? 'timeout' : e.message });
    }
    await new Promise(r => setTimeout(r, 1500)); // 间隔防风控
  }
  if (SESSIONS.length) saveSessions();
  warmupState = results;
  console.log('[warmup] ok=' + results.ok + ' bad=' + results.bad.length + (results.bad.length ? ' bad:' + results.bad.map(b => b.email + '(' + b.reason + ')').join(',') : ''));
  return results;
}
function startWarmup() {
  if (WARMUP_INTERVAL <= 0) return;
  warmupOnce().catch(() => {}); // 启动先跑一次
  setInterval(() => warmupOnce().catch(() => {}), WARMUP_INTERVAL);
}
startWarmup();

// 账号轮换状态
let nextAccount = 0;
let queue = [];       // 并发队列: { fn, resolve, reject }

// —— 工具 ——
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type,x-co-token');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
}
function json(res, code, obj) {
  res.statusCode = code;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise(r => {
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => r(d));
    req.on('error', () => r(''));
  });
}
function extractVanity(url) {
  const m = String(url).match(/linkedin\.com\/in\/([^/?#]+)/i);
  return m ? decodeURIComponent(m[1]) : null;
}
function parseLinks(input) {
  const arr = Array.isArray(input) ? input : String(input || '').split(/[\n,;]+/);
  const seen = {}, items = [];
  for (const raw of arr) {
    const url = String(raw).trim();
    const vanity = extractVanity(url);
    if (vanity && !seen[vanity]) {
      seen[vanity] = 1;
      let fullName = '';
      // 支持 "url,Full Name"
      const parts = url.split(',').map(s => s.trim());
      const mainUrl = parts[0];
      if (parts.length > 1) fullName = parts.slice(1).join(' ');
      items.push({ profile_url: mainUrl, li_vanity: vanity, full_name: fullName });
    }
  }
  return items;
}

// —— 查询核心: 选一个有额度的账号调用 reveal ——
async function pickAccount() {
  // 找到还有邮箱额度的账号
  for (let i = 0; i < SESSIONS.length; i++) {
    const idx = (nextAccount + i) % SESSIONS.length;
    const s = SESSIONS[idx];
    if (!s.cookie) continue;
    const credit = typeof s.credit === 'number' ? s.credit : 5;
    if (credit > 0) { nextAccount = (idx + 1) % SESSIONS.length; return s; }
  }
  return null;
}

async function revealWithAccount(session, item) {
  const body = {
    uuid: randomUUID(),
    version: VERSION,
    user: session.userId,
    profile_url: item.profile_url,
    li_vanity: item.li_vanity,
    full_name: item.full_name || '',
    profile_type: 'regular',
    member_id: '',
  };
  const res = await fetch('https://contactout.com/api/v5/profiles/reveal', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': session.cookie,
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch (e) {}
  return { status: res.status, data, text };
}

// 单条查询: 失败/受限换账号重试
async function lookupOne(item) {
  const attempts = SESSIONS.length || 1;
  let allRestricted = 0;
  for (let i = 0; i < attempts; i++) {
    const session = await pickAccount();
    if (!session) return { ok: false, error: 'no_credit', msg: '所有账号邮箱额度已用完' };
    try {
      const r = await revealWithAccount(session, item);
      if (r.status === 200 && r.data && r.data.profile) {
        // 更新额度 (响应里带新 credit)
        if (typeof r.data.credit === 'number') session.credit = r.data.credit;
        if (r.data.userCredits) {
          if (typeof r.data.userCredits.email === 'number') session.credit = r.data.userCredits.email;
          if (typeof r.data.userCredits.phone === 'number') session.phoneCredit = r.data.userCredits.phone;
        }
        saveSessions();
        const emails = (r.data.profile.emails || []).map(e => ({
          value: e.value, confidence: e.confidence_level || '', is_guess: !!e.is_guess,
          type: e.type === 2 ? 'personal' : (e.type === 1 ? 'work' : ''),
        }));
        const phones = (r.data.profile.phones || []).map(p => ({
          value: p.value || p.number || '', confidence: p.confidence_level || '',
        }));
        return {
          ok: true,
          linkedin: item.profile_url,
          name: item.full_name || '',
          emails,
          phones,
          credit_used: 1,
          credit_remaining: typeof r.data.credit === 'number' ? r.data.credit : session.credit,
        };
      }
      // 受限 profile (status 900): 免费版按账号随机锁, 换下一个账号重试
      if (r.status === 200 && r.data && r.data.status === 900) {
        if (r.data.userCredits) {
          if (typeof r.data.userCredits.email === 'number') session.credit = r.data.userCredits.email;
          if (typeof r.data.userCredits.phone === 'number') session.phoneCredit = r.data.userCredits.phone;
        }
        saveSessions();
        session.restrictedCount = (session.restrictedCount || 0) + 1;
        allRestricted++;
        continue; // 换下一个账号
      }
      if (r.status === 401 || r.status === 403) {
        // cookie 失效, 标记并试下一个
        session.cookie = null;
        session.invalid = true;
        saveSessions();
        continue;
      }
      if (r.status === 402 || (r.data && r.data.error && /credit/i.test(String(r.data.error)))) {
        session.credit = 0;
        saveSessions();
        continue;
      }
      return { ok: false, error: 'upstream', msg: 'HTTP ' + r.status + ': ' + (r.text || '').slice(0, 200), credit_used: 0 };
    } catch (e) {
      // 网络错误, 换账号重试
      if (i === attempts - 1) return { ok: false, error: 'network', msg: e.message };
    }
  }
  if (allRestricted === attempts) {
    return { ok: false, error: 'restricted', msg: '该 profile 在所有免费账号均受限，需升级付费账号', credit_used: 0 };
  }
  return { ok: false, error: 'unknown' };
}

// 电话查询: 单独端点 /api/find/phone, 扣 phoneCredit
async function lookupPhone(item) {
  const attempts = SESSIONS.length || 1;
  let allRestricted = 0;
  for (let i = 0; i < attempts; i++) {
    // 选有电话额度的账号
    let session = null;
    for (let k = 0; k < SESSIONS.length; k++) {
      const idx = (nextAccount + k) % SESSIONS.length;
      const s = SESSIONS[idx];
      if (!s.cookie || s.invalid) continue;
      const pc = typeof s.phoneCredit === 'number' ? s.phoneCredit : 5;
      if (pc > 0) { session = s; nextAccount = (idx + 1) % SESSIONS.length; break; }
    }
    if (!session) return { ok: false, error: 'no_credit', msg: '所有账号电话额度已用完' };
    try {
      const body = {
        uuid: randomUUID(),
        version: VERSION,
        user: session.userId,
        liVanity: item.li_vanity,
        memberId: '',
        profileType: item.profile_type || 'regular',
        fullName: item.full_name || '',
        companies: item.companies || [],
      };
      const r = await fetch('https://contactout.com/api/find/phone', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': session.cookie,
          'x-reveal-source': 'default',
          'x-disable-message': '0',
        },
        body: JSON.stringify(body),
      });
      const text = await r.text();
      let data = null; try { data = JSON.parse(text); } catch (e) {}
      // 受限 profile (status 900): 免费版按账号随机锁, 换下一个账号重试
      if (r.status === 200 && data && data.status === 900) {
        if (data.userCredits && typeof data.userCredits.phone === 'number') session.phoneCredit = data.userCredits.phone;
        saveSessions();
        allRestricted++;
        continue; // 换下一个账号
      }
      if (r.status === 200 && data && data.phone) {
        if (typeof data.credit === 'number') session.phoneCredit = data.credit;
        if (data.userCredits) {
          if (typeof data.userCredits.phone === 'number') session.phoneCredit = data.userCredits.phone;
          if (typeof data.userCredits.email === 'number') session.credit = data.userCredits.email;
        }
        saveSessions();
        let phoneVal = '';
        if (typeof data.phone === 'object') phoneVal = String(data.phone.value || data.phone.number || data.phone.phone || '');
        else phoneVal = String(data.phone || '');
        const types = data.phoneTypes || {};
        return {
          ok: true,
          linkedin: item.profile_url,
          phone: phoneVal,
          phone_type: types[phoneVal] || 'unknown',
          phones: (data.phones || []).filter(Boolean),
          credit_used: 1,
          credit_remaining: typeof data.credit === 'number' ? data.credit : session.phoneCredit,
        };
      }
      if (r.status === 401 || r.status === 403) {
        session.cookie = null; session.invalid = true; saveSessions(); continue;
      }
      if (r.status === 402 || (data && data.error && /credit/i.test(String(data.error)))) {
        session.phoneCredit = 0; saveSessions(); continue;
      }
      // 无电话 (200 但 phone null) — 不重试, 正常返回
      if (r.status === 200) {
        if (data && data.userCredits && typeof data.userCredits.phone === 'number') session.phoneCredit = data.userCredits.phone;
        saveSessions();
        return { ok: false, found: false, linkedin: item.profile_url, msg: 'no phone', credit_used: 1 };
      }
      return { ok: false, error: 'upstream', msg: 'HTTP ' + r.status + ': ' + text.slice(0, 200) };
    } catch (e) {
      if (i === attempts - 1) return { ok: false, error: 'network', msg: e.message };
    }
  }
  if (allRestricted === attempts) {
    return { ok: false, error: 'restricted', msg: '该 profile 在所有免费账号均受限，需升级付费账号', credit_used: 0 };
  }
  return { ok: false, error: 'unknown' };
}

// —— 并发队列 (全局信号量) ——
let activeJobs = 0;
async function enqueue(fn) {
  return new Promise((resolve, reject) => {
    queue.push({ fn, resolve, reject });
    pump();
  });
}
function pump() {
  while (queue.length > 0 && activeJobs < MAX_CONCURRENCY) {
    const job = queue.shift();
    if (!job) break;
    activeJobs++;
    job.fn().then(job.resolve, job.reject).finally(() => {
      activeJobs--;
      pump();
    });
  }
}

// —— 统计 ——
function stats() {
  return SESSIONS.map(s => ({
    email: s.email || 'unknown',
    userId: s.userId,
    email_credit: s.invalid ? 0 : (typeof s.credit === 'number' ? s.credit : 5),
    phone_credit: s.invalid ? 0 : (typeof s.phoneCredit === 'number' ? s.phoneCredit : 5),
    invalid: !!s.invalid,
  }));
}
function totalEmailCredit() {
  return stats().reduce((a, s) => a + s.email_credit, 0);
}
function totalPhoneCredit() {
  return stats().reduce((a, s) => a + s.phone_credit, 0);
}

// 前端页面
const INDEX_HTML = path.join(__dirname, 'public', 'index.html');
const ADMIN_HTML = path.join(__dirname, 'public', 'admin.html');
function serveIndex(res) {
  try {
    res.statusCode = 200;
    res.setHeader('content-type', 'text/html; charset=utf-8');
    return res.end(fs.readFileSync(INDEX_HTML));
  } catch (e) {
    return json(res, 500, { error: 'index.html missing: ' + e.message });
  }
}
function serveAdmin(res) {
  try {
    res.statusCode = 200;
    res.setHeader('content-type', 'text/html; charset=utf-8');
    return res.end(fs.readFileSync(ADMIN_HTML));
  } catch (e) {
    return json(res, 500, { error: 'admin.html missing: ' + e.message });
  }
}

// —— 服务 ——
const server = http.createServer(async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  // 前端页面 (无需 token, 客户打开即用; 查询 API 才需 token)
  if (p === '/' || p === '/index.html') return serveIndex(res);
  if (p === '/admin' || p === '/admin.html') return serveAdmin(res);

  if (p === '/health') return json(res, 200, { ok: true, accounts: SESSIONS.length, total_email_credit: totalEmailCredit() });

  // 额度
  if (p === '/api/credits') {
    if (!tokenOK(req, u)) return json(res, 401, { error: 'bad or missing token' });
    const tk = req.headers['x-co-token'] || u.searchParams.get('token') || '';
    const tu = tokenUsage(tk);
    const isMaster = masterOK(req, u);
    const my = tu ? { email_limit: tu.email_limit || 0, email_used: tu.email_used || 0, phone_limit: tu.phone_limit || 0, phone_used: tu.phone_used || 0, name: tu.name || '' } : null;
    // 客户: 只返回自己的额度; 管理员: 额外返回全局账号池
    if (!isMaster) {
      return json(res, 200, { ok: true, resets: 'daily', me: my, is_master: false });
    }
    return json(res, 200, { ok: true, accounts: stats(), total_email_credit: totalEmailCredit(), total_phone_credit: totalPhoneCredit(), resets: 'daily', me: my, is_master: true });
  }

  // 单条查询: POST /api/reveal  {"profile_url":"...","full_name":"..."}
  if (p === '/api/reveal') {
    if (!tokenOK(req, u)) return json(res, 401, { error: 'bad or missing token' });
    if (!SESSIONS.length) return json(res, 503, { error: 'no sessions configured' });
    const tk = req.headers['x-co-token'] || u.searchParams.get('token') || '';
    const q = tokenQuotaOK(tk, 'email');
    if (!q.ok) return json(res, 429, { code: 2003, error: 'daily limit reached', msg: '今日邮箱查询额度已达上限 (' + q.used + '/' + q.limit + ')' });
    const bodyTxt = await readBody(req);
    let body = {}; try { body = JSON.parse(bodyTxt || '{}'); } catch (e) {}
    const items = parseLinks(body.profile_url || body.url || body.linkedin || '');
    if (!items.length) return json(res, 400, { error: 'no valid linkedin url', hint: 'POST JSON {"profile_url":"https://www.linkedin.com/in/xxx"}' });
    const item = items[0];
    if (body.full_name) item.full_name = String(body.full_name);
    const r = await enqueue(() => lookupOne(item));
    consumeQuota(tk, 'email');
    logUsage(req, tk, { kind: 'email', profile: item.profile_url, ok: !!r.ok, email: r.emails ? r.emails.map(e => e.value).join(';') : '', restricted: r.error === 'restricted' });
    if (r.ok) return json(res, 200, { code: 0, data: r, credits: { used: r.credit_used, remaining: r.credit_remaining } });
    if (r.error === 'no_credit') return json(res, 402, { code: 2001, error: 'no credit', msg: r.msg });
    return json(res, 502, { code: 3001, error: r.error, msg: r.msg });
  }

  // 单条查电话: POST /api/phone  {"profile_url":"...","full_name":"..."}
  if (p === '/api/phone') {
    if (!tokenOK(req, u)) return json(res, 401, { error: 'bad or missing token' });
    if (!SESSIONS.length) return json(res, 503, { error: 'no sessions configured' });
    const tk = req.headers['x-co-token'] || u.searchParams.get('token') || '';
    const q = tokenQuotaOK(tk, 'phone');
    if (!q.ok) return json(res, 429, { code: 2003, error: 'daily limit reached', msg: '今日电话查询额度已达上限 (' + q.used + '/' + q.limit + ')' });
    const bodyTxt = await readBody(req);
    let body = {}; try { body = JSON.parse(bodyTxt || '{}'); } catch (e) {}
    const items = parseLinks(body.profile_url || body.url || body.linkedin || '');
    if (!items.length) return json(res, 400, { error: 'no valid linkedin url', hint: 'POST JSON {"profile_url":"https://www.linkedin.com/in/xxx"}' });
    const item = items[0];
    if (body.full_name) item.full_name = String(body.full_name);
    const r = await enqueue(() => lookupPhone(item));
    consumeQuota(tk, 'phone');
    logUsage(req, tk, { kind: 'phone', profile: item.profile_url, ok: !!r.ok, phone: r.phone || '', restricted: r.error === 'restricted' });
    if (r.ok) return json(res, 200, { code: 0, data: r });
    if (r.error === 'no_credit') return json(res, 402, { code: 2001, error: 'no credit', msg: r.msg });
    if (r.found === false) return json(res, 200, { code: 0, data: r });
    return json(res, 502, { code: 3001, error: r.error, msg: r.msg });
  }

  // 邮箱+电话一起查: POST /api/find  {"profile_url":"...","full_name":"..."}
  if (p === '/api/find') {
    if (!tokenOK(req, u)) return json(res, 401, { error: 'bad or missing token' });
    if (!SESSIONS.length) return json(res, 503, { error: 'no sessions configured' });
    const tk = req.headers['x-co-token'] || u.searchParams.get('token') || '';
    const qe = tokenQuotaOK(tk, 'email');
    if (!qe.ok) return json(res, 429, { code: 2003, error: 'daily limit reached', msg: '今日邮箱查询额度已达上限 (' + qe.used + '/' + qe.limit + ')' });
    const qp = tokenQuotaOK(tk, 'phone');
    if (!qp.ok) return json(res, 429, { code: 2003, error: 'daily limit reached', msg: '今日电话查询额度已达上限 (' + qp.used + '/' + qp.limit + ')' });
    const bodyTxt = await readBody(req);
    let body = {}; try { body = JSON.parse(bodyTxt || '{}'); } catch (e) {}
    const items = parseLinks(body.profile_url || body.url || body.linkedin || '');
    if (!items.length) return json(res, 400, { error: 'no valid linkedin url', hint: 'POST JSON {"profile_url":"https://www.linkedin.com/in/xxx"}' });
    const item = items[0];
    if (body.full_name) item.full_name = String(body.full_name);
    const [em, ph] = await Promise.all([enqueue(() => lookupOne(item)), enqueue(() => lookupPhone(item))]);
    consumeQuota(tk, 'email');
    consumeQuota(tk, 'phone');
    logUsage(req, tk, { kind: 'both', profile: item.profile_url, ok: !!(em.ok || ph.ok), email: em.ok ? em.emails.map(e => e.value).join(';') : '', phone: ph.ok ? ph.phone : '', restricted: em.error === 'restricted' || ph.error === 'restricted' });
    const phoneList = ph.ok ? (ph.phones && ph.phones.length ? ph.phones : (ph.phone ? [ph.phone] : [])) : [];
    return json(res, 200, { code: 0, data: {
      ok: em.ok || ph.ok,
      linkedin: item.profile_url,
      name: item.full_name || '',
      emails: em.emails || [],
      phones: phoneList.map(v => typeof v === 'string' ? { value: v } : v),
      phone: ph.ok ? ph.phone : '',
      email_credit_remaining: em.credit_remaining ?? 0,
      phone_credit_remaining: ph.credit_remaining ?? 0,
      email_error: em.ok ? undefined : em.msg,
      phone_error: ph.ok ? undefined : ph.msg,
    } });
  }

  // 批量: POST /api/reveal/batch  {"profiles":["url1","url2"]}
  if (p === '/api/reveal/batch') {
    if (!tokenOK(req, u)) return json(res, 401, { error: 'bad or missing token' });
    if (!SESSIONS.length) return json(res, 503, { error: 'no sessions configured' });
    const tk = req.headers['x-co-token'] || u.searchParams.get('token') || '';
    const q = tokenQuotaOK(tk, 'email');
    if (!q.ok) return json(res, 429, { code: 2003, error: 'daily limit reached', msg: '今日邮箱查询额度已达上限 (' + q.used + '/' + q.limit + ')' });
    const bodyTxt = await readBody(req);
    let body = {}; try { body = JSON.parse(bodyTxt || '{}'); } catch (e) {}
    const input = body.profiles || body.urls || body.links || [];
    const items = parseLinks(input);
    if (!items.length) return json(res, 400, { error: 'no valid linkedin urls', hint: 'POST JSON {"profiles":["url1","url2"]}' });
    const totalCredit = totalEmailCredit();
    if (items.length > totalCredit) {
      return json(res, 402, { code: 2002, error: 'not enough credit', need: items.length, have: totalCredit });
    }
    const results = [];
    for (const item of items) {
      const r = await enqueue(() => lookupOne(item));
      results.push(r);
    }
    consumeQuota(tk, 'email', results.length);
    logUsage(req, tk, { kind: 'batch', profile: 'batch:' + items.length, ok: results.some(r => r.ok), email: results.filter(r => r.ok).map(r => r.emails ? r.emails.map(e => e.value).join(';') : '').join('|') });
    const okCount = results.filter(r => r.ok).length;
    return json(res, 200, { ok: true, total: results.length, found: okCount, results });
  }

  // ============ 管理后台端点 (需 master token) ============
  // GET /admin/api/tokens  列出所有口令+用量
  if (p === '/admin/api/tokens' && req.method !== 'POST') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const today = dayKey();
    const list = Object.keys(CUSTOM_TOKENS).map(k => {
      const t = CUSTOM_TOKENS[k];
      return { key: k, name: t.name, email_limit: t.email_limit || 0, phone_limit: t.phone_limit || 0, email_used: t.day === today ? (t.email_used || 0) : 0, phone_used: t.day === today ? (t.phone_used || 0) : 0, created: t.created, active: t.active !== false };
    });
    const envTokens = TOKENS.map((k, i) => ({ key: k, name: '环境变量口令 #' + (i + 1), email_limit: 0, phone_limit: 0, email_used: 0, phone_used: 0, created: 0, active: true, isEnv: true }));
    return json(res, 200, { ok: true, tokens: list.concat(envTokens) });
  }
  // POST /admin/api/tokens  {"name":"客户A","email_limit":50,"phone_limit":50}
  if (p === '/admin/api/tokens' && req.method === 'POST') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const bodyTxt = await readBody(req);
    let body = {}; try { body = JSON.parse(bodyTxt || '{}'); } catch (e) {}
    const key = genTokenKey();
    CUSTOM_TOKENS[key] = { name: String(body.name || '未命名').slice(0, 50), email_limit: parseInt(body.email_limit, 10) || 0, phone_limit: parseInt(body.phone_limit, 10) || 0, email_used: 0, phone_used: 0, day: dayKey(), created: Date.now(), active: true };
    saveJSONFile(TOKENS_FILE, CUSTOM_TOKENS);
    return json(res, 200, { ok: true, token: key, ...CUSTOM_TOKENS[key] });
  }
  // POST /admin/api/tokens/toggle {"key":"...","active":false}
  if (p === '/admin/api/tokens/toggle') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const bodyTxt = await readBody(req);
    let body = {}; try { body = JSON.parse(bodyTxt || '{}'); } catch (e) {}
    const t = CUSTOM_TOKENS[body.key];
    if (!t) return json(res, 404, { error: 'token not found' });
    t.active = body.active !== false;
    saveJSONFile(TOKENS_FILE, CUSTOM_TOKENS);
    return json(res, 200, { ok: true });
  }
  // POST /admin/api/tokens/limit {"key":"...","email_limit":50,"phone_limit":50}
  if (p === '/admin/api/tokens/limit') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const bodyTxt = await readBody(req);
    let body = {}; try { body = JSON.parse(bodyTxt || '{}'); } catch (e) {}
    const t = CUSTOM_TOKENS[body.key];
    if (!t) return json(res, 404, { error: 'token not found' });
    if (body.email_limit !== undefined) t.email_limit = parseInt(body.email_limit, 10) || 0;
    if (body.phone_limit !== undefined) t.phone_limit = parseInt(body.phone_limit, 10) || 0;
    saveJSONFile(TOKENS_FILE, CUSTOM_TOKENS);
    return json(res, 200, { ok: true });
  }
  // DELETE /admin/api/tokens {"key":"..."}
  if (p === '/admin/api/tokens/delete') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const bodyTxt = await readBody(req);
    let body = {}; try { body = JSON.parse(bodyTxt || '{}'); } catch (e) {}
    delete CUSTOM_TOKENS[body.key];
    saveJSONFile(TOKENS_FILE, CUSTOM_TOKENS);
    return json(res, 200, { ok: true });
  }
  // GET /admin/api/backup  下载完整备份 (tokens + usage)
  if (p === '/admin/api/backup') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const backup = { exportedAt: Date.now(), tokens: CUSTOM_TOKENS, usage: USAGE_LOG };
    const data = JSON.stringify(backup, null, 2);
    res.statusCode = 200;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.setHeader('content-disposition', 'attachment; filename="co_backup_' + dayKey() + '.json"');
    return res.end(data);
  }
  // POST /admin/api/backup/restore  恢复备份 (tokens + usage)
  if (p === '/admin/api/backup/restore') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const bodyTxt = await readBody(req);
    let body = {};
    try { body = JSON.parse(bodyTxt || '{}'); } catch (e) {}
    const data = body.data || body;
    if (!data || (!data.tokens && !data.usage)) return json(res, 400, { error: 'invalid backup data', hint: 'POST JSON {"data": <备份文件内容>}' });
    if (data.tokens) { CUSTOM_TOKENS = Object.assign({}, data.tokens); saveJSONFile(TOKENS_FILE, CUSTOM_TOKENS); }
    if (data.usage) { USAGE_LOG = data.usage.slice(-20000); saveJSONFile(USAGE_FILE, USAGE_LOG); }
    return json(res, 200, { ok: true, tokens: Object.keys(CUSTOM_TOKENS).length, usage: USAGE_LOG.length });
  }

  // GET /admin/api/warmup  查看 cookie 预热状态
  if (p === '/admin/api/warmup') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const accountStatus = SESSIONS.map(s => {
      const bad = warmupState.bad.find(b => b.email === s.email);
      return { email: s.email, userId: s.userId, credit: s.credit, phoneCredit: s.phoneCredit, lastWarmupBad: bad ? bad.reason : null };
    });
    return json(res, 200, { ok: true, lastRun: warmupState.lastRun, ok: warmupState.ok, bad: warmupState.bad, accounts: accountStatus });
  }

  // GET /admin/api/usage?key=xxx&days=1&date=YYYY-MM-DD  查询日志 (可按口令/天数/日期过滤)
  if (p === '/admin/api/usage') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const key = u.searchParams.get('key') || '';
    const days = parseInt(u.searchParams.get('days') || '1', 10) || 1;
    const date = u.searchParams.get('date') || '';
    const since = date ? new Date(date + 'T00:00:00').getTime() : (Date.now() - days * 86400000);
    const until = date ? since + 86400000 : Date.now();
    let rows = USAGE_LOG.filter(x => x.ts >= since && x.ts < until && (!key || x.token === key));
    // 按时间倒序
    rows = rows.sort((a, b) => b.ts - a.ts).slice(0, 2000);
    return json(res, 200, { ok: true, count: rows.length, rows });
  }
  // GET /admin/api/usage/export?key=xxx&days=1&format=csv  导出日志 CSV (可指定日期)
  if (p === '/admin/api/usage/export') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const key = u.searchParams.get('key') || '';
    const days = parseInt(u.searchParams.get('days') || '1', 10) || 1;
    const date = u.searchParams.get('date') || ''; // YYYY-MM-DD 精确日期(优先)
    const since = date ? new Date(date + 'T00:00:00').getTime() : (Date.now() - days * 86400000);
    const until = date ? since + 86400000 : Date.now();
    let rows = USAGE_LOG.filter(x => x.ts >= since && x.ts < until && (!key || x.token === key));
    rows = rows.sort((a, b) => a.ts - b.ts);
    // CSV
    const esc = v => { v = String(v == null ? '' : v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
    const header = ['时间', '口令', '名称', 'IP', '类型', 'Profile', '邮箱', '电话', '结果'];
    const lines = [header.join(',')].concat(rows.map(r => [
      new Date(r.ts).toLocaleString('zh-CN', { hour12: false }),
      r.token || '', r.name || '', r.ip || '',
      r.kind || '', r.profile || '', r.email || '', r.phone || '',
      r.ok ? '查到' : (r.restricted ? '受限' : '无')
    ].map(esc).join(',')));
    const csv = '\ufeff' + lines.join('\n');
    const fname = 'usage_' + (date || new Date().toISOString().slice(0, 10)) + (key ? '_' + key.slice(-6) : '') + '.csv';
    res.statusCode = 200;
    res.setHeader('content-type', 'text/csv; charset=utf-8');
    res.setHeader('content-disposition', 'attachment; filename="' + fname + '"');
    return res.end(csv);
  }
  // GET /admin/api/stats  总览: 今日查询数/账号额度
  if (p === '/admin/api/stats') {
    if (!masterOK(req, u)) return json(res, 401, { error: 'master token required' });
    const today = dayKey();
    const since = Date.now() - 86400000;
    const todayRows = USAGE_LOG.filter(x => x.ts >= since);
    const byKind = {};
    for (const r of todayRows) byKind[r.kind] = (byKind[r.kind] || 0) + 1;
    return json(res, 200, { ok: true, today_queries: todayRows.length, by_kind: byKind, accounts: stats(), total_email_credit: totalEmailCredit(), total_phone_credit: totalPhoneCredit() });
  }

  // 404
  return json(res, 404, { error: 'not found', routes: ['/health', '/api/credits', '/api/reveal', '/api/reveal/batch', '/admin/api/*'] });
});

server.listen(PORT, () => {
  console.log(`ContactOut API 服务已启动: http://localhost:${PORT}`);
  console.log(`账号数: ${SESSIONS.length}, 总邮箱额度: ${totalEmailCredit()}`);
  console.log(`访问令牌: ${TOKENS.length ? '已设置' : '未设置(开放)'}`);
});

// 优雅关闭
process.on('SIGINT', () => { server.close(); process.exit(0); });
