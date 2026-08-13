// Ahmed KeyMaster — Fixed & Modified server
// Changes vs original:
//  - Anonymous users can encrypt (no login required). A guest session is
//    created on the fly so their files are tracked.
//  - Encryption without an IP works for everyone (no IP lock).
//  - Removed the free-trial package + trial redemption endpoint.
//  - Subscription page now returns days_left / expires_ms (fixes NaN).
//  - New endpoints for the user's own encrypted files with a stop toggle:
//      GET  /api/my-files
//      POST /api/my-files/:id/stop   (revokes the activation)
//      POST /api/my-files/:id/start  (re-enables it)
//  - Owner activations page reads the same list across all users.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3001;
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'database.json');

let db = {
  users: [],
  packages: [
    { id: 2, name: 'الباقة الأساسية (Basic)', price: 49, days: 30, desc: 'حماية 5 سكربتات وتحديد IP محدود' },
    { id: 3, name: 'باقة VIP الاحترافية (Pro)', price: 99, days: 90, desc: 'حماية غير محدودة للسكربتات', popular: true },
    { id: 4, name: 'الباقة المدى الحياة (Lifetime)', price: 249, days: 3650, desc: 'وصول دائم لجميع التحديثات' }
  ],
  orders: [],
  files: [],   // encrypted scripts (owned by user_id) with active flag
  codes: [],
  reviews: [],
  blacklist: [],
  logs: [],
  settings: {
    brand: 'Ahmed KeyMaster',
    discord_link: 'https://discord.gg/cfw3',
    store_url: 'https://legendcfw.com',
    bot_connected: true,
    bot_configured: true,
    platform: 'Node.js',
    node: process.version,
  },
  announcement: { text: '📢 مرحباً بكم في منصة Ahmed Dev KeyMaster' }
};

if (fs.existsSync(DATA_FILE)) {
  try { db = { ...db, ...JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) }; } catch (e) {}
}
function saveData() { try { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); } catch (e) {} }

const sessions = new Map();
function newToken() { return crypto.randomBytes(16).toString('hex'); }
function getOwner() { return db.users.find(u => u.role === 'owner'); }
function hashPass(p) { return crypto.createHash('sha256').update(String(p)).digest('hex'); }

function parseCookies(req) {
  const out = {};
  const c = req.headers.cookie || '';
  c.split(';').forEach(s => { const i = s.indexOf('='); if (i > 0) out[s.slice(0, i).trim()] = decodeURIComponent(s.slice(i + 1).trim()); });
  return out;
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.svg': 'image/svg+xml'
};

function genCode(prefix) {
  const rand = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `${prefix || 'KEY'}-${rand()}-${rand()}`;
}

function daysLeft(iso) {
  if (!iso) return null;
  const ms = new Date(iso).getTime();
  if (!ms) return null;
  return Math.max(0, Math.ceil((ms - Date.now()) / 86400000));
}

function subInfo(u) {
  if (!u || !u.subscription) return null;
  const s = u.subscription;
  const expires_ms = s.expires_at ? new Date(s.expires_at).getTime() : null;
  return {
    active: !!s.active,
    plan: s.plan || '—',
    expires_at: s.expires_at || null,
    expires_ms,
    days_left: daysLeft(s.expires_at),
    allowed_ips: s.allowed_ips || ['*'],
    encrypts_used: u.enc_count || 0
  };
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  let bodyStr = '';
  req.on('data', c => bodyStr += c);
  req.on('end', () => {
    let body = {};
    if (bodyStr) { try { body = JSON.parse(bodyStr); } catch (e) {} }

    const cookies = parseCookies(req);
    let token = cookies['sid'] || req.headers['x-session'] || '';
    let uid = sessions.get(token);
    let currentUser = uid ? db.users.find(u => u.id === uid) : null;

    const extraCookies = [];
    const sendJson = (data, code = 200, extraHeaders = {}) => {
      const headers = { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders };
      if (extraCookies.length) headers['Set-Cookie'] = extraCookies;
      res.writeHead(code, headers);
      res.end(JSON.stringify(data));
    };
    const setSession = (userId) => {
      const t = newToken();
      sessions.set(t, userId);
      extraCookies.push(`sid=${t}; Path=/; Max-Age=${60 * 60 * 24 * 30}; SameSite=Lax`);
      return t;
    };
    const ensureGuest = () => {
      if (currentUser) return currentUser;
      const u = {
        id: db.users.length + 1,
        email: `guest_${Date.now()}@guest.local`,
        username: `ضيف ${db.users.length + 1}`,
        name: `ضيف`,
        role: 'guest',
        pass: '',
        created_at: new Date().toISOString(),
        enc_count: 0,
        subscription: { active: true, plan: 'ضيف (تشفير عام)', expires_at: null, allowed_ips: ['*'] }
      };
      db.users.push(u);
      setSession(u.id);
      currentUser = u;
      saveData();
      return u;
    };
    const requireOwner = () => currentUser && currentUser.role === 'owner';

    // ============ AUTH MODE ============
    if (pathname === '/api/auth-mode') {
      return sendJson({ ownerExists: !!getOwner() });
    }

    // ============ REGISTER (first user = owner) ============
    if (pathname === '/api/register' && req.method === 'POST') {
      const email = (body.email || body.username || '').trim().toLowerCase();
      const password = body.password || '';
      if (!email || !password) return sendJson({ ok: false, message: 'الإيميل وكلمة المرور مطلوبين' }, 400);
      if (getOwner()) return sendJson({ ok: false, message: 'الأونر موجود بالفعل — استخدم كود تفعيل' }, 403);
      const user = {
        id: db.users.length + 1,
        email, username: email, name: email.split('@')[0],
        role: 'owner',
        pass: hashPass(password),
        created_at: new Date().toISOString(),
        enc_count: 0,
        subscription: { active: true, plan: 'Owner', expires_at: '2099-12-31T23:59:59Z', allowed_ips: ['*'] }
      };
      db.users.push(user);
      saveData();
      setSession(user.id);
      return sendJson({ ok: true, user, message: '🎉 تم إنشاء حساب الأونر' });
    }

    // ============ OWNER LOGIN ============
    if (pathname === '/api/login' && req.method === 'POST') {
      const email = (body.email || body.username || '').trim().toLowerCase();
      const password = body.password || '';
      const owner = getOwner();
      if (!owner) return sendJson({ ok: false, message: 'لا يوجد أونر بعد — أنشئ الحساب أولاً' }, 404);
      if (owner.email !== email || owner.pass !== hashPass(password)) {
        return sendJson({ ok: false, message: 'بيانات الأونر غير صحيحة' }, 401);
      }
      setSession(owner.id);
      return sendJson({ ok: true, user: owner });
    }

    // ============ ACTIVATION CODE ============
    if (pathname === '/api/activate' && req.method === 'POST') {
      const code = (body.code || '').trim();
      if (!code) return sendJson({ ok: false, message: 'أدخل كود التفعيل' }, 400);
      const entry = db.codes.find(c => c.code.toUpperCase() === code.toUpperCase());
      if (!entry) return sendJson({ ok: false, message: 'كود غير موجود' }, 404);
      if (entry.used) return sendJson({ ok: false, message: 'الكود مستخدم مسبقاً' }, 409);
      entry.used = true;
      entry.used_at = new Date().toISOString();
      const days = Number(entry.days) || 30;
      const user = {
        id: db.users.length + 1,
        email: `user_${Date.now()}@code.local`,
        username: `عميل ${entry.code}`,
        name: `عميل ${entry.code}`,
        role: 'user',
        pass: '',
        code_used: entry.code,
        created_at: new Date().toISOString(),
        enc_count: 0,
        subscription: {
          active: true,
          plan: entry.custom ? 'Custom Plan' : `كود (${days} يوم)`,
          expires_at: new Date(Date.now() + days * 86400000).toISOString(),
          allowed_ips: ['*']
        }
      };
      db.users.push(user);
      entry.used_by = user.id;
      entry.used_by_name = user.username;
      saveData();
      setSession(user.id);
      return sendJson({ ok: true, user, message: '✅ تم التفعيل — أهلاً بك' });
    }

    if (pathname === '/api/logout') {
      if (token) sessions.delete(token);
      return sendJson({ ok: true }, 200, { 'Set-Cookie': 'sid=; Path=/; Max-Age=0' });
    }

    // ============ ME ============
    if (pathname === '/api/me') {
      if (!currentUser) return sendJson({ user: null });
      const info = subInfo(currentUser);
      return sendJson({
        user: currentUser,
        subscription: info,
        subscriptions: info ? [info] : [],
        encryptCount: currentUser.enc_count || 0
      });
    }

    if (pathname === '/api/packages') return sendJson(db.packages);
    if (pathname === '/api/reviews') return sendJson({ reviews: db.reviews, average: 5.0, count: db.reviews.length });

    // ============ MY FILES (own encrypted scripts) ============
    if (pathname === '/api/my-files') {
      if (!currentUser) return sendJson([]);
      const mine = db.files.filter(f => f.user_id === currentUser.id);
      return sendJson(mine);
    }
    const stopMatch = pathname.match(/^\/api\/my-files\/([^/]+)\/(stop|start|delete)$/);
    if (stopMatch && req.method === 'POST') {
      if (!currentUser) return sendJson({ ok: false, message: 'سجّل الدخول أولاً' }, 401);
      const id = stopMatch[1];
      const action = stopMatch[2];
      const idx = db.files.findIndex(f => String(f.id) === String(id) && (f.user_id === currentUser.id || currentUser.role === 'owner'));
      if (idx < 0) return sendJson({ ok: false, message: 'غير موجود' }, 404);
      if (action === 'delete') { db.files.splice(idx, 1); }
      else db.files[idx].active = (action === 'start');
      saveData();
      return sendJson({ ok: true });
    }

    // ============ ADMIN (owner-only) ============
    if (pathname.startsWith('/api/admin/')) {
      if (!requireOwner()) return sendJson({ ok: false, message: 'صلاحيات الأونر مطلوبة' }, 403);

      if (pathname === '/api/admin/codes') {
        if (req.method === 'POST') {
          const days = Number(body.days) || 30;
          const custom = (body.custom_code || '').trim();
          const count = Math.max(1, Math.min(200, Number(body.count) || 1));
          const prefix = (body.prefix || 'KEY').trim().toUpperCase().replace(/[^A-Z0-9]/g, '') || 'KEY';
          const created = [];
          if (custom) {
            if (db.codes.some(c => c.code.toUpperCase() === custom.toUpperCase())) {
              return sendJson({ ok: false, message: 'هذا الكود موجود بالفعل' }, 409);
            }
            const c = { id: db.codes.length + 1, code: custom, days, used: false, custom: true, created_at: new Date().toISOString() };
            db.codes.push(c); created.push(c.code);
          } else {
            for (let i = 0; i < count; i++) {
              const c = { id: db.codes.length + 1, code: genCode(prefix), days, used: false, custom: false, created_at: new Date().toISOString() };
              db.codes.push(c); created.push(c.code);
            }
          }
          saveData();
          return sendJson({ ok: true, codes: created });
        }
        return sendJson(db.codes.map(c => ({
          id: c.id, code: c.code, package_name: c.custom ? 'مخصص' : `${c.days} يوم`,
          status: c.used ? 'used' : 'unused', used_by_name: c.used_by_name || null,
          created_at: c.created_at
        })));
      }

      const burnMatch = pathname.match(/^\/api\/admin\/codes\/(\d+)\/burn$/);
      if (burnMatch) {
        const id = Number(burnMatch[1]);
        const c = db.codes.find(x => x.id === id);
        if (!c) return sendJson({ ok: false, message: 'غير موجود' }, 404);
        c.used = true; c.burned = true; saveData();
        return sendJson({ ok: true });
      }

      if (pathname === '/api/admin/users') return sendJson(db.users);
      if (pathname === '/api/admin/files') return sendJson(db.files);
      if (pathname === '/api/admin/stats') return sendJson({
        total_users: db.users.length, files: db.files.length,
        active_files: db.files.filter(f => f.active !== false).length,
        stopped_files: db.files.filter(f => f.active === false).length,
        total_orders: db.orders.length,
        revenue: db.orders.reduce((a, o) => a + (o.amount || 0), 0),
      });
      if (pathname === '/api/admin/settings') return sendJson(db.settings);
    }

    // ============ ENCRYPT ============
    if (pathname === '/api/encrypt' && req.method === 'POST') {
      // Allow anonymous: auto-create a guest session so the file is tracked.
      const user = ensureGuest();

      const userLuaCode = body.src || body.code || 'print("Protected Script Active")';
      const targetIp = ((body.allowed_ip || body.ip || '') + '').trim();
      const fileName = body.file_name || body.script_name || 'script.lua';

      const bcVar  = '_' + crypto.randomBytes(4).toString('hex');
      const decVar = '_' + crypto.randomBytes(4).toString('hex');
      const execVar= '_' + crypto.randomBytes(4).toString('hex');
      const xorFn  = '_' + crypto.randomBytes(4).toString('hex');
      const xorKey = Math.floor(Math.random() * 200) + 20;

      const bytes = Array.from(Buffer.from(userLuaCode, 'utf8')).map(b => b ^ xorKey).join(',');

      // IP lock only when the user provided one; empty = works for everyone
      const hasIp = targetIp && targetIp !== '*';
      const ipCheck = hasIp
        ? `
local _ahmed_ok = false
local _ahmed_target = "${targetIp}"
local function _ahmed_abort(msg)
  print("[Ahmed] "..tostring(msg))
  if os and os.exit then pcall(os.exit, 0) end
  while true do end
end
local function _ahmed_check(ip)
  ip = tostring(ip or ""):gsub("%s+", "")
  if ip == "" then _ahmed_abort("no ip") end
  if ip == "127.0.0.1" or ip == "::1" or ip == "localhost" or ip:match("^192%.168%.") or ip:match("^10%.") or ip:match("^172%.1[6-9]%.") or ip:match("^172%.2[0-9]%.") or ip:match("^172%.3[0-1]%.") then
    _ahmed_abort("localhost/private blocked")
  end
  if ip ~= _ahmed_target then _ahmed_abort("ip mismatch ("..ip..")") end
  _ahmed_ok = true
end
if PerformHttpRequest then
  PerformHttpRequest("https://api.ipify.org", function(_c, _ip)
    if _c ~= 200 or not _ip then _ahmed_abort("http fail") end
    _ahmed_check(_ip)
  end, "GET")
  local _t0 = (GetGameTimer and GetGameTimer()) or 0
  if Wait then while not _ahmed_ok do Wait(50) if GetGameTimer and (GetGameTimer()-_t0) > 8000 then _ahmed_abort("timeout") end end end
else
  local ok, sock = pcall(function()
    local h = io.popen and io.popen("curl -s https://api.ipify.org 2>/dev/null || wget -qO- https://api.ipify.org 2>/dev/null")
    if not h then return nil end
    local s = h:read("*a"); h:close(); return s
  end)
  if not ok or not sock or sock == "" then _ahmed_abort("no http (localhost blocked)") end
  _ahmed_check(sock)
end
if not _ahmed_ok then _ahmed_abort("not verified") end
`.trim() + '\n'
        : '';


      const obfuscatedCode =
`-- Ahmed KeyMaster VM (auto-generated)
${ipCheck}local ${xorFn} = (bit32 and bit32.bxor) or function(a,b) local r,p=0,1 for i=0,7 do local x,y=a%2,b%2 if x~=y then r=r+p end a,b,p=(a-x)/2,(b-y)/2,p*2 end return r end
local ${bcVar} = {${bytes}}
local ${decVar} = {}
for i = 1, #${bcVar} do ${decVar}[i] = string.char(${xorFn}(${bcVar}[i], ${xorKey})) end
local ${execVar}, ${execVar}_err = load(table.concat(${decVar}), "=Ahmed", "t", _ENV or getfenv())
if ${execVar} then return ${execVar}() else print("[Ahmed] load error: "..tostring(${execVar}_err)) end
`;

      const newFile = {
        id: 'F-' + Date.now().toString(36).toUpperCase(),
        user_id: user.id,
        owner_name: user.username,
        name: fileName,
        size_kb: Number((Buffer.byteLength(obfuscatedCode) / 1024).toFixed(1)),
        ip: hasIp ? targetIp : '',
        active: true,
        encrypted_code: obfuscatedCode,
        encrypted_at: new Date().toISOString(),
      };
      db.files.unshift(newFile);
      user.enc_count = (user.enc_count || 0) + 1;
      saveData();
      return sendJson({
        ok: true, code: obfuscatedCode, fileName, file_id: newFile.id,
        message: '🔒 تم تشفير السكربت بنجاح'
      });
    }

    // ============ REDEEM (kept for compat) ============
    if (pathname === '/api/redeem' && req.method === 'POST') {
      const code = (body.code || '').trim();
      const entry = db.codes.find(c => c.code.toUpperCase() === code.toUpperCase());
      if (!entry) return sendJson({ ok: false, message: 'كود غير موجود' }, 404);
      if (entry.used) return sendJson({ ok: false, message: 'مستخدم مسبقاً' }, 409);
      entry.used = true;
      if (currentUser) currentUser.subscription = {
        active: true, plan: `كود (${entry.days} يوم)`,
        expires_at: new Date(Date.now() + entry.days * 86400000).toISOString(),
        allowed_ips: ['*']
      };
      saveData();
      return sendJson({ ok: true, message: '✅ تم التفعيل' });
    }

    // ============ STATIC ============
    let filePath = path.join(ROOT, pathname === '/' ? 'index.html' : pathname);
    if (!filePath.startsWith(ROOT)) { res.writeHead(403); return res.end('Forbidden'); }
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) filePath = path.join(ROOT, 'index.html');
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(`Ahmed KeyMaster running on http://localhost:${PORT}`);
});
