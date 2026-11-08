/* JUST LIFE 보장분석 — 계정 · 활동 기록 서버
   저장 위치: Netlify Blobs (store "justlife")
     config            { secret, admin: {salt, hash, ver}, fails }
     users             { [id]: { name, salt, hash, ver, active, created, lastLogin, fails, lockUntil } }
     log/<YYYY-MM-DD>/<id>  [ { t, a, d } ]   ← 고객 보고서 내용은 저장하지 않음 (가린 고객명 · 건수만)
*/
import crypto from "node:crypto";

const SETUP_HASH = "11a1ea3f9be052be2619fa5191dbef97657d2cda3615a54c2a3054097f21f506";            // 처음 관리자 설정 코드 (sha256)
const TEAM_TTL = 7 * 24 * 3600e3, ADMIN_TTL = 4 * 3600e3;
const MAX_FAILS = 5, LOCK_MS = 10 * 60e3;
const ACTIONS = { login: "로그인", pdf: "PDF 불러오기", save: "고객 파일 저장", open: "고객 파일 열기", print: "인쇄/PDF", new: "새 보고서", plan: "플랜 저장", hira: "심평원 분석", hiraprint: "고지사항 인쇄", prop: "가입제안서", logout: "로그아웃" };

const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const err = (msg, status = 400) => json({ error: msg }, status);
const sha256 = s => crypto.createHash("sha256").update(s).digest("hex");
const hashPw = (pw, salt = crypto.randomBytes(16).toString("hex")) => ({ salt, hash: crypto.scryptSync(String(pw), salt, 32).toString("hex") });
const checkPw = (pw, rec) => { if (!rec || !rec.salt) return false; const h = crypto.scryptSync(String(pw), rec.salt, 32); const t = Buffer.from(rec.hash, "hex"); return t.length === h.length && crypto.timingSafeEqual(h, t); };
const kstDate = (ms = Date.now()) => new Date(ms + 9 * 3600e3).toISOString().slice(0, 10);
const validId = id => /^[a-z0-9._-]{2,30}$/.test(id);
const clean = (s, n = 80) => String(s ?? "").replace(/[\u0000-\u001f]/g, " ").slice(0, n);

export function makeApi(store) {
  const get = async (k, d) => (await store.get(k, { type: "json" })) ?? d;
  const set = (k, v) => store.setJSON(k, v);

  async function config() {
    let c = await get("config", null);
    if (!c) { c = { secret: crypto.randomBytes(32).toString("hex"), admin: null }; await set("config", c); }
    return c;
  }
  const b64 = o => Buffer.from(JSON.stringify(o)).toString("base64url");
  const sign = (c, payload) => { const p = b64(payload); return p + "." + crypto.createHmac("sha256", c.secret).update(p).digest("base64url"); };
  function verify(c, token) {
    if (!token || !token.includes(".")) return null;
    const [p, s] = token.split(".");
    const want = crypto.createHmac("sha256", c.secret).update(p).digest("base64url");
    if (s.length !== want.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(want))) return null;
    const o = JSON.parse(Buffer.from(p, "base64url").toString());
    return o.exp > Date.now() ? o : null;
  }
  const bearer = req => (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");

  async function teamAuth(req) {
    const c = await config(), t = verify(c, bearer(req));
    if (!t || t.role !== "team") return null;
    const users = await get("users", {}), u = users[t.u];
    if (!u || !u.active || u.ver !== t.v) return null;
    return { id: t.u, name: u.name };
  }
  async function adminAuth(req) {
    const c = await config(), t = verify(c, bearer(req));
    return t && t.role === "admin" && c.admin && t.v === c.admin.ver ? c : null;
  }
  async function addLog(id, a, d = "") {
    const k = `log/${kstDate()}/${id}`, list = await get(k, []);
    list.push({ t: Date.now(), a, d: clean(d, 120) });
    await set(k, list.slice(-500));
  }

  return async function handle(req) {
    const url = new URL(req.url), path = url.pathname.replace(/^\/(\.netlify\/functions\/)?api\/?/, "").replace(/^api\//, "");
    const method = req.method;
    let body = {};
    if (method === "POST") { try { body = await req.json(); } catch (e) { body = {}; } }

    /* ---------- 팀원 ---------- */
    if (path === "login" && method === "POST") {
      const id = String(body.id || "").trim().toLowerCase(), users = await get("users", {}), u = users[id];
      if (!u) return err("아이디 또는 비밀번호가 맞지 않아요", 401);
      if (!u.active) return err("사용이 중지된 아이디예요. 관리자에게 문의하세요", 403);
      if (!checkPw(body.pw, u)) return err("아이디 또는 비밀번호가 맞지 않아요", 401);
      u.fails = 0; u.lockUntil = 0; u.lastLogin = Date.now(); await set("users", users);
      await addLog(id, "login");
      const c = await config();
      return json({ token: sign(c, { role: "team", u: id, v: u.ver, exp: Date.now() + TEAM_TTL }), id, name: u.name });
    }
    if (path === "me") { const me = await teamAuth(req); return me ? json(me) : err("다시 로그인해 주세요", 401); }
    if (path === "log" && method === "POST") {
      const me = await teamAuth(req); if (!me) return err("다시 로그인해 주세요", 401);
      if (!ACTIONS[body.a]) return err("알 수 없는 활동");
      await addLog(me.id, body.a, body.d); return json({ ok: true });
    }

    /* ---------- 관리자 ---------- */
    if (path === "admin/status") { const c = await config(); return json({ setup: !!c.admin }); }
    if (path === "admin/setup" && method === "POST") {
      const c = await config();
      if (c.admin) return err("이미 설정되어 있어요");
      if (sha256(String(body.code || "").trim().toUpperCase()) !== SETUP_HASH) return err("설정 코드가 맞지 않아요", 401);
      if (String(body.pw || "").length < 8) return err("관리자 비밀번호는 8자 이상으로 해 주세요");
      c.admin = { ...hashPw(body.pw), ver: 1 }; await set("config", c);
      return json({ token: sign(c, { role: "admin", v: 1, exp: Date.now() + ADMIN_TTL }) });
    }
    if (path === "admin/reset" && method === "POST") {          // 관리자 비밀번호 분실 → 설정 코드로 새로 정하기
      const c = await config();
      if (sha256(String(body.code || "").trim().toUpperCase()) !== SETUP_HASH) return err("설정 코드가 맞지 않아요", 401);
      if (String(body.pw || "").length < 8) return err("관리자 비밀번호는 8자 이상으로 해 주세요");
      c.admin = { ...hashPw(body.pw), ver: ((c.admin && c.admin.ver) || 0) + 1 }; c.fails = 0; c.lockUntil = 0; await set("config", c);
      return json({ token: sign(c, { role: "admin", v: c.admin.ver, exp: Date.now() + ADMIN_TTL }) });
    }
    if (path === "admin/login" && method === "POST") {
      const c = await config();
      if (!c.admin) return err("먼저 관리자 비밀번호를 설정해 주세요", 409);
      if (!checkPw(body.pw, c.admin)) return err("비밀번호가 맞지 않아요", 401);
      if (c.lockUntil || c.fails) { c.fails = 0; c.lockUntil = 0; await set("config", c); }
      return json({ token: sign(c, { role: "admin", v: c.admin.ver, exp: Date.now() + ADMIN_TTL }) });
    }
    if (path.startsWith("admin/")) {
      const c = await adminAuth(req); if (!c) return err("관리자 로그인이 필요해요", 401);
      const users = await get("users", {});
      const pub = () => Object.entries(users).map(([id, u]) => ({ id, name: u.name, active: u.active, created: u.created, lastLogin: u.lastLogin || null, locked: false })).sort((a, b) => a.name.localeCompare(b.name, "ko"));

      if (path === "admin/users" && method === "GET") return json({ users: pub() });
      if (path === "admin/users" && method === "POST") {
        const id = String(body.id || "").trim().toLowerCase(), name = clean(body.name, 30).trim();
        if (!validId(id)) return err("아이디는 영문 소문자·숫자 2~30자로 해 주세요");
        if (!name) return err("이름을 입력해 주세요");
        if (users[id]) return err("이미 있는 아이디예요");
        if (String(body.pw || "").length < 6) return err("비밀번호는 6자 이상으로 해 주세요");
        users[id] = { name, ...hashPw(body.pw), ver: 1, active: true, created: Date.now() };
        await set("users", users); return json({ users: pub() });
      }
      if (path === "admin/users/update" && method === "POST") {
        const u = users[body.id]; if (!u) return err("없는 아이디예요", 404);
        if (body.name != null) u.name = clean(body.name, 30).trim() || u.name;
        if (body.pw != null) { if (String(body.pw).length < 6) return err("비밀번호는 6자 이상으로 해 주세요"); Object.assign(u, hashPw(body.pw)); u.ver++; u.fails = 0; u.lockUntil = 0; }
        if (body.active != null) { u.active = !!body.active; if (!u.active) u.ver++; }
        if (body.unlock) { u.fails = 0; u.lockUntil = 0; }
        await set("users", users); return json({ users: pub() });
      }
      if (path === "admin/users/delete" && method === "POST") {
        if (!users[body.id]) return err("없는 아이디예요", 404);
        delete users[body.id]; await set("users", users); return json({ users: pub() });
      }
      if (path === "admin/logs" && method === "GET") {
        const from = url.searchParams.get("from") || kstDate(Date.now() - 6 * 864e5), to = url.searchParams.get("to") || kstDate(), who = url.searchParams.get("user") || "";
        const { blobs } = await store.list({ prefix: "log/" });
        const keys = blobs.map(b => b.key).filter(k => { const [, d, id] = k.split("/"); return d >= from && d <= to && (!who || id === who); });
        const rows = [];
        for (const k of keys) { const id = k.split("/")[2]; for (const e of await get(k, [])) rows.push({ t: e.t, id, name: users[id]?.name || id + " (삭제됨)", a: e.a, label: ACTIONS[e.a] || e.a, d: e.d }); }
        rows.sort((a, b) => b.t - a.t);
        return json({ from, to, rows: rows.slice(0, 3000), total: rows.length, actions: ACTIONS });
      }
      if (path === "admin/password" && method === "POST") {
        if (!checkPw(body.old, c.admin)) return err("현재 비밀번호가 맞지 않아요", 401);
        if (String(body.pw || "").length < 8) return err("새 비밀번호는 8자 이상으로 해 주세요");
        c.admin = { ...hashPw(body.pw), ver: c.admin.ver + 1 }; await set("config", c);
        return json({ token: sign(c, { role: "admin", v: c.admin.ver, exp: Date.now() + ADMIN_TTL }) });
      }
      return err("없는 기능이에요", 404);
    }
    return err("없는 주소예요", 404);
  };
}
