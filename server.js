// Finlete CRM server — no dependencies, just Node (18+).
// Serves the app from ./public, persists data to ./data.json,
// and syncs prospect ranks from FanGraphs + MLB Pipeline.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

const PORT = process.env.PORT || 4321;
// In the cloud, DATA_DIR points at a persistent volume; locally data.json sits next to the code
const DATA_FILE = process.env.DATA_DIR
  ? path.join(process.env.DATA_DIR, 'data.json')
  : path.join(__dirname, 'data.json');
// Set CRM_PASSWORD to require login (always set it for cloud deploys); empty = no auth (local use)
const PASSWORD = process.env.CRM_PASSWORD || '';
const PUBLIC_DIR = path.join(__dirname, 'public');
const SYNC_INTERVAL_DAYS = 7;
// Generic UA on purpose: Cloudflare rejects curl claiming to be Chrome (TLS fingerprint mismatch)
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)';

const EMPTY = { prospects: [], agents: [], opportunities: [], lastSync: null };

// ---------- Auth (only active when CRM_PASSWORD is set) ----------

const AUTH_SECRET = crypto.createHash('sha256').update('finlete-crm|' + PASSWORD).digest();
const sign = (s) => crypto.createHmac('sha256', AUTH_SECRET).update(s).digest('hex');

function makeAuthCookie(req) {
  const exp = Date.now() + 90 * 24 * 3600 * 1000; // stay logged in for 90 days
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `crm_auth=${exp}.${sign(String(exp))}; Path=/; HttpOnly; Max-Age=7776000; SameSite=Lax${secure}`;
}

function isAuthed(req) {
  const m = /(?:^|;\s*)crm_auth=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return false;
  const [exp, sig] = m[1].split('.');
  if (!exp || !sig || +exp < Date.now()) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(exp)));
  } catch {
    return false;
  }
}

// Brute-force guard: 20 password attempts per IP per hour
const attempts = new Map();
function tooManyAttempts(ip) {
  const now = Date.now();
  const a = attempts.get(ip) || { count: 0, reset: now + 3600 * 1000 };
  if (now > a.reset) { a.count = 0; a.reset = now + 3600 * 1000; }
  a.count++;
  attempts.set(ip, a);
  return a.count > 20;
}

const LOGIN_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Finlete CRM — Log in</title>
<style>body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f6f7f9;
display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#fff;border:1px solid #e4e7ec;border-radius:16px;padding:36px;width:320px;text-align:center}
h1{font-size:19px;margin:0 0 4px}h1 span{color:#2563eb}p{color:#6b7486;font-size:13px;margin:0 0 20px}
input{width:100%;box-sizing:border-box;padding:11px 12px;font-size:15px;border:1px solid #e4e7ec;border-radius:8px;outline:none;margin-bottom:12px}
input:focus{border-color:#2563eb}button{width:100%;padding:11px;border:none;border-radius:8px;background:#2563eb;color:#fff;font-size:15px;font-weight:600;cursor:pointer}
#err{color:#dc2626;font-size:13px;min-height:18px;margin-top:10px}</style></head>
<body><form class="box" onsubmit="go(event)"><h1>Finlete <span>CRM</span></h1><p>Enter the team password</p>
<input type="password" id="pw" autofocus autocomplete="current-password"><button>Log in</button><div id="err"></div></form>
<script>async function go(e){e.preventDefault();
const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('pw').value})});
if(r.ok)location.reload();else document.getElementById('err').textContent=r.status===429?'Too many attempts — try again later.':'Wrong password.';}
</script></body></html>`;

function loadData() {
  try {
    const d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return { ...EMPTY, ...d };
  } catch {
    return { ...EMPTY };
  }
}

function saveData(data) {
  // Write via temp file so a crash mid-write can't corrupt the data file
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

const uid = () => Math.random().toString(36).slice(2, 10);

// Normalize player names so "Jesús Made", "Jesus Made" and "George Lombard Jr." all match
function norm(name) {
  return String(name || '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/\b(jr|sr|ii|iii|iv|v)\.?\s*$/, '')
    .replace(/[^a-z ]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

// ---------- Rank sources ----------

// Fetch via curl: its TLS fingerprint passes Cloudflare where Node's fetch gets challenged
function curlGet(url) {
  return new Promise((resolve, reject) => {
    execFile('curl', ['-sL', '--max-time', '30', '-A', UA, url],
      { maxBuffer: 32 * 1024 * 1024 },
      (err, stdout) => (err ? reject(new Error('fetch failed: ' + err.message)) : resolve(stdout)));
  });
}

async function fetchFangraphs() {
  const html = await curlGet('https://www.fangraphs.com/prospects/the-board/2026-prospect-list');
  const start = html.indexOf('__NEXT_DATA__');
  if (start === -1) throw new Error('page format changed (no __NEXT_DATA__)');
  const jsonStart = html.indexOf('>', start) + 1;
  const jsonEnd = html.indexOf('</script>', jsonStart);
  const next = JSON.parse(html.slice(jsonStart, jsonEnd));

  // Find the query whose data is the prospect array
  const queries = next?.props?.pageProps?.dehydratedState?.queries || [];
  let players = null;
  for (const q of queries) {
    const d = q?.state?.data;
    if (Array.isArray(d) && d[0] && 'playerName' in d[0]) { players = d; break; }
  }
  if (!players) throw new Error('prospect array not found');

  // Rob's cut: everyone FV 45 or better on The Board (only the FV 50+ tier carries an overall rank)
  return players
    .filter((p) => (p.Ovr_Rank != null && p.Ovr_Rank >= 1) || +p.FV_Current >= 45)
    .map((p) => ({
      rank: p.Ovr_Rank != null ? +p.Ovr_Rank : null,
      fv: p.FV_Current != null ? +p.FV_Current : null,
      name: p.playerName,
      position: p.Position || '',
      team: p.Team || '',
      eta: String(p.ETA_Current || ''),
      age: p.Age ? Math.round(p.Age * 10) / 10 : null,
      level: p.mlevel || '',
      bonus: p.Sign_Bonus != null && p.Sign_Bonus !== '' ? +p.Sign_Bonus : null,
      url: p.UPURL ? 'https://www.fangraphs.com' + p.UPURL : null,
      minorId: p.minorMasterId || null,
    }));
}

// Current-season FIP for every minor-league pitcher, IP-weighted across levels.
// (FanGraphs publishes FIP- only for MLB, so raw FIP is the best available for prospects.)
const STATS_SEASON = 2026;
async function fetchMinorPitchingFip() {
  const html = await curlGet(`https://www.fangraphs.com/leaders/minor-league?pos=all&stats=pit&lg=all&qual=0&season=${STATS_SEASON}`);
  const start = html.indexOf('__NEXT_DATA__');
  if (start === -1) throw new Error('leaders page format changed');
  const next = JSON.parse(html.slice(html.indexOf('>', start) + 1, html.indexOf('</script>', start)));
  const queries = next?.props?.pageProps?.dehydratedState?.queries || [];
  let rows = null;
  for (const q of queries) {
    const d = q?.state?.data;
    if (Array.isArray(d) && d[0] && 'FIP' in d[0] && 'minormasterid' in d[0]) { rows = d; break; }
  }
  if (!rows) throw new Error('pitching stats array not found');

  // "45.1" IP means 45 innings + 1 out
  const outs = (ip) => { const [full, frac] = String(ip ?? 0).split('.'); return (+full || 0) * 3 + (+frac || 0); };

  // League-average FIP per level, so we can express each pitcher as FIP- (100 = level average).
  // This is level/league-adjusted like FanGraphs' MLB FIP-, minus park factors (not published for minors).
  const lvl = new Map();
  for (const r of rows) {
    const o = outs(r.IP);
    const level = r.aLevel || r.level;
    if (!level || !o || r.FIP == null) continue;
    const a = lvl.get(level) || { outs: 0, fipOuts: 0 };
    a.outs += o;
    a.fipOuts += +r.FIP * o;
    lvl.set(level, a);
  }
  const lvlAvg = new Map([...lvl].map(([k, a]) => [k, a.fipOuts / a.outs]));

  const acc = new Map();
  for (const r of rows) {
    if (!r.minormasterid || r.FIP == null) continue;
    const o = outs(r.IP);
    if (!o) continue;
    const a = acc.get(r.minormasterid) || { outs: 0, fipOuts: 0, fmOuts: 0, fmWt: 0, tbf: 0, kbbTbf: 0, g: 0 };
    a.outs += o;
    a.g += +r.G || 0;
    a.fipOuts += +r.FIP * o;
    const avg = lvlAvg.get(r.aLevel || r.level);
    if (avg) { a.fmOuts += (100 * +r.FIP / avg) * o; a.fmWt += o; }
    // K-BB% weighted by batters faced, which is what the rate is out of
    if (r['K-BB%'] != null && +r.TBF > 0) { a.tbf += +r.TBF; a.kbbTbf += +r['K-BB%'] * +r.TBF; }
    acc.set(r.minormasterid, a);
  }
  const result = new Map();
  for (const [id, a] of acc) {
    result.set(id, { fip: Math.round((a.fipOuts / a.outs) * 100) / 100,
                     fipMinus: a.fmWt ? Math.round(a.fmOuts / a.fmWt) : null,
                     ip: `${Math.floor(a.outs / 3)}.${a.outs % 3}`,
                     kbb: a.tbf ? Math.round((a.kbbTbf / a.tbf) * 1000) / 10 : null,
                     g: a.g || null });
  }
  return result;
}

// Current-season wRC+ for every minor-league hitter, PA-weighted across levels
async function fetchMinorBattingWrc() {
  const html = await curlGet(`https://www.fangraphs.com/leaders/minor-league?pos=all&stats=bat&lg=all&qual=0&season=${STATS_SEASON}`);
  const start = html.indexOf('__NEXT_DATA__');
  if (start === -1) throw new Error('leaders page format changed');
  const next = JSON.parse(html.slice(html.indexOf('>', start) + 1, html.indexOf('</script>', start)));
  const queries = next?.props?.pageProps?.dehydratedState?.queries || [];
  let rows = null;
  for (const q of queries) {
    const d = q?.state?.data;
    if (Array.isArray(d) && d[0] && 'wRC+' in d[0] && 'minormasterid' in d[0]) { rows = d; break; }
  }
  if (!rows) throw new Error('batting stats array not found');

  const acc = new Map();
  for (const r of rows) {
    if (!r.minormasterid || r['wRC+'] == null || !(+r.PA > 0)) continue;
    const a = acc.get(r.minormasterid) || { pa: 0, wrcPa: 0, g: 0 };
    a.pa += +r.PA;
    a.wrcPa += +r['wRC+'] * +r.PA;
    a.g += +r.G || 0;
    acc.set(r.minormasterid, a);
  }
  const result = new Map();
  for (const [id, a] of acc) {
    result.set(id, { wrc: Math.round(a.wrcPa / a.pa), pa: a.pa, g: a.g || null });
  }
  return result;
}

// Parse the ranked-player payload MLB embeds in its prospect pages (top 100 and per-team top 30)
function parseMlbRankings(html) {
  const attr = 'data-init-state="';
  const attrStart = html.indexOf(attr);
  if (attrStart === -1) throw new Error('page format changed (no data-init-state)');
  const valStart = attrStart + attr.length;
  const valEnd = html.indexOf('"', valStart);
  const raw = html.slice(valStart, valEnd)
    .replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>').replace(/&#x3D;/g, '=').replace(/&amp;/g, '&');
  const payload = JSON.parse(raw).payload;

  const rq = payload.ROOT_QUERY || {};
  const listKey = Object.keys(rq).find((k) => k.startsWith('getPlayerRankingsFromSelection'));
  if (!listKey) throw new Error('rankings query not found');

  return rq[listKey].map((entry) => {
    const ref = entry.playerEntity?.player?.__ref;
    const person = ref ? payload[ref] : null;
    if (!person) return null;
    return {
      rank: entry.rank,
      name: `${person.useName} ${person.useLastName}`,
      position: entry.playerEntity?.position || person.primaryPosition?.abbreviation || '',
      age: person.currentAge ?? null,
      mlbId: person.id ?? null,
      url: person.nameSlug ? 'https://www.mlb.com/player/' + person.nameSlug : null,
      twitter: person.social?.twitter || null,
    };
  }).filter(Boolean);
}

async function fetchMlbPipeline() {
  return parseMlbRankings(await curlGet('https://www.mlb.com/milb/prospects/top100'));
}

// Per-team top 30 pages (URLs live in sources/team-top30-urls.csv so Rob can edit the list)
const TEAM_URLS_FILE = path.join(__dirname, 'sources', 'team-top30-urls.csv');
const TEAM_ABBREV = {
  athletics: 'ATH', braves: 'ATL', orioles: 'BAL', redsox: 'BOS', cubs: 'CHC', whitesox: 'CWS',
  reds: 'CIN', guardians: 'CLE', rockies: 'COL', tigers: 'DET', astros: 'HOU', royals: 'KC',
  angels: 'LAA', dodgers: 'LAD', marlins: 'MIA', brewers: 'MIL', twins: 'MIN', mets: 'NYM',
  yankees: 'NYY', phillies: 'PHI', pirates: 'PIT', padres: 'SD', mariners: 'SEA', giants: 'SF',
  cardinals: 'STL', rays: 'TB', rangers: 'TEX', bluejays: 'TOR', nationals: 'WSH', dbacks: 'AZ',
};

async function fetchTeamTop30s() {
  let urls = [];
  try {
    urls = fs.readFileSync(TEAM_URLS_FILE, 'utf8').split(/\r?\n/)
      .map((s) => s.trim()).filter((s) => s.startsWith('http'));
  } catch { /* no file — skip team ranks */ }

  const results = [], errors = [];
  const BATCH = 6;
  for (let i = 0; i < urls.length; i += BATCH) {
    await Promise.all(urls.slice(i, i + BATCH).map(async (url) => {
      const slug = url.replace(/\/+$/, '').split('/').pop();
      try {
        results.push({ slug, list: parseMlbRankings(await curlGet(url)) });
      } catch (e) {
        errors.push(slug + ': ' + e.message);
      }
    }));
  }
  return { results, errors };
}

async function syncRanks(data) {
  const [fgResult, mlbResult] = await Promise.allSettled([fetchFangraphs(), fetchMlbPipeline()]);
  const errors = [];
  const byName = new Map(data.prospects.map((p) => [norm(p.name), p]));

  const apply = (list, rankField, source) => {
    // Clear this source's ranks first so players who dropped off the list lose theirs
    data.prospects.forEach((p) => (p[rankField] = null));
    for (const item of list) {
      let p = byName.get(norm(item.name));
      if (!p) {
        p = { id: uid(), name: item.name, position: '', team: '', eta: '', age: null, level: '', bonus: null, fv: null,
              fgRank: null, baRank: null, mlbRank: null, agentId: '', notes: '',
              fgUrl: null, baUrl: null, mlbUrl: null, mlbId: null, twitter: null,
              fgMinorId: null, fip: null, fipMinus: null, ip: null, kbb: null, wrc: null, pa: null, games: null };
        data.prospects.push(p);
        byName.set(norm(p.name), p);
      }
      p[rankField] = item.rank;
      // Fill in bio fields, preferring FanGraphs (richer data), never erasing with blanks
      if (item.position && (source === 'fg' || !p.position)) p.position = item.position;
      if (item.team && (source === 'fg' || !p.team)) p.team = item.team;
      if (item.eta && source === 'fg') p.eta = item.eta;
      if (item.age != null && (source === 'fg' || p.age == null)) p.age = item.age;
      if (item.level && source === 'fg') p.level = item.level;
      if (item.bonus != null && source === 'fg') p.bonus = item.bonus;
      if (item.fv != null && source === 'fg') p.fv = item.fv;
      if (item.url && source === 'fg') p.fgUrl = item.url;
      if (item.minorId && source === 'fg') p.fgMinorId = item.minorId;
      if (item.url && source === 'mlb') p.mlbUrl = item.url;
      if (item.mlbId && source === 'mlb') p.mlbId = item.mlbId;
      if (item.twitter && source === 'mlb' && !p.twitter) p.twitter = item.twitter; // never overwrite a hand-entered handle
    }
  };

  if (fgResult.status === 'fulfilled') apply(fgResult.value, 'fgRank', 'fg');
  else errors.push('FanGraphs: ' + fgResult.reason.message);
  if (mlbResult.status === 'fulfilled') apply(mlbResult.value, 'mlbRank', 'mlb');
  else errors.push('MLB Pipeline: ' + mlbResult.reason.message);
  const coreFailed = errors.length >= 2;

  // Team top-30 pages: annotate existing prospects with their org rank (never adds players)
  const teams = await fetchTeamTop30s();
  if (teams.results.length) data.prospects.forEach((p) => (p.orgRank = null));
  for (const { slug, list } of teams.results) {
    const abbrev = TEAM_ABBREV[slug] || '';
    for (const item of list) {
      const p = byName.get(norm(item.name));
      if (!p) continue;
      p.orgRank = item.rank;
      if (abbrev && !p.team) p.team = abbrev;
      if (item.position && !p.position) p.position = item.position;
      if (item.age != null && p.age == null) p.age = item.age;
      if (item.mlbId && !p.mlbId) p.mlbId = item.mlbId;
      if (item.url && !p.mlbUrl) p.mlbUrl = item.url;
      if (item.twitter && !p.twitter) p.twitter = item.twitter;
    }
  }
  errors.push(...teams.errors);

  // Season stats: FIP + K-BB% for pitchers, wRC+ for hitters, matched by FanGraphs id
  let fipCount = 0, wrcCount = 0;
  const [pitRes, batRes] = await Promise.allSettled([fetchMinorPitchingFip(), fetchMinorBattingWrc()]);
  if (pitRes.status === 'fulfilled') {
    for (const p of data.prospects) {
      const s = p.fgMinorId ? pitRes.value.get(p.fgMinorId) : null;
      p.fip = s ? s.fip : null;
      p.fipMinus = s ? s.fipMinus : null;
      p.ip = s ? s.ip : null;
      p.kbb = s ? s.kbb : null;
      if (s) fipCount++;
    }
  } else errors.push('Pitching stats: ' + pitRes.reason.message);
  if (batRes.status === 'fulfilled') {
    for (const p of data.prospects) {
      const s = p.fgMinorId ? batRes.value.get(p.fgMinorId) : null;
      p.wrc = s ? s.wrc : null;
      p.pa = s ? s.pa : null;
      if (s) wrcCount++;
    }
  } else errors.push('Batting stats: ' + batRes.reason.message);
  // Current-season games: pitching appearances + games as a hitter, whichever the player has
  if (pitRes.status === 'fulfilled' || batRes.status === 'fulfilled') {
    for (const p of data.prospects) {
      const gp = pitRes.status === 'fulfilled' ? pitRes.value.get(p.fgMinorId)?.g || 0 : 0;
      const gb = batRes.status === 'fulfilled' ? batRes.value.get(p.fgMinorId)?.g || 0 : 0;
      p.games = gp + gb || null;
    }
  }

  if (!coreFailed) {
    data.lastSync = new Date().toISOString();
    snapshotHistory(data);
  }
  return { errors, fg: fgResult.status === 'fulfilled' ? fgResult.value.length : 0,
           mlb: mlbResult.status === 'fulfilled' ? mlbResult.value.length : 0,
           teams: teams.results.length, fip: fipCount, wrc: wrcCount };
}

// Append a rank snapshot per player whenever their ranks changed — powers the ▲/▼ trend arrows
function snapshotHistory(data) {
  const today = new Date().toISOString().slice(0, 10);
  for (const p of data.prospects) {
    p.hist = p.hist || [];
    const last = p.hist[p.hist.length - 1];
    const cur = { d: today, fg: p.fgRank ?? null, ba: p.baRank ?? null, mlb: p.mlbRank ?? null };
    if (!last || last.fg !== cur.fg || last.ba !== cur.ba || last.mlb !== cur.mlb) {
      // Same-day re-sync replaces today's entry instead of stacking one per sync
      if (last && last.d === today) p.hist[p.hist.length - 1] = cur;
      else p.hist.push(cur);
      if (p.hist.length > 30) p.hist.shift();
    }
  }
}

// Auto-sync weekly: check on startup and once a day after
async function autoSyncIfStale() {
  const data = loadData();
  const age = data.lastSync ? Date.now() - new Date(data.lastSync).getTime() : Infinity;
  if (age < SYNC_INTERVAL_DAYS * 24 * 3600 * 1000) return;
  try {
    const result = await syncRanks(data);
    saveData(data);
    console.log(`Auto-synced ranks (FG: ${result.fg}, MLB: ${result.mlb})`,
      result.errors.length ? 'errors: ' + result.errors.join('; ') : '');
  } catch (e) {
    console.log('Auto-sync failed:', e.message);
  }
}

// ---------- HTTP ----------

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };

const server = http.createServer((req, res) => {
  const json = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };

  if (PASSWORD) {
    if (req.url === '/api/login' && req.method === 'POST') {
      const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
      if (tooManyAttempts(ip)) return json(429, { error: 'too many attempts' });
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        let pw = '';
        try { pw = JSON.parse(body).password || ''; } catch {}
        const a = Buffer.from(pw), b = Buffer.from(PASSWORD);
        if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': makeAuthCookie(req) });
          res.end('{"ok":true}');
        } else json(401, { error: 'wrong password' });
      });
      return;
    }
    if (!isAuthed(req)) {
      if (req.url.startsWith('/api/')) return json(401, { error: 'unauthorized' });
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(LOGIN_HTML);
      return;
    }
  }

  if (req.url === '/api/data' && req.method === 'GET') return json(200, loadData());

  if (req.url === '/api/data' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      try {
        const incoming = JSON.parse(body);
        if (!Array.isArray(incoming.prospects) || !Array.isArray(incoming.agents) ||
            !Array.isArray(incoming.opportunities)) throw new Error('bad shape');
        const current = loadData();
        incoming.lastSync = current.lastSync; // client never owns the sync timestamp
        saveData(incoming);
        json(200, { ok: true });
      } catch (e) {
        json(400, { error: e.message });
      }
    });
    return;
  }

  // Look up a player's RotoWire page (linked from their FanGraphs page) and cache it
  const rw = req.url.match(/^\/api\/rotowire\/([a-z0-9]+)$/);
  if (rw && req.method === 'POST') {
    const data = loadData();
    const p = data.prospects.find((x) => x.id === rw[1]);
    if (!p) return json(404, { error: 'prospect not found' });
    if (p.rotowireUrl) return json(200, { url: p.rotowireUrl });
    if (!p.fgUrl) return json(200, { url: null });
    curlGet(p.fgUrl)
      .then((html) => {
        const m = html.match(/https:\/\/www\.rotowire\.com\/baseball\/player\/[a-z0-9-]+/);
        if (m) { p.rotowireUrl = m[0]; saveData(data); }
        json(200, { url: m ? m[0] : null });
      })
      .catch((e) => json(500, { error: e.message }));
    return;
  }

  if (req.url === '/api/sync' && req.method === 'POST') {
    const data = loadData();
    syncRanks(data)
      .then((result) => { saveData(data); json(200, { ...result, data }); })
      .catch((e) => json(500, { error: e.message }));
    return;
  }

  // Static files
  let file = req.url === '/' ? '/index.html' : req.url.split('?')[0];
  const filePath = path.join(PUBLIC_DIR, path.normalize(file));
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end(); return; }
  fs.readFile(filePath, (err, content) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(content);
  });
});

// First run on a fresh cloud volume: seed it with the data.json bundled alongside the code
if (!fs.existsSync(DATA_FILE)) {
  const bundled = path.join(__dirname, 'data.json');
  if (bundled !== DATA_FILE && fs.existsSync(bundled)) {
    fs.copyFileSync(bundled, DATA_FILE);
    console.log('Seeded data volume from bundled data.json');
  }
}

server.listen(PORT, () => {
  console.log(`Finlete CRM running at http://localhost:${PORT}${PASSWORD ? ' (password required)' : ''}`);
  autoSyncIfStale();
  setInterval(autoSyncIfStale, 24 * 3600 * 1000);
});
