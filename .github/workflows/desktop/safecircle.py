#!/usr/bin/env python3
"""Safe Circle AI: a local personal-safety app.

Run:  pip install -r requirements.txt && python safecircle.py
Open: http://127.0.0.1:5000   (bound to this computer only; your data stays in safecircle.db)
"""
import asyncio, csv, io, json, os, re, smtplib, sqlite3, threading, time, urllib.parse, urllib.request
from email.message import EmailMessage
from flask import Flask, Response, jsonify, request

def _data_dir():
    d = os.path.join(os.path.expanduser("~"), ".safecircle")
    os.makedirs(d, exist_ok=True)
    return d


DB = os.environ.get("SC_DB", os.path.join(_data_dir(), "safecircle.db"))
SCAN_SECONDS = float(os.environ.get("SC_SCAN_SECONDS", 8))      # length of one BLE scan
SCAN_PAUSE = float(os.environ.get("SC_SCAN_PAUSE", 52))         # pause between scans
AUTO_NOTIFY = os.environ.get("SC_AUTO_NOTIFY", "0") == "1"      # alert contacts on high-risk tracker
app = Flask(__name__)


# ---------- storage ----------
def q(sql, args=()):
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    try:
        cur = c.execute(sql, args)
        rows = cur.fetchall()
        c.commit()
        return rows
    finally:
        c.close()


def init():
    for s in (
        "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, module TEXT, sev INT, msg TEXT)",
        "CREATE TABLE IF NOT EXISTS contacts(id INTEGER PRIMARY KEY, name TEXT, email TEXT, telegram TEXT)",
        "CREATE TABLE IF NOT EXISTS sightings(id INTEGER PRIMARY KEY, ts REAL, addr TEXT, kind TEXT, name TEXT, rssi INT)",
        "CREATE TABLE IF NOT EXISTS flagged(addr TEXT PRIMARY KEY, ts REAL)",
    ):
        q(s)


def log_event(module, sev, msg):
    q("INSERT INTO events(ts,module,sev,msg) VALUES(?,?,?,?)", (time.time(), module, int(sev), msg))


# ---------- TrackShield: real Bluetooth scanning ----------
def classify(adv):
    """Return a tracker type if the advertisement looks like a known item tracker, else None."""
    md = adv.manufacturer_data or {}
    apple = md.get(0x004C)
    if apple and apple[:1] == b"\x12":                       # Apple Find My network payload
        return "Find My accessory (AirTag-type)"
    for u in adv.service_uuids or []:
        short = u.lower()[4:8]
        if short == "feed":
            return "Tile tracker"
        if short == "fd5a":
            return "Samsung SmartTag"
        if short == "fe33":
            return "Chipolo tracker"
    return None


class Scanner:
    running = False
    scans = 0
    last = None
    error = None


SC = Scanner()


def scan_loop():
    try:
        from bleak import BleakScanner
    except ImportError:
        SC.error, SC.running = "Bluetooth library missing. Run: pip install bleak", False
        return

    async def run():
        while SC.running:
            try:
                found = await BleakScanner.discover(timeout=SCAN_SECONDS, return_adv=True)
                now, rows = time.time(), []
                for addr, (dev, adv) in found.items():
                    kind = classify(adv)
                    if kind:
                        rows.append((now, addr, kind, adv.local_name or dev.name or "", adv.rssi))
                for r in rows:
                    q("INSERT INTO sightings(ts,addr,kind,name,rssi) VALUES(?,?,?,?,?)", r)
                SC.scans += 1
                SC.last, SC.error = now, None
                check_trackers()
            except Exception as e:  # Bluetooth off, no permission, no adapter
                SC.error = f"Scan failed: {e}"
                await asyncio.sleep(15)
            for _ in range(int(SCAN_PAUSE)):
                if not SC.running:
                    break
                await asyncio.sleep(1)

    asyncio.run(run())


def trackers(hours=6):
    """Group tracker sightings. A tracker that keeps showing up over a long span is travelling with you."""
    rows = q("SELECT addr,kind,name,MIN(ts) a,MAX(ts) b,COUNT(*) n,AVG(rssi) r FROM sightings "
             "WHERE ts>? GROUP BY addr ORDER BY n DESC", (time.time() - hours * 3600,))
    out = []
    for r in rows:
        span = (r["b"] - r["a"]) / 60
        lvl = 3 if r["n"] >= 6 and span >= 30 else 2 if r["n"] >= 4 and span >= 15 else 1
        out.append(dict(id=r["addr"][-5:], kind=r["kind"], scans=r["n"], minutes=round(span),
                        rssi=round(r["r"] or 0), level=lvl, addr=r["addr"],
                        last=r["b"]))
    return out


def check_trackers():
    for t in trackers():
        if t["level"] >= 2 and not q("SELECT 1 FROM flagged WHERE addr=?", (t["addr"],)):
            q("INSERT INTO flagged(addr,ts) VALUES(?,?)", (t["addr"], time.time()))
            msg = f"{t['kind']} (…{t['id']}) detected in {t['scans']} scans over {t['minutes']} min"
            log_event("trackshield", t["level"], msg)
            if AUTO_NOTIFY and t["level"] == 3:
                notify("Safe Circle alert: " + msg + ". I may be being tracked.")


# ---------- Privacy Guardian ----------
PII = [
    (r"(?<!\d)(\+?\d[\d\s\-]{8,}\d)", "Phone number", 2),
    (r"[\w.+-]+@[\w-]+\.[\w.]+", "Email address", 2),
    (r"\b\d{1,4}[\w/-]*,?\s+[\w ]{2,25}\b(?:street|st\.|road|rd\.|nagar|lane|avenue|ave|colony)\b", "Street address", 3),
    (r"\b(?:i['’]?m|i am|we['’]?re)\s+(?:at|in|near|outside)\s+[^.!\n]{3,40}", "Live location", 3),
    (r"\b(?:my|our)\s+(?:school|college|office|gym|hostel)\b[^.!\n]{0,30}", "Routine place", 2),
    (r"\b(?:every|each)\s+(?:day|morning|evening|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b[^.!\n]{0,30}", "Routine pattern", 2),
    (r"\b[A-Z]{2}\s?\d{1,2}\s?[A-Z]{1,3}\s?\d{3,4}\b", "Vehicle number", 3),
]


def privacy_scan(text):
    found = []
    for pat, label, sev in PII:
        for m in re.finditer(pat, text, re.I if label != "Vehicle number" else 0):
            found.append(dict(label=label, text=m.group(0).strip(), sev=sev))
    return found


# ---------- PatternLock: correlate everything ----------
NAMES = {"trackshield": "TrackShield", "shadowwatch": "ShadowWatch", "privacyguardian": "Privacy Guardian",
         "incident": "Incident report", "saferesponse": "Safe Response"}


def analyse():
    ev = q("SELECT * FROM events WHERE ts>? ORDER BY ts DESC", (time.time() - 7 * 86400,))
    score = min(100, sum(e["sev"] ** 2 * 3 for e in ev))
    mods = sorted({e["module"] for e in ev if e["sev"] >= 2})
    alerts = []
    if len(mods) >= 2:
        alerts.append((3, "Concerns in %d areas (%s) within 7 days. This may be a coordinated pattern. "
                          "Save your evidence and tell someone you trust." % (len(mods), ", ".join(NAMES.get(m, m) for m in mods))))
    elif mods:
        alerts.append((2, "Repeated concern in %s. Keep logging so patterns can be spotted." % NAMES.get(mods[0], mods[0])))
    if "trackshield" in mods and not q("SELECT 1 FROM contacts"):
        alerts.append((2, "A tracking concern is logged but you have no trusted contacts. Add one in Safe Response."))
    if sum(1 for e in ev if e["module"] == "incident") >= 3:
        alerts.append((3, "Three or more incidents this week. Repeated incidents can support a stalking report."))
    if not ev:
        alerts.append((1, "No concerns logged in the last 7 days."))
    tips = []
    if "trackshield" in mods: tips.append("Check bags, car and coat linings for small unknown tags.")
    if "shadowwatch" in mods: tips.append("Change passwords from a device you trust, then turn on two-step sign-in.")
    if "privacyguardian" in mods: tips.append("Remove live location and contact details from public posts.")
    tips.append("Take dated screenshots. A clear timeline helps police and support services.")
    return dict(score=score, alerts=[dict(sev=s, msg=m) for s, m in alerts], tips=tips)


# ---------- Safe Response: real notifications ----------
def notify(message):
    results = []
    for c in q("SELECT * FROM contacts"):
        sent = []
        host = os.environ.get("SC_SMTP_HOST")
        if c["email"] and host:
            try:
                m = EmailMessage()
                m["Subject"], m["From"], m["To"] = "Safe Circle alert", os.environ.get("SC_SMTP_USER", ""), c["email"]
                m.set_content(message)
                with smtplib.SMTP(host, int(os.environ.get("SC_SMTP_PORT", 587)), timeout=15) as s:
                    s.starttls()
                    s.login(os.environ["SC_SMTP_USER"], os.environ["SC_SMTP_PASS"])
                    s.send_message(m)
                sent.append("email sent")
            except Exception as e:
                sent.append(f"email failed ({e})")
        token = os.environ.get("SC_TG_TOKEN")
        if c["telegram"] and token:
            try:
                data = urllib.parse.urlencode({"chat_id": c["telegram"], "text": message}).encode()
                urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data, timeout=15)
                sent.append("Telegram sent")
            except Exception as e:
                sent.append(f"Telegram failed ({e})")
        results.append(dict(name=c["name"], result=", ".join(sent) or "no channel set up (see README)"))
    return results


# ---------- API ----------
@app.get("/api/state")
def state():
    a = analyse()
    return jsonify(
        risk=a, trackers=trackers(),
        scanner=dict(running=SC.running, scans=SC.scans, last=SC.last, error=SC.error),
        events=[dict(ts=e["ts"], module=NAMES.get(e["module"], e["module"]), sev=e["sev"], msg=e["msg"])
                for e in q("SELECT * FROM events ORDER BY ts DESC LIMIT 40")],
        contacts=[dict(id=c["id"], name=c["name"], email=c["email"], telegram=c["telegram"]) for c in q("SELECT * FROM contacts")])


@app.post("/api/scan/<act>")
def scan(act):
    if act == "start" and not SC.running:
        SC.running, SC.error = True, None
        threading.Thread(target=scan_loop, daemon=True).start()
    elif act == "stop":
        SC.running = False
    return jsonify(ok=True)


@app.post("/api/privacy")
def privacy():
    text = (request.json or {}).get("text", "")
    f = privacy_scan(text)
    if f:
        log_event("privacyguardian", max(x["sev"] for x in f), "%d risky detail(s): %s" % (len(f), ", ".join(sorted({x["label"] for x in f}))))
    return jsonify(findings=f)


@app.post("/api/surveillance")
def surveillance():
    n = int((request.json or {}).get("count", 0))
    sev = 3 if n >= 4 else 2 if n >= 2 else 1
    if n:
        log_event("shadowwatch", sev, f"{n} of 6 digital surveillance signs reported")
    return jsonify(sev=sev)


@app.post("/api/incident")
def incident():
    d = request.json or {}
    if d.get("text", "").strip():
        log_event("incident", d.get("sev", 2), d["text"].strip()[:500])
    return jsonify(ok=True)


@app.post("/api/contacts")
def add_contact():
    d = request.json or {}
    if d.get("name", "").strip():
        q("INSERT INTO contacts(name,email,telegram) VALUES(?,?,?)", (d["name"].strip(), d.get("email", "").strip(), d.get("telegram", "").strip()))
    return jsonify(ok=True)


@app.delete("/api/contacts/<int:cid>")
def del_contact(cid):
    q("DELETE FROM contacts WHERE id=?", (cid,))
    return jsonify(ok=True)


@app.post("/api/sos")
def sos():
    msg = (request.json or {}).get("message", "I need help.")
    res = notify(f"{msg} (Sent {time.strftime('%d %b %H:%M')})")
    log_event("saferesponse", 3, "Alert sent to %d contact(s)" % len(res))
    return jsonify(results=res)


@app.post("/api/clear")
def clear():
    for t in ("events", "sightings", "flagged"):
        q(f"DELETE FROM {t}")
    return jsonify(ok=True)


@app.get("/api/export.csv")
def export():
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["time", "module", "severity", "details"])
    for e in q("SELECT * FROM events ORDER BY ts"):
        w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"])), NAMES.get(e["module"], e["module"]), e["sev"], e["msg"]])
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=safecircle-evidence.csv"})


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


PAGE = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Safe Circle AI</title><style>
:root{--bg:#eef3fb;--card:#fff;--ink:#0d1b3d;--mut:#55627f;--line:#d6dfef;--b:#2563eb;--soft:#e4ecfa}
@media(prefers-color-scheme:dark){:root{--bg:#070f26;--card:#101c3f;--ink:#e8eefc;--mut:#9aa9cc;--line:#253362;--soft:#18264f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif}
header{background:linear-gradient(120deg,#07123a,#0f2a6b);color:#fff;padding:14px 20px}header h1{margin:0;font-size:1.4rem}header h1 span{color:#22d3ee}header p{margin:0;opacity:.8;font-size:.9rem}
nav{display:flex;gap:6px;margin-top:10px;overflow-x:auto}nav button{background:none;border:1px solid #ffffff40;color:#cfe0ff;border-radius:99px;padding:6px 13px;cursor:pointer;white-space:nowrap}nav button.on{background:#22d3ee;color:#06214a;border-color:#22d3ee;font-weight:600}
main{max-width:1000px;margin:auto;padding:20px}section{display:none}section.on{display:block}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}
.btn{border:0;border-radius:8px;padding:9px 15px;font:600 .95rem system-ui;cursor:pointer;background:var(--b);color:#fff}.btn.alt{background:var(--soft);color:var(--ink)}.btn.red{background:#dc2626}
input,textarea,select{width:100%;border:1px solid var(--line);background:var(--bg);color:var(--ink);border-radius:8px;padding:9px;font:inherit}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.mut{color:var(--mut)}h2,h3{margin:0 0 8px}
.pill{border-radius:99px;padding:2px 10px;font-size:.8rem;font-weight:600;color:#fff}.s1{background:#16a34a}.s2{background:#ea7a0c}.s3{background:#dc2626}
.meter{height:12px;background:var(--soft);border-radius:99px;overflow:hidden}.meter i{display:block;height:100%;background:#2563eb;transition:width .5s}
.item{padding:9px 0;border-bottom:1px solid var(--line)}.item small{display:block;color:var(--mut)}.hl{background:#ea7a0c55;border-radius:3px}
label.c{display:flex;gap:8px;padding:6px 0}details{border-bottom:1px solid var(--line);padding:9px 0}summary{cursor:pointer;font-weight:600}
</style></head><body><header><h1>Safe Circle <span>AI</span></h1><p>Detect. Prevent. Protect. Runs on your computer. Data stays here.</p>
<nav id="nav"></nav></header><main>
<section id="dashboard"><div class="card"><h2>Risk this week: <span id="lvl"></span></h2><div class="meter"><i id="mt"></i></div><div id="alerts"></div></div>
<div class="grid"><div class="card"><h3>Evidence timeline</h3><div id="tl"></div><div class="row" style="margin-top:10px"><a class="btn alt" href="/api/export.csv" style="text-decoration:none">Download CSV</a><button class="btn alt" onclick="clr()">Clear all</button></div></div>
<div class="card"><h3>Personalised tips</h3><ul id="tips"></ul></div></div></section>

<section id="trackshield"><div class="card"><h2>TrackShield</h2><p class="mut">Scans for AirTag-type, Tile, Samsung and Chipolo trackers using this computer's Bluetooth. Keep it running while you travel (a laptop in your bag works). A tracker that keeps appearing over 15+ minutes is flagged.</p>
<div class="row"><button class="btn" id="sb" onclick="scan()">Start scanning</button><span id="ss" class="mut"></span></div></div><div class="card"><h3>Trackers seen (last 6 hours)</h3><div id="tr"></div></div></section>

<section id="shadowwatch"><div class="card"><h2>ShadowWatch</h2><p class="mut">Tick what is happening to you.</p><div id="sw"></div><button class="btn" onclick="sw()">Check my risk</button><p id="swo"></p></div></section>

<section id="privacyguardian"><div class="card"><h2>Privacy Guardian</h2><p class="mut">Paste a message or post to find details that reveal where you are or how to reach you.</p>
<textarea id="pg" rows="6" placeholder="Paste text here"></textarea><div class="row" style="margin-top:8px"><button class="btn" onclick="pg()">Scan</button></div><div id="pgo"></div></div></section>

<section id="patternlock"><div class="card"><h2>PatternLock: log an incident</h2><div class="row"><input id="it" placeholder="What happened?" style="flex:1;min-width:220px"><select id="is" style="width:auto"><option value="1">Minor</option><option value="2" selected>Concerning</option><option value="3">Urgent</option></select><button class="btn" onclick="inc()">Add</button></div>
<p class="mut">Every module feeds this engine. It raises an alert when concerns repeat or appear in more than one area.</p></div></section>

<section id="saferesponse"><div class="grid"><div class="card"><h2>Trusted contacts</h2><input id="cn" placeholder="Name"><input id="ce" placeholder="Email (optional)" style="margin-top:6px"><input id="ct" placeholder="Telegram chat ID (optional)" style="margin-top:6px"><button class="btn" style="margin-top:8px" onclick="addc()">Add contact</button><div id="cl"></div></div>
<div class="card"><h2>Send an alert</h2><textarea id="sm" rows="4">I need help and I don't feel safe. Please call me now.</textarea><button class="btn red" style="margin-top:8px" onclick="sos()">Notify contacts</button><div id="so"></div>
<p class="mut">In danger? Call 112 (India), 911 (US), 999 (UK). Women's helpline India: 181.</p></div></div></section>

<section id="awareness"><div class="card"><h2>Behaviour Awareness</h2><div id="ls"></div></div></section>
</main><script>
const $=s=>document.querySelector(s),esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api=(u,m='GET',b)=>fetch(u,{method:m,headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined}).then(r=>r.json());
const TABS=[['dashboard','Dashboard'],['trackshield','TrackShield'],['shadowwatch','ShadowWatch'],['privacyguardian','Privacy Guardian'],['patternlock','PatternLock'],['saferesponse','Safe Response'],['awareness','Learn']];
$('#nav').innerHTML=TABS.map(t=>`<button data-t="${t[0]}">${t[1]}</button>`).join('');
function tab(id){document.querySelectorAll('section').forEach(s=>s.classList.toggle('on',s.id==id));document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('on',b.dataset.t==id))}
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>tab(b.dataset.t));tab('dashboard');
const SW=['I get sign-in alerts for logins I didn\u2019t make','Someone knows things I only shared privately','My phone battery drains fast or runs hot','An unfamiliar app or profile is installed','Someone else knows my passcode or passwords','My location or messages seem shared with someone'];
$('#sw').innerHTML=SW.map(x=>`<label class="c"><input type="checkbox" class="swc"> ${x}</label>`).join('');
const LES=[['Recognise controlling patterns','Stalking is a pattern: repeated contact, turning up where you are, monitoring accounts, tracking movement. Each act may look small. Together they matter.'],['Respectful boundaries online','Consent covers location sharing, photos and messages. A no, or silence, means stop.'],['Secure your accounts','Use unique passwords, two-step sign-in, review logged-in devices, remove unknown apps.'],['Supporting a friend','Listen, don\u2019t blame, help them keep dated evidence, let them choose the next step.']];
$('#ls').innerHTML=LES.map(l=>`<details><summary>${l[0]}</summary><p>${l[1]}</p></details>`).join('');
const P=['','Low','Concern','Urgent'];
async function load(){const s=await api('/api/state');
 $('#lvl').innerHTML=`<span class="pill s${s.risk.score>=60?3:s.risk.score>=25?2:1}">${s.risk.score>=60?'High':s.risk.score>=25?'Medium':'Low'}</span> ${s.risk.score}/100`;$('#mt').style.width=s.risk.score+'%';
 $('#alerts').innerHTML=s.risk.alerts.map(a=>`<p><span class="pill s${a.sev}">${P[a.sev]}</span> ${esc(a.msg)}</p>`).join('');
 $('#tl').innerHTML=s.events.length?s.events.map(e=>`<div class="item"><span class="pill s${e.sev}">${P[e.sev]}</span> ${esc(e.msg)}<small>${esc(e.module)} \u00b7 ${new Date(e.ts*1e3).toLocaleString()}</small></div>`).join(''):'<p class="mut">Nothing logged yet.</p>';
 $('#tips').innerHTML=s.risk.tips.map(t=>`<li>${esc(t)}</li>`).join('');
 const sc=s.scanner;$('#sb').textContent=sc.running?'Stop scanning':'Start scanning';$('#sb').dataset.run=sc.running?1:'';
 $('#ss').textContent=sc.error||(sc.running?`Scanning. ${sc.scans} scans done.`:'Not scanning.');
 $('#tr').innerHTML=s.trackers.length?s.trackers.map(t=>`<div class="item"><span class="pill s${t.level}">${['','Seen','Watch','Likely following you'][t.level]}</span> ${esc(t.kind)} (\u2026${esc(t.id)})<small>${t.scans} scans over ${t.minutes} min \u00b7 signal ${t.rssi} dBm</small></div>`).join(''):'<p class="mut">No trackers detected yet.</p>';
 $('#cl').innerHTML=s.contacts.map(c=>`<div class="item row"><span style="flex:1">${esc(c.name)}<small>${esc(c.email||'')} ${esc(c.telegram||'')}</small></span><button class="btn alt" onclick="delc(${c.id})">Remove</button></div>`).join('');}
async function scan(){await api('/api/scan/'+($('#sb').dataset.run?'stop':'start'),'POST');setTimeout(load,500)}
async function sw(){const n=document.querySelectorAll('.swc:checked').length,r=await api('/api/surveillance','POST',{count:n});$('#swo').innerHTML=`<span class="pill s${r.sev}">${['','Low','Medium','High'][r.sev]} risk</span> ${n} of 6 signs. `+['Keep two-step sign-in on.','Review installed apps and logged-in devices; change passwords.','Strong signs of monitoring. Change passwords from a trusted device and get support before removing anything, so evidence is kept.'][r.sev-1];load()}
async function pg(){const t=$('#pg').value;if(!t.trim())return;const r=await api('/api/privacy','POST',{text:t});$('#pgo').innerHTML=r.findings.length?'<ul>'+r.findings.map(f=>`<li><span class="pill s${f.sev}">${P[f.sev]}</span> <b>${esc(f.label)}:</b> <span class="hl">${esc(f.text)}</span></li>`).join('')+'</ul>':'<p><span class="pill s1">Low</span> Nothing sensitive found.</p>';load()}
async function inc(){await api('/api/incident','POST',{text:$('#it').value,sev:+$('#is').value});$('#it').value='';load()}
async function addc(){await api('/api/contacts','POST',{name:$('#cn').value,email:$('#ce').value,telegram:$('#ct').value});['#cn','#ce','#ct'].forEach(i=>$(i).value='');load()}
async function delc(id){await api('/api/contacts/'+id,'DELETE');load()}
async function sos(){const r=await api('/api/sos','POST',{message:$('#sm').value});$('#so').innerHTML=r.results.length?r.results.map(x=>`<p>${esc(x.name)}: ${esc(x.result)}</p>`).join(''):'<p class="mut">Add a contact first.</p>';load()}
async function clr(){if(confirm('Delete all logged events and tracker sightings?')){await api('/api/clear','POST');load()}}
load();setInterval(load,10000);
</script></body></html>"""

if __name__ == "__main__":
    init()
    import webbrowser
    print("Safe Circle AI is running. Close this window to quit.")
    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(host="127.0.0.1", port=5000)
