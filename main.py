"""PhishGuard API. Run:  uvicorn main:app --reload"""
import os, sqlite3, time
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from analyzer import analyze

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin123")   # change before the demo!
DB = "reports.db"
app = FastAPI(title="PhishGuard", description="Fake website & brand impersonation detector")

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, score INTEGER, verdict TEXT,
        user_note TEXT, status TEXT DEFAULT 'pending', reviewer_note TEXT, created REAL)""")
    return c

class AnalyzeIn(BaseModel):
    url: str
    deep: bool = True

class ReportIn(BaseModel):
    url: str
    note: str = ""

class ReviewIn(BaseModel):
    status: str            # confirmed_phishing | false_positive
    reviewer_note: str = ""

@app.post("/api/analyze")
def api_analyze(body: AnalyzeIn):
    if not body.url.strip() or len(body.url) > 2000:
        raise HTTPException(400, "Invalid URL")
    return analyze(body.url, body.deep)          # nothing is stored here (privacy)

@app.post("/api/report")
def api_report(body: ReportIn):
    r = analyze(body.url, deep=False)
    with db() as c:
        c.execute("INSERT INTO reports(url,score,verdict,user_note,created) VALUES(?,?,?,?,?)",
                  (r["url"], r["score"], r["verdict"], body.note[:500], time.time()))
    return {"ok": True, "message": "Thanks! Your report is queued for review."}

@app.get("/api/reports")
def api_reports(x_admin_token: str = Header(default="")):
    if x_admin_token != ADMIN_TOKEN: raise HTTPException(401, "Admin token required")
    with db() as c:
        return [dict(x) for x in c.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 200")]

@app.post("/api/reports/{rid}/review")
def api_review(rid: int, body: ReviewIn, x_admin_token: str = Header(default="")):
    if x_admin_token != ADMIN_TOKEN: raise HTTPException(401, "Admin token required")
    if body.status not in ("confirmed_phishing", "false_positive"): raise HTTPException(400, "Bad status")
    with db() as c:
        c.execute("UPDATE reports SET status=?, reviewer_note=? WHERE id=?", (body.status, body.reviewer_note[:500], rid))
    return {"ok": True}

@app.get("/")
def home(): return FileResponse("static/index.html")
app.mount("/static", StaticFiles(directory="static"), name="static")
