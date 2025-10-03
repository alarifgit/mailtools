from typing import Optional
from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from dns_checks import run_dns_checks, dns_lookup_records, rbl_check_target, RESOLVER_PRESETS
from header_analyzer import analyze_headers

app = FastAPI(title="MailTools")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def _resolver_choice(q: Optional[str]) -> str:
    return q if q in RESOLVER_PRESETS else "system"

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

# E-mail DNS Check (formerly “Auth”)
@app.get("/dns", response_class=HTMLResponse)
async def dns_get(request: Request, domain: Optional[str] = None, resolver: Optional[str] = Query(default="system")):
    choice = _resolver_choice(resolver)
    results = run_dns_checks(domain, resolver_choice=choice) if domain else None
    return templates.TemplateResponse("dns.html", {"request": request, "domain": domain or "", "results": results, "resolver": choice, "presets": RESOLVER_PRESETS})

@app.post("/dns", response_class=HTMLResponse)
async def dns_post(request: Request, domain: str = Form(...), resolver: str = Form("system")):
    choice = _resolver_choice(resolver)
    results = run_dns_checks(domain.strip(), resolver_choice=choice)
    return templates.TemplateResponse("dns.html", {"request": request, "domain": domain.strip(), "results": results, "resolver": choice, "presets": RESOLVER_PRESETS})

# Message Header Analyzer
@app.get("/mha", response_class=HTMLResponse)
async def mha_get(request: Request):
    return templates.TemplateResponse("mha.html", {"request": request, "headers_text": "", "analysis": None})

@app.post("/mha", response_class=HTMLResponse)
async def mha_post(request: Request, headers_text: str = Form(...)):
    headers_text = headers_text.strip()[:300000]
    analysis = analyze_headers(headers_text)
    return templates.TemplateResponse("mha.html", {"request": request, "headers_text": headers_text, "analysis": analysis})

# Dig (DNS Lookup) — fixed checkbox bug + resolver picker
@app.get("/dig", response_class=HTMLResponse)
async def dig_get(request: Request, host: Optional[str] = None, types: Optional[str] = None, resolver: Optional[str] = Query(default="system")):
    choice = _resolver_choice(resolver)
    selected = (types.split(",") if types else []) or ["A","CNAME","MX","TXT"]
    results = dns_lookup_records(host, selected, resolver_choice=choice) if host else None
    return templates.TemplateResponse("dig.html", {"request": request, "host": host or "", "selected": selected, "results": results, "resolver": choice, "presets": RESOLVER_PRESETS})

@app.post("/dig", response_class=HTMLResponse)
async def dig_post(
    request: Request,
    host: str = Form(...),
    resolver: str = Form("system"),
    a: Optional[str] = Form(None),
    cname: Optional[str] = Form(None),
    mx: Optional[str] = Form(None),
    txt: Optional[str] = Form(None),
):
    choice = _resolver_choice(resolver)
    selected = []
    if a is not None: selected.append("A")
    if cname is not None: selected.append("CNAME")
    if mx is not None: selected.append("MX")
    if txt is not None: selected.append("TXT")
    if not selected:
        selected = ["A","CNAME","MX","TXT"]
    results = dns_lookup_records(host.strip(), selected, resolver_choice=choice)
    return templates.TemplateResponse("dig.html", {"request": request, "host": host.strip(), "selected": selected, "results": results, "resolver": choice, "presets": RESOLVER_PRESETS})

# RBL / Blacklist checks
@app.get("/rbl", response_class=HTMLResponse)
async def rbl_get(request: Request, target: Optional[str] = None, resolver: Optional[str] = Query(default="system")):
    choice = _resolver_choice(resolver)
    outcome = rbl_check_target(target, resolver_choice=choice) if target else None
    return templates.TemplateResponse("rbl.html", {"request": request, "target": target or "", "resolver": choice, "presets": RESOLVER_PRESETS, "outcome": outcome})

@app.post("/rbl", response_class=HTMLResponse)
async def rbl_post(request: Request, target: str = Form(...), resolver: str = Form("system")):
    choice = _resolver_choice(resolver)
    outcome = rbl_check_target(target.strip(), resolver_choice=choice)
    return templates.TemplateResponse("rbl.html", {"request": request, "target": target.strip(), "resolver": choice, "presets": RESOLVER_PRESETS, "outcome": outcome})

@app.get("/health")
async def health():
    return {"ok": True}
