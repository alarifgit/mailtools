from typing import Optional
from fastapi import FastAPI, Request, Form, Query, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from datetime import datetime
import time

from dns_checks import run_dns_checks, dns_lookup_records, rbl_check_target, RESOLVER_PRESETS
from header_analyzer import analyze_headers

app = FastAPI(title="MailTools")

# Session middleware with secure secret
app.add_middleware(SessionMiddleware, secret_key="change-this-to-a-secure-random-key-in-production-123456789")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# System metrics tracking
system_metrics = {
    "total_requests": 0,
    "last_request_time": None
}

def _resolver_choice(q: Optional[str]) -> str:
    return q if q in RESOLVER_PRESETS else "system"

def track_check(request: Request, tool: str, target: str):
    """Add a check to recent history"""
    if "recent_checks" not in request.session:
        request.session["recent_checks"] = []
    
    recent = request.session["recent_checks"]
    recent.insert(0, {
        "tool": tool,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "url": f"/{tool}?{'domain' if tool == 'dns' else 'host' if tool == 'dig' else 'target'}={target}"
    })
    
    request.session["recent_checks"] = recent[:5]

def get_recent_checks(request: Request):
    """Get recent checks with relative time"""
    checks = request.session.get("recent_checks", [])
    
    for check in checks:
        check_time = datetime.fromisoformat(check["timestamp"])
        delta = datetime.now() - check_time
        
        if delta.seconds < 60:
            check["time_ago"] = "just now"
        elif delta.seconds < 3600:
            mins = delta.seconds // 60
            check["time_ago"] = f"{mins}m ago"
        elif delta.seconds < 86400:
            hours = delta.seconds // 3600
            check["time_ago"] = f"{hours}h ago"
        else:
            days = delta.days
            check["time_ago"] = f"{days}d ago"
    
    return checks

def get_system_metrics(request: Request):
    """Get system metrics"""
    request_count = request.session.get("request_count", 0)
    response_time = system_metrics.get("last_request_time", 124)
    
    return {
        "api_status": "Online",
        "rate_limit": f"{min(request_count, 100)}/100",
        "response_time": f"{response_time}ms"
    }

def track_request(request: Request, start_time: float):
    """Track request metrics"""
    system_metrics["total_requests"] += 1
    system_metrics["last_request_time"] = int((time.time() - start_time) * 1000)
    request.session["request_count"] = request.session.get("request_count", 0) + 1

def get_context(request: Request):
    """Get common template context"""
    return {
        "request": request,
        "recent_checks": get_recent_checks(request),
        "system_metrics": get_system_metrics(request)
    }

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    start_time = time.time()
    context = get_context(request)
    track_request(request, start_time)
    return templates.TemplateResponse("home.html", context)

@app.get("/dns", response_class=HTMLResponse)
async def dns_get(request: Request, domain: Optional[str] = None, resolver: Optional[str] = Query(default="system")):
    start_time = time.time()
    choice = _resolver_choice(resolver)
    results = run_dns_checks(domain, resolver_choice=choice) if domain else None
    
    if domain:
        track_check(request, "dns", domain)
    
    context = get_context(request)
    context.update({
        "domain": domain or "",
        "results": results,
        "resolver": choice,
        "presets": RESOLVER_PRESETS
    })
    track_request(request, start_time)
    return templates.TemplateResponse("dns.html", context)

@app.post("/dns", response_class=HTMLResponse)
async def dns_post(request: Request, domain: str = Form(...), resolver: str = Form("system")):
    start_time = time.time()
    choice = _resolver_choice(resolver)
    domain = domain.strip()
    results = run_dns_checks(domain, resolver_choice=choice)
    
    track_check(request, "dns", domain)
    
    context = get_context(request)
    context.update({
        "domain": domain,
        "results": results,
        "resolver": choice,
        "presets": RESOLVER_PRESETS
    })
    track_request(request, start_time)
    return templates.TemplateResponse("dns.html", context)

@app.get("/mha", response_class=HTMLResponse)
async def mha_get(request: Request):
    start_time = time.time()
    context = get_context(request)
    context.update({
        "headers_text": "",
        "analysis": None
    })
    track_request(request, start_time)
    return templates.TemplateResponse("mha.html", context)

@app.post("/mha", response_class=HTMLResponse)
async def mha_post(request: Request, headers_text: str = Form(...)):
    start_time = time.time()
    headers_text = headers_text.strip()[:300000]
    analysis = analyze_headers(headers_text)
    
    track_check(request, "mha", "Email Headers")
    
    context = get_context(request)
    context.update({
        "headers_text": headers_text,
        "analysis": analysis
    })
    track_request(request, start_time)
    return templates.TemplateResponse("mha.html", context)

@app.get("/dig", response_class=HTMLResponse)
async def dig_get(request: Request, host: Optional[str] = None, types: Optional[str] = None, resolver: Optional[str] = Query(default="system")):
    start_time = time.time()
    choice = _resolver_choice(resolver)
    selected = (types.split(",") if types else []) or ["A","CNAME","MX","TXT"]
    results = dns_lookup_records(host, selected, resolver_choice=choice) if host else None
    
    if host:
        track_check(request, "dig", host)
    
    context = get_context(request)
    context.update({
        "host": host or "",
        "selected": selected,
        "results": results,
        "resolver": choice,
        "presets": RESOLVER_PRESETS
    })
    track_request(request, start_time)
    return templates.TemplateResponse("dig.html", context)

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
    start_time = time.time()
    choice = _resolver_choice(resolver)
    selected = []
    if a is not None: selected.append("A")
    if cname is not None: selected.append("CNAME")
    if mx is not None: selected.append("MX")
    if txt is not None: selected.append("TXT")
    if not selected:
        selected = ["A","CNAME","MX","TXT"]
    
    host = host.strip()
    results = dns_lookup_records(host, selected, resolver_choice=choice)
    
    track_check(request, "dig", host)
    
    context = get_context(request)
    context.update({
        "host": host,
        "selected": selected,
        "results": results,
        "resolver": choice,
        "presets": RESOLVER_PRESETS
    })
    track_request(request, start_time)
    return templates.TemplateResponse("dig.html", context)

@app.get("/rbl", response_class=HTMLResponse)
async def rbl_get(request: Request, target: Optional[str] = None, resolver: Optional[str] = Query(default="system")):
    start_time = time.time()
    choice = _resolver_choice(resolver)
    outcome = rbl_check_target(target, resolver_choice=choice) if target else None
    
    if target:
        track_check(request, "rbl", target)
    
    context = get_context(request)
    context.update({
        "target": target or "",
        "resolver": choice,
        "presets": RESOLVER_PRESETS,
        "outcome": outcome
    })
    track_request(request, start_time)
    return templates.TemplateResponse("rbl.html", context)

@app.post("/rbl", response_class=HTMLResponse)
async def rbl_post(request: Request, target: str = Form(...), resolver: str = Form("system")):
    start_time = time.time()
    choice = _resolver_choice(resolver)
    target = target.strip()
    outcome = rbl_check_target(target, resolver_choice=choice)
    
    track_check(request, "rbl", target)
    
    context = get_context(request)
    context.update({
        "target": target,
        "resolver": choice,
        "presets": RESOLVER_PRESETS,
        "outcome": outcome
    })
    track_request(request, start_time)
    return templates.TemplateResponse("rbl.html", context)

@app.post("/clear-history", response_class=HTMLResponse)
async def clear_history(request: Request):
    request.session["recent_checks"] = []
    return Response(status_code=200)

@app.get("/health")
async def health():
    return {"ok": True}