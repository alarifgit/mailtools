import dns.resolver, idna, re, ipaddress, time
from functools import lru_cache

RESOLVER_PRESETS = {
    "system":   {"label": "System default",           "servers": None},
    "google":   {"label": "Google (8.8.8.8)",         "servers": ["8.8.8.8","8.8.4.4"]},
    "cloudflare":{"label":"Cloudflare (1.1.1.1)",     "servers": ["1.1.1.1","1.0.0.1"]},
    "quad9":    {"label": "Quad9 (9.9.9.9)",          "servers": ["9.9.9.9","149.112.112.112"]},
    "opendns":  {"label": "OpenDNS (208.67.222.222)", "servers": ["208.67.222.222","208.67.220.220"]},
}

def _resolver(timeout=4, lifetime=4, resolver_choice="system"):
    r = dns.resolver.Resolver()
    r.timeout, r.lifetime = timeout, lifetime
    preset = RESOLVER_PRESETS.get(resolver_choice, RESOLVER_PRESETS["system"])
    if preset["servers"]:
        r.nameservers = preset["servers"]
    return r

def _resolve(name, rtype, resolver_choice="system"):
    try:
        return _resolver(resolver_choice=resolver_choice).resolve(name, rtype)
    except Exception:
        return None

def _txt_values(name, resolver_choice="system"):
    ans = _resolve(name, "TXT", resolver_choice)
    vals = []
    if ans:
        for r in ans:
            try:
                s = b"".join(getattr(r, "strings", [])).decode("utf-8","ignore") if getattr(r,"strings",None) else r.to_text().strip('"')
                vals.append(s)
            except Exception: pass
    return vals

def _puny(d):
    try:    return idna.encode(d.strip().lower()).decode()
    except: return d.strip().lower()

# ------- Dig lookups -------
def dns_lookup_records(host, types, resolver_choice="system"):
    if not host: return None
    host = _puny(host)
    out = []
    for t in [t.upper() for t in types]:
        res = _resolve(host, t, resolver_choice)
        rows = []
        if res:
            for r in res:
                try:
                    if t == "A": rows.append(r.address)
                    elif t == "CNAME": rows.append(getattr(r,"target",r).to_text().rstrip("."))
                    elif t == "MX": rows.append(f"{r.preference} {r.exchange.to_text().rstrip('.')}")
                    elif t == "TXT":
                        rows.append(b"".join(getattr(r,"strings",[])).decode("utf-8","ignore") if getattr(r,"strings",None) else r.to_text().strip('"'))
                    else: rows.append(r.to_text())
                except Exception: pass
        out.append({"type": t, "host": host, "records": rows})
    return out

# ------- RBL checks -------
RBL_ZONES = [
    {"zone":"zen.spamhaus.org",     "label":"Spamhaus ZEN"},
    {"zone":"bl.spamcop.net",       "label":"SpamCop"},
    {"zone":"dnsbl.sorbs.net",      "label":"SORBS"},
    {"zone":"b.barracudacentral.org","label":"Barracuda"},
]

def _rbl_query_ip_with_timing(ip, resolver_choice="system"):
    """RBL query with individual timing and delist URLs"""
    if ":" in ip:
        return [{"zone":z["zone"],"label":z["label"],"status":"skipped","txt":"IPv6 not checked","ms":0,"note":"","delist":None} for z in RBL_ZONES]
    
    rev = ".".join(ip.split(".")[::-1])
    rows = []
    delist_urls = {
        "zen.spamhaus.org": "https://www.spamhaus.org/lookup/",
        "bl.spamcop.net": "https://www.spamcop.net/bl.shtml",
        "dnsbl.sorbs.net": "https://www.sorbs.net/lookup.shtml",
        "b.barracudacentral.org": "https://www.barracudacentral.org/rbl/removal-request"
    }
    
    for z in RBL_ZONES:
        name = f"{rev}.{z['zone']}"
        start = time.time()
        try:
            a = _resolve(name,"A",resolver_choice)
            if a:
                status, txt = "listed", None
                t = _resolve(name,"TXT",resolver_choice)
                if t:
                    try:
                        txt = b"".join(getattr(t[0],"strings",[])).decode("utf-8","ignore") if getattr(t[0],"strings",None) else t[0].to_text().strip('"')
                    except Exception: pass
            else:
                status, txt = "not_listed", None
        except Exception:
            status, txt = "error", None
        
        ms = int((time.time() - start) * 1000)
        delist = delist_urls.get(z['zone'])
        rows.append({
            "zone":z["zone"],
            "label":z["label"],
            "status":status,
            "txt":txt,
            "ms":ms,
            "note":"",
            "delist":delist
        })
    return rows

def rbl_check_target(target, resolver_choice="system"):
    if not target: return None
    start = time.time()
    
    target = target.strip()
    ips = []
    try:
        ipaddress.ip_address(target); ips=[target]
    except Exception:
        a = _resolve(_puny(target),"A",resolver_choice)
        if a:
            for rr in a:
                try: ips.append(rr.address)
                except Exception: pass
    
    results = []
    for ip in ips:
        lists = _rbl_query_ip_with_timing(ip, resolver_choice)
        results.append({"ip": ip, "lists": lists})
    
    duration_ms = int((time.time() - start) * 1000)
    checked = len(RBL_ZONES) * len(ips) if ips else 0
    
    return {
        "target": target, 
        "ips": ips, 
        "results": results,
        "duration_ms": duration_ms,
        "checked": checked
    }

# ------- E-mail DNS Check (SPF/DKIM/DMARC) -------
@lru_cache(maxsize=512)
def _find_spf_record(domain, resolver_choice="system"):
    return next((t for t in _txt_values(_puny(domain), resolver_choice) if t.lower().startswith("v=spf1")), None)

def _terms(rec):
    if not rec: return []
    s = re.sub(r"\s+"," ",rec.strip()).replace(";"," ")
    return [p for p in s.split(" ") if p and p.lower()!="v=spf1"]

def _redirect_domain(rec):
    for t in _terms(rec):
        m = re.match(r"(?i)redirect(?:=|:)([\w\.-]+)", t)
        if m: return m.group(1).lower()
    return None

def _gather_redirect_chain(domain, resolver_choice="system"):
    chain, visited = [], set()
    rec = _find_spf_record(domain, resolver_choice)
    root = rec
    while True:
        rd = _redirect_domain(rec or "")
        if not rd: break
        if rd in visited:
            chain.append({"domain": rd, "record": None, "note":"loop detected"}); break
        visited.add(rd)
        hop = _find_spf_record(rd, resolver_choice)
        chain.append({"domain": rd, "record": hop})
        rec = hop or ""
    return root, chain

def _includes(rec):
    inc=[]
    for t in _terms(rec):
        m=re.match(r"(?i)include:([\w\.-]+)",t)
        if m: inc.append(m.group(1).lower())
    return inc

def _lookup_count(rec):
    detail={"include":0,"a":0,"mx":0,"ptr":0,"exists":0,"redirect":0}
    c=0
    for t in _terms(rec):
        lt=t.lower()
        if lt.startswith("include:"): detail["include"]+=1; c+=1
        elif lt=="a" or lt.startswith("a:"): detail["a"]+=1; c+=1
        elif lt=="mx" or lt.startswith("mx:"): detail["mx"]+=1; c+=1
        elif lt.startswith("ptr"): detail["ptr"]+=1; c+=1
        elif lt.startswith("exists:"): detail["exists"]+=1; c+=1
        elif lt.startswith("redirect=") or lt.startswith("redirect:"): detail["redirect"]+=1; c+=1
    return c, detail

def _expand_includes(domain, resolver_choice="system"):
    seen=set(); stack=[domain]; hops=[]
    while stack:
        d=stack.pop()
        if d in seen: continue
        seen.add(d)
        rec=_find_spf_record(d, resolver_choice)
        hops.append({"domain":d,"record":rec})
        if rec:
            for inc in _includes(rec):
                if inc not in seen: stack.append(inc)
    return hops

def check_mx(domain, resolver_choice="system"):
    hosts, ok=[], False
    ans=_resolve(_puny(domain),"MX",resolver_choice)
    if ans:
        for r in ans:
            try: hosts.append(r.exchange.to_text().rstrip(".")); ok=True
            except Exception: pass
    return {"ok":ok,"hosts":hosts}

def check_spf(domain, mx_hosts, resolver_choice="system"):
    base, chain = _gather_redirect_chain(domain, resolver_choice)
    if not base:
        return {"present": False, "record": None, "effective_record": None, "issues": ["Missing SPF record"], "info": [], "redirect_chain": chain, "include_hops": [], "lookup_count": 0, "lookup_detail": {}}

    effective = base
    if chain:
        for hop in chain:
            if hop.get("record"): effective = hop["record"]

    include_hops = _expand_includes(domain, resolver_choice)
    if effective and effective != base:
        inc2 = _expand_includes(_redirect_domain(base) or domain, resolver_choice)
        have=set([h["domain"] for h in include_hops])
        for h in inc2:
            if h["domain"] not in have:
                include_hops.append(h); have.add(h["domain"])

    total, detail = _lookup_count(effective)
    for hop in include_hops:
        if hop.get("record"):
            c,d = _lookup_count(hop["record"])
            total += c
            for k in detail: detail[k] += d.get(k,0)

    issues, info = [], []
    low=(effective or "").lower()
    if " -all" not in low: issues.append("SPF should end with -all (hard fail).")
    if " +all" in low or " ?all" in low: issues.append("Weak/unsafe 'all' mechanism (+all/?all).")
    if any(("outlook.com" in h) or ("protection.outlook.com" in h) for h in mx_hosts):
        if "include:spf.protection.outlook.com" not in low:
            issues.append("Using Microsoft 365? Add include:spf.protection.outlook.com.")
    if total > 10: issues.append(f"SPF may exceed 10 DNS lookups when includes are expanded (est. {total}).")

    return {
        "present": True,
        "record": base,
        "effective_record": effective,
        "redirect_chain": chain,
        "include_hops": include_hops,
        "lookup_count": total,
        "lookup_detail": detail,
        "issues": issues,
        "info": info,
    }

def check_dkim(domain, resolver_choice="system"):
    sels={}
    for s in ("selector1","selector2"):
        ans=_resolve(f"{s}._domainkey.{_puny(domain)}","CNAME",resolver_choice)
        if ans:
            try: sels[s]={"present":True,"cname":ans[0].target.to_text().rstrip(".")}
            except Exception: sels[s]={"present":True,"cname":None}
        else:
            sels[s]={"present":False,"cname":None}
    return sels

def check_dmarc(domain, resolver_choice="system"):
    txts=_txt_values(f"_dmarc.{_puny(domain)}",resolver_choice)
    rec=next((t for t in txts if t.lower().startswith("v=dmarc1")),None)
    if not rec:
        return {"present":False,"record":None,"policy":None,"issues":["Missing DMARC record"],"advice":[]}
    tags={}
    for part in [p.strip() for p in rec.split(";") if "=" in p]:
        k,v=part.split("=",1); tags[k.strip().lower()]=v.strip()
    policy=tags.get("p","").lower()
    issues, advice=[],[]
    if policy in ("","none"):
        issues.append("DMARC policy is 'none' (monitoring only).")
        advice.append("Ramp policy to quarantine → reject once aligned sources are ≥98% of volume.")
    if "rua" not in tags: issues.append("No DMARC aggregate reports (rua=).")
    if tags.get("adkim","").lower()!="s": advice.append("Consider adkim=s for strict DKIM alignment.")
    if tags.get("aspf","").lower()!="s": advice.append("Consider aspf=s for strict SPF alignment.")
    return {"present":True,"record":rec,"policy":policy,"issues":issues,"advice":advice,"tags":tags}

def run_dns_checks(domain, resolver_choice="system"):
    if not domain: return None
    domain=domain.strip().lower()
    mx=check_mx(domain, resolver_choice)
    spf=check_spf(domain, mx["hosts"], resolver_choice)
    dkim=check_dkim(domain, resolver_choice)
    dmarc=check_dmarc(domain, resolver_choice)
    return {"mx":mx,"spf":spf,"dkim":dkim,"dmarc":dmarc,"summary_ok": all([mx["ok"], spf.get("present"), dmarc.get("present")])}