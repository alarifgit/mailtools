import re

def _unfold(block):  # handle folded headers
    return re.sub(r"\r?\n[ \t]+", " ", block)

def _find_all(block, name):
    pattern = rf"(?im)^{re.escape(name)}:\s*.*(?:\n[ \t].*)*"
    return [_unfold(m).split(":",1)[1].strip() for m in re.findall(pattern, block)]

def _first(vals):
    for v in vals:
        if v and v.strip(): return v.strip()
    return None

def _flag(ar_value, token):
    b=(ar_value or "").lower()
    if f"{token}=pass" in b: return "pass"
    if f"{token}=fail" in b: return "fail"
    if "temperror" in b or "tempfail" in b or "permerror" in b or "permfail" in b: return "error"
    if token=="spf":
        if "received-spf: pass" in b: return "pass"
        if "received-spf: fail" in b or "softfail" in b: return "fail"
        if "received-spf: none" in b: return "unknown"
    return "unknown"

def analyze_headers(raw):
    if not raw: return None

    ar = _find_all(raw, "Authentication-Results") or _find_all(raw, "ARC-Authentication-Results") or _find_all(raw, "Authentication-Results-Original")
    ar_top = _first(ar) or ""
    rspf_list = _find_all(raw, "Received-SPF"); rspf_top = _first(rspf_list) or ""

    scl_list = _find_all(raw, "X-MS-Exchange-Organization-SCL") or _find_all(raw, "X-Forefront-Antispam-Report")
    scl=None
    for v in (scl_list or [])[::-1]:
        m = re.search(r"(?i)\bSCL\s*[:=]\s*(-?\d+)", v) or re.search(r"(?i)\bSCL\s*[:=]\s*(-?\d+)", "SCL:"+v)
        if m: scl=m.group(1); break
    if scl is None:
        scl = _first(_find_all(raw, "X-MS-Exchange-Organization-SCL"))

    dkim_sig = _first(_find_all(raw, "DKIM-Signature"))

    verdict = {
        "spf": _flag(ar_top, "spf") if ar_top else _flag(rspf_top, "spf"),
        "dkim": _flag(ar_top, "dkim"),
        "dmarc": _flag(ar_top, "dmarc"),
        "scl": scl,
    }

    tips=[]
    if "permerror" in rspf_top.lower() and verdict["spf"]=="pass":
        tips.append("Earlier hop shows SPF permerror, but final hop passes — forwarding or multi-hop processing likely.")
    if verdict["dmarc"]=="fail" and verdict["dkim"]=="pass":
        tips.append("DMARC failed though DKIM passed → likely From-domain misalignment (d= differs from 5322.From).")
    if "softfail" in rspf_top.lower() or "~all" in rspf_top.lower():
        tips.append("SPF softfail observed at an intermediate hop. Authorize the sending IP or rely on DKIM alignment.")
    try:
        if scl is not None and int(scl) >= 5:
            tips.append("High spam score (SCL≥5). Improve content, add List-Unsubscribe, and check sender reputation.")
        if scl is not None and int(scl) == -1:
            tips.append("SCL -1 indicates trusted/bulk sender in Microsoft 365.")
    except Exception:
        pass
    if not ar and not rspf_list:
        tips.append("No recognizable Authentication-Results/Received-SPF found — they may have been removed by relays.")
    if dkim_sig and verdict["dkim"] in ("fail","error"):
        tips.append("DKIM present but not passing. Check canonicalization/body changes.")

    return {"verdict": verdict, "tips": tips, "raw": raw, "found": {"authentication_results": ar, "received_spf": rspf_list[:5]}}
