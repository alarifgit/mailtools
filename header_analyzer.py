import re
from typing import Dict, List, Optional

def _unfold(block):
    """Handle folded headers"""
    return re.sub(r"\r?\n[ \t]+", " ", block)

def _find_all(block, name):
    """Find all instances of a header"""
    pattern = rf"(?im)^{re.escape(name)}:\s*.*(?:\n[ \t].*)*"
    return [_unfold(m).split(":",1)[1].strip() for m in re.findall(pattern, block)]

def _first(vals):
    """Get first non-empty value"""
    for v in vals:
        if v and v.strip(): return v.strip()
    return None

def _flag(ar_value, token):
    """Extract authentication result flag"""
    b = (ar_value or "").lower()
    if f"{token}=pass" in b: return "pass"
    if f"{token}=fail" in b: return "fail"
    if "temperror" in b or "tempfail" in b or "permerror" in b or "permfail" in b: return "error"
    if token == "spf":
        if "received-spf: pass" in b: return "pass"
        if "received-spf: fail" in b or "softfail" in b: return "fail"
        if "received-spf: none" in b: return "unknown"
    return "unknown"

def _extract_domain_from_header(header_value: str, header_name: str) -> Optional[str]:
    """Extract domain from From/Return-Path headers"""
    if not header_value:
        return None
    # Match email address
    match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', header_value)
    if match:
        return match.group(1).lower()
    return None

def _extract_ip_from_received(received: str) -> Optional[str]:
    """Extract sending IP from Received header"""
    if not received:
        return None
    # Look for IP in square brackets or after 'from'
    ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
    if ip_match:
        return ip_match.group(1)
    return None

def _analyze_authentication_flow(ar_list: List[str], rspf_list: List[str]) -> Dict:
    """Analyze authentication flow through email hops"""
    flow = {
        "total_hops": max(len(ar_list), len(rspf_list)),
        "authentication_consistent": True,
        "forwarding_detected": False,
        "issues": []
    }
    
    # Check for forwarding indicators
    if len(rspf_list) > 1:
        for i, rspf in enumerate(rspf_list):
            if "permerror" in rspf.lower() and i < len(rspf_list) - 1:
                flow["forwarding_detected"] = True
                flow["issues"].append(f"Hop {i+1}: SPF PermError detected, possible forwarding")
    
    # Check for authentication changes across hops
    if len(ar_list) > 1:
        prev_results = {}
        for i, ar in enumerate(ar_list):
            curr_spf = _flag(ar, "spf")
            curr_dkim = _flag(ar, "dkim")
            curr_dmarc = _flag(ar, "dmarc")
            
            if i > 0:
                if prev_results.get("spf") == "pass" and curr_spf != "pass":
                    flow["authentication_consistent"] = False
                    flow["issues"].append(f"Hop {i+1}: SPF changed from pass to {curr_spf}")
            
            prev_results = {"spf": curr_spf, "dkim": curr_dkim, "dmarc": curr_dmarc}
    
    return flow

def _generate_detailed_tips(verdict: Dict, analysis_data: Dict) -> List[Dict]:
    """Generate detailed, actionable tips with explanations"""
    tips = []
    
    # SPF Analysis
    if verdict["spf"] == "fail":
        tips.append({
            "severity": "high",
            "category": "SPF",
            "title": "SPF Authentication Failed",
            "description": "The sending server's IP address is not authorized in the domain's SPF record.",
            "action": "Add the sending IP to your SPF record or verify you're sending from an authorized server.",
            "learn_more": "SPF validates that email is sent from an authorized IP address for the domain."
        })
    elif verdict["spf"] == "softfail":
        tips.append({
            "severity": "medium",
            "category": "SPF",
            "title": "SPF Soft Fail",
            "description": "The sending IP is not explicitly authorized, but the domain owner hasn't enforced strict policy.",
            "action": "Review your SPF record and consider changing ~all to -all for stronger protection.",
            "learn_more": "Soft fail (~all) means the check failed but shouldn't be rejected immediately."
        })
    elif verdict["spf"] == "unknown" or verdict["spf"] == "none":
        tips.append({
            "severity": "medium",
            "category": "SPF",
            "title": "No SPF Record Found",
            "description": "The domain doesn't have an SPF record published in DNS.",
            "action": "Publish an SPF record in your DNS to specify which servers can send email for your domain.",
            "learn_more": "Without SPF, recipients can't verify if email from your domain is legitimate."
        })
    
    # DKIM Analysis
    if verdict["dkim"] == "fail":
        tips.append({
            "severity": "high",
            "category": "DKIM",
            "title": "DKIM Signature Verification Failed",
            "description": "The email's DKIM signature is invalid, indicating the message was modified in transit or improperly signed.",
            "action": "Check your DKIM private key configuration and ensure the message body isn't being altered by mail servers.",
            "learn_more": "DKIM creates a digital signature that proves the email hasn't been tampered with."
        })
    elif verdict["dkim"] == "unknown":
        dkim_present = analysis_data.get("dkim_signature_present", False)
        if dkim_present:
            tips.append({
                "severity": "medium",
                "category": "DKIM",
                "title": "DKIM Signature Not Verified",
                "description": "A DKIM signature is present but couldn't be verified by the receiving server.",
                "action": "Verify your DKIM DNS record is published correctly and matches your signing configuration.",
                "learn_more": "This often happens when the DNS record is missing or incorrectly formatted."
            })
        else:
            tips.append({
                "severity": "low",
                "category": "DKIM",
                "title": "No DKIM Signature",
                "description": "This email was not signed with DKIM.",
                "action": "Enable DKIM signing on your mail server to improve deliverability and email authentication.",
                "learn_more": "DKIM is optional but highly recommended for professional email sending."
            })
    
    # DMARC Analysis
    if verdict["dmarc"] == "fail":
        if verdict["spf"] == "pass" and verdict["dkim"] == "pass":
            tips.append({
                "severity": "high",
                "category": "DMARC",
                "title": "DMARC Alignment Failed",
                "description": "Both SPF and DKIM passed, but neither aligned with the From domain (header.from).",
                "action": "Ensure your DKIM d= domain or Return-Path domain matches the From domain.",
                "learn_more": "DMARC requires either SPF or DKIM to pass AND align with the visible From address."
            })
        else:
            tips.append({
                "severity": "high",
                "category": "DMARC",
                "title": "DMARC Policy Failure",
                "description": "The email failed DMARC authentication, which may result in delivery issues.",
                "action": "Fix SPF and/or DKIM authentication, ensuring at least one passes and aligns with the From domain.",
                "learn_more": "DMARC builds on SPF and DKIM to prevent domain spoofing."
            })
    elif verdict["dmarc"] == "unknown":
        tips.append({
            "severity": "medium",
            "category": "DMARC",
            "title": "No DMARC Record",
            "description": "The sending domain doesn't have a DMARC policy published.",
            "action": "Publish a DMARC record starting with p=none to begin monitoring, then gradually enforce stricter policies.",
            "learn_more": "DMARC allows you to control what happens to emails that fail authentication."
        })
    
    # Spam Score Analysis
    if verdict.get("scl"):
        try:
            scl = int(verdict["scl"])
            if scl >= 7:
                tips.append({
                    "severity": "high",
                    "category": "Spam",
                    "title": "High Spam Confidence Level",
                    "description": f"Microsoft assigned a spam score of {scl}/9, indicating high probability this is spam.",
                    "action": "Review email content, ensure proper authentication, add List-Unsubscribe headers, and check sender reputation.",
                    "learn_more": "SCL 5-9 means the message is likely spam. Fix authentication and content issues."
                })
            elif scl >= 5:
                tips.append({
                    "severity": "medium",
                    "category": "Spam",
                    "title": "Moderate Spam Score",
                    "description": f"Spam confidence level is {scl}/9. The message may be filtered or flagged.",
                    "action": "Improve email authentication, avoid spam trigger words, and ensure you have permission to email recipients.",
                    "learn_more": "SCL 5-6 indicates suspicious content or poor sender reputation."
                })
            elif scl == -1:
                tips.append({
                    "severity": "info",
                    "category": "Delivery",
                    "title": "Trusted Sender",
                    "description": "Microsoft has marked this as a trusted or bulk sender (SCL -1).",
                    "action": "No action needed. This email bypassed spam filtering.",
                    "learn_more": "SCL -1 indicates the sender is on a safe senders list or sending bulk mail."
                })
        except ValueError:
            pass
    
    # Forwarding Detection
    flow = analysis_data.get("authentication_flow", {})
    if flow.get("forwarding_detected"):
        tips.append({
            "severity": "medium",
            "category": "Routing",
            "title": "Email Forwarding Detected",
            "description": "This email appears to have been forwarded, which can break SPF authentication.",
            "action": "If you're using forwarding, consider using SRS (Sender Rewriting Scheme) or ensure DKIM passes for authentication.",
            "learn_more": "Forwarding changes the sending IP, causing SPF to fail. DKIM remains valid through forwarding."
        })
    
    return tips

def analyze_headers(raw: str) -> Optional[Dict]:
    """
    Enhanced header analysis with detailed insights
    """
    if not raw:
        return None

    # Extract all relevant headers
    ar = _find_all(raw, "Authentication-Results") or _find_all(raw, "ARC-Authentication-Results") or _find_all(raw, "Authentication-Results-Original")
    ar_top = _first(ar) or ""
    rspf_list = _find_all(raw, "Received-SPF")
    rspf_top = _first(rspf_list) or ""
    
    from_header = _first(_find_all(raw, "From"))
    return_path = _first(_find_all(raw, "Return-Path"))
    received_list = _find_all(raw, "Received")
    
    # Extract domains
    from_domain = _extract_domain_from_header(from_header, "From")
    return_path_domain = _extract_domain_from_header(return_path, "Return-Path")
    sending_ip = _extract_ip_from_received(received_list[0] if received_list else "")
    
    # SCL Analysis
    scl_list = _find_all(raw, "X-MS-Exchange-Organization-SCL") or _find_all(raw, "X-Forefront-Antispam-Report")
    scl = None
    for v in (scl_list or [])[::-1]:
        m = re.search(r"(?i)\bSCL\s*[:=]\s*(-?\d+)", v) or re.search(r"(?i)\bSCL\s*[:=]\s*(-?\d+)", "SCL:" + v)
        if m:
            scl = m.group(1)
            break
    if scl is None:
        scl = _first(_find_all(raw, "X-MS-Exchange-Organization-SCL"))
    
    # DKIM Signature
    dkim_sig = _first(_find_all(raw, "DKIM-Signature"))
    dkim_domain = None
    if dkim_sig:
        match = re.search(r'd=([^\s;]+)', dkim_sig)
        if match:
            dkim_domain = match.group(1).lower()
    
    # Build verdict
    verdict = {
        "spf": _flag(ar_top, "spf") if ar_top else _flag(rspf_top, "spf"),
        "dkim": _flag(ar_top, "dkim"),
        "dmarc": _flag(ar_top, "dmarc"),
        "scl": scl,
    }
    
    # Analyze authentication flow
    auth_flow = _analyze_authentication_flow(ar, rspf_list)
    
    # Additional analysis data
    analysis_data = {
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "dkim_domain": dkim_domain,
        "sending_ip": sending_ip,
        "dkim_signature_present": dkim_sig is not None,
        "authentication_flow": auth_flow,
        "alignment_check": {
            "spf_aligned": return_path_domain == from_domain if return_path_domain and from_domain else False,
            "dkim_aligned": dkim_domain == from_domain if dkim_domain and from_domain else False
        }
    }
    
    # Generate detailed tips
    detailed_tips = _generate_detailed_tips(verdict, analysis_data)
    
    # Legacy simple tips for backwards compatibility
    simple_tips = []
    if "permerror" in rspf_top.lower() and verdict["spf"] == "pass":
        simple_tips.append("Earlier hop shows SPF permerror, but final hop passes — forwarding or multi-hop processing likely.")
    if verdict["dmarc"] == "fail" and verdict["dkim"] == "pass":
        simple_tips.append("DMARC failed though DKIM passed → likely From-domain misalignment (d= differs from 5322.From).")
    if "softfail" in rspf_top.lower() or "~all" in rspf_top.lower():
        simple_tips.append("SPF softfail observed. Authorize the sending IP or rely on DKIM alignment.")
    
    return {
        "verdict": verdict,
        "tips": simple_tips,
        "detailed_tips": detailed_tips,
        "analysis_data": analysis_data,
        "raw": raw,
        "found": {
            "authentication_results": ar,
            "received_spf": rspf_list[:5],
            "from": from_header,
            "return_path": return_path,
            "sending_ip": sending_ip
        }
    }