import os, json, base64, hmac, hashlib
from datetime import datetime, timezone
from flask import Flask, request, render_template, jsonify, make_response
import requests

app = Flask(__name__)

# ---------- ENV ----------
FUB_API_BASE = "https://api.followupboss.com/v1"
FUB_API_KEY  = os.getenv("FUB_API_KEY", "")          # set in Render → Settings → Environment
EMBED_SECRET = os.getenv("EMBED_SECRET", "")         # must match the secret in FUB Embedded App settings

# ---------- FIELD MAPPING (People/Contact custom fields) ----------
FIELD_KEYS = {
    "sentPropertyListAt":               "customSentPropertyListAt",
    "appointmentSetAt":                 "customAppointmentSetAt",
    "buyerCriteriaCollectedAt":         "customBuyerCriteriaCollectedAt",
    "qualificationQuestionsCompletedAt":"customQualificationQuestionsCompletedAt",
}

# ---------- HELPERS ----------
def _require_api_key():
    if not FUB_API_KEY:
        raise RuntimeError("FUB_API_KEY is not set")

def fub_headers():
    """FUB uses HTTP Basic with base64('API_KEY:')."""
    _require_api_key()
    basic = base64.b64encode(f"{FUB_API_KEY}:".encode("utf-8")).decode("utf-8")
    return {"Authorization": f"Basic {basic}", "Content-Type": "application/json", "Accept": "application/json"}

def fub_get(path):
    r = requests.get(FUB_API_BASE + path, headers=fub_headers(), timeout=20)
    if r.status_code >= 300:
        app.logger.error(f"[FUB GET {path}] {r.status_code} {r.text}")
        r.raise_for_status()
    return r.json() if r.text else {}

def fub_put(path, body):
    r = requests.put(FUB_API_BASE + path, headers=fub_headers(), data=json.dumps(body), timeout=20)
    if r.status_code >= 300:
        app.logger.error(f"[FUB PUT {path}] {r.status_code} {r.text}")
        r.raise_for_status()
    return r.json() if r.text else {}

def verify_sig(context_b64: str, signature: str, secret: str) -> bool:
    """
    FUB signs 'context' with HMAC-SHA256. Accept hex or base64url signatures.
    """
    if not secret:
        return True
    if not context_b64 or not signature:
        return False

    raw = hmac.new(secret.encode("utf-8"), context_b64.encode("utf-8"), hashlib.sha256).digest()
    hex_sig = raw.hex()
    b64_sig = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    # Normalize and compare constant-time style
    def norm(s): return s.strip().lower()
    return norm(signature) in (norm(hex_sig), norm(b64_sig))

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "===")  # tolerate missing padding


# ---------- ROUTES ----------
@app.get("/health")
def health():
    return "ok", 200


@app.get("/")
def index():
    """
    Loads in two modes:
    - Signed embed from FUB (context + signature required when EMBED_SECRET set)
    - Manual test: /?personId=123456  (works when EMBED_SECRET is empty)
    """
    person_id = request.args.get("personId")
    context_b64 = request.args.get("context", "")
    signature   = request.args.get("signature", "")

    if EMBED_SECRET:
        if not (context_b64 and signature) or not verify_sig(context_b64, signature, EMBED_SECRET):
            return make_response("Unauthorized (signature mismatch)", 401)
        try:
            ctx = json.loads(_b64url_decode(context_b64).decode("utf-8"))
            person_id = ((ctx.get("person")) or {}).get("id")
        except Exception:
            return make_response("Bad context payload", 400)

    if not person_id:
        return make_response("No person context", 400)

    # fetch current values
    person = fub_get(f"/people/{person_id}?fields=allFields") or {}
    values = {
        "sentPropertyListAt":                person.get(FIELD_KEYS["sentPropertyListAt"], ""),
        "appointmentSetAt":                  person.get(FIELD_KEYS["appointmentSetAt"], ""),
        "buyerCriteriaCollectedAt":          person.get(FIELD_KEYS["buyerCriteriaCollectedAt"], ""),
        "qualificationQuestionsCompletedAt": person.get(FIELD_KEYS["qualificationQuestionsCompletedAt"], ""),
    }

    html = render_template("index.html", personId=person_id, values=values)
    resp = make_response(html, 200)
    # Allow embedding in FUB
    resp.headers.pop("X-Frame-Options", None)
    return resp


@app.post("/toggle")
def toggle():
    """
    Payload:
      { personId: <int>, key: <one of FIELD_KEYS>, check: <bool> }
    Returns:
      { ok: true, at: <ISO timestamp or ''> }
    """
    data = request.get_json(force=True, silent=True) or {}
    person_id = data.get("personId")
    key   = data.get("key")
    check = bool(data.get("check"))

    if not person_id or key not in FIELD_KEYS:
        return jsonify({"ok": False, "error": "Bad payload"}), 400

    # server-side timestamp
    value = datetime.now(timezone.utc).isoformat() if check else ""
    body = { FIELD_KEYS[key]: value }

    try:
        fub_put(f"/people/{person_id}", body)
        return jsonify({"ok": True, "at": value})
    except Exception as e:
        app.logger.error(f"[TOGGLE ERROR] person={person_id} key={key} body={body} err={e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.after_request
def remove_xfo(resp):
    # Ensure FUB can iframe the page
    resp.headers.pop("X-Frame-Options", None)
    return resp


# Local dev support
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
