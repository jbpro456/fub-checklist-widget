import os, base64, hmac, hashlib, json
from datetime import datetime, timezone
from flask import Flask, request, render_template, jsonify, make_response
import requests

FUB_API_BASE = "https://api.followupboss.com/v1"
FUB_API_KEY = os.environ.get("FUB_API_KEY", "")
EMBED_SECRET = os.environ.get("EMBED_SECRET", "")

FIELD_KEYS = {
    "sentPropertyListAt": "customSentPropertyListAt",
    "appointmentSetAt": "customAppointmentSetAt",
    "buyerCriteriaCollectedAt": "customBuyerCriteriaCollectedAt",
    "qualificationQuestionsCompletedAt": "customQualificationQuestionsCompletedAt",
}

app = Flask(__name__)

def allow_iframe(resp):
    resp.headers["X-Frame-Options"] = "ALLOWALL"
    resp.headers["Content-Security-Policy"] = "frame-ancestors https://*.followupboss.com;"
    return resp

def verify_signature(context_b64: str, signature: str) -> bool:
    if not EMBED_SECRET:
        return True
    if not context_b64 or not signature:
        return False
    mac = hmac.new(EMBED_SECRET.encode("utf-8"), context_b64.encode("utf-8"), hashlib.sha256).digest()
    hex_sig = mac.hex()
    b64_sig = base64.urlsafe_b64encode(mac).decode("utf-8").rstrip("=")
    s = signature.strip().lower()
    return s == hex_sig.lower() or s == b64_sig.lower()

def fub_headers():
    token = base64.b64encode(f"{FUB_API_KEY}:".encode("utf-8")).decode("utf-8")
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}

def fub_get(path: str):
    r = requests.get(FUB_API_BASE + path, headers=fub_headers(), timeout=20)
    r.raise_for_status()
    return r.json() if r.text else {}

def fub_put(path: str, body: dict):
    r = requests.put(FUB_API_BASE + path, headers=fub_headers(), data=json.dumps(body), timeout=20)
    r.raise_for_status()
    return r.json() if r.text else {}

@app.after_request
def add_headers(resp):
    return allow_iframe(resp)

@app.get("/health")
def health():
    return "ok"

@app.get("/")
def index():
    person_id = request.args.get("personId")
    context_b64 = request.args.get("context", "")
    signature = request.args.get("signature", "")

    if EMBED_SECRET:
        if not verify_signature(context_b64, signature):
            return allow_iframe(make_response("Unauthorized (signature mismatch)", 401))
        try:
            ctx = json.loads(base64.urlsafe_b64decode(context_b64 + "==").decode("utf-8"))
        except Exception:
            return allow_iframe(make_response("Bad context payload", 400))
        person_id = (ctx.get("person") or {}).get("id")
        if not person_id:
            return allow_iframe(make_response("No person context", 400))
    else:
        if not person_id:
            return allow_iframe(make_response("No person context (set EMBED_SECRET or pass ?personId=)", 400))

    person = fub_get(f"/people/{person_id}?fields=allFields") or {}
    values = {
        "sentPropertyListAt": person.get(FIELD_KEYS["sentPropertyListAt"], "") or "",
        "appointmentSetAt": person.get(FIELD_KEYS["appointmentSetAt"], "") or "",
        "buyerCriteriaCollectedAt": person.get(FIELD_KEYS["buyerCriteriaCollectedAt"], "") or "",
        "qualificationQuestionsCompletedAt": person.get(FIELD_KEYS["qualificationQuestionsCompletedAt"], "") or "",
    }
    return render_template("index.html", personId=person_id, values=values)

@app.post("/toggle")
def toggle():
    data = request.get_json(force=True, silent=True) or {}
    person_id = data.get("personId")
    key = data.get("key")
    check = bool(data.get("check"))
    if not person_id or key not in FIELD_KEYS:
        return jsonify({"ok": False, "error": "Bad payload"}), 400
    field = FIELD_KEYS[key]
    body = {field: datetime.now(timezone.utc).isoformat() if check else ""}
    fub_put(f"/people/{person_id}", body)
    return jsonify({"ok": True, "at": body[field]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
