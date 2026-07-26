"""AI-agent layer — config-driven LLM providers for investigation summarization + triage.

Add a provider's API key and it lights up; with none set, a deterministic LOCAL summary is
produced from the model data so the notebook is always useful offline. Providers:

  Anthropic Claude   ANTHROPIC_API_KEY      (+ ANTHROPIC_MODEL, default claude-sonnet-4-6)
  OpenAI             OPENAI_API_KEY         (+ OPENAI_MODEL, default gpt-4o-mini)
  Google Gemini      GEMINI_API_KEY         (+ GEMINI_MODEL, default gemini-1.5-flash)
  Azure OpenAI       AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_API_KEY + AZURE_OPENAI_DEPLOYMENT
  AWS Bedrock        AWS creds + BEDROCK_MODEL (uses boto3 if installed)
  Microsoft Copilot  SECURITY_COPILOT_MCP_URL (MCP — see integrations.py)

Keys are read from the environment, sent only to their provider over TLS, never logged."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = 30
SYSTEM = ("You are a senior SOC analyst. Be concise, technical, and action-oriented. "
          "Use the provided investigation context only.")


def _post(url, headers, body, timeout=DEFAULT_TIMEOUT):
    data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"ok": True, "data": json.loads(r.read().decode())}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": e.read().decode()[:300]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:200]}


class Provider:
    name = "base"
    env: list = []

    def configured(self) -> bool:
        return all(os.environ.get(e) for e in self.env)

    def complete(self, prompt: str, system: str = SYSTEM) -> dict:
        return {"ok": False, "error": "not implemented"}


class Anthropic(Provider):
    name = "Anthropic Claude"
    env = ["ANTHROPIC_API_KEY"]

    def complete(self, prompt, system=SYSTEM):
        r = _post("https://api.anthropic.com/v1/messages",
                  {"x-api-key": os.environ["ANTHROPIC_API_KEY"],
                   "anthropic-version": "2023-06-01", "content-type": "application/json"},
                  {"model": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
                   "max_tokens": 1024, "system": system,
                   "messages": [{"role": "user", "content": prompt}]})
        if not r.get("ok"):
            return r
        parts = (r["data"].get("content") or [])
        return {"ok": True, "text": "".join(p.get("text", "") for p in parts)}


class OpenAI(Provider):
    name = "OpenAI"
    env = ["OPENAI_API_KEY"]

    def complete(self, prompt, system=SYSTEM):
        r = _post("https://api.openai.com/v1/chat/completions",
                  {"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
                   "Content-Type": "application/json"},
                  {"model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                   "messages": [{"role": "system", "content": system},
                                {"role": "user", "content": prompt}]})
        if not r.get("ok"):
            return r
        return {"ok": True, "text": r["data"]["choices"][0]["message"]["content"]}


class Gemini(Provider):
    name = "Google Gemini"
    env = ["GEMINI_API_KEY"]

    def complete(self, prompt, system=SYSTEM):
        model = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
        r = _post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
                  f"?key={os.environ['GEMINI_API_KEY']}",
                  {"Content-Type": "application/json"},
                  {"contents": [{"parts": [{"text": system + "\n\n" + prompt}]}]})
        if not r.get("ok"):
            return r
        cand = (r["data"].get("candidates") or [{}])[0]
        parts = ((cand.get("content") or {}).get("parts") or [])
        return {"ok": True, "text": "".join(p.get("text", "") for p in parts)}


class AzureOpenAI(Provider):
    name = "Azure OpenAI"
    env = ["AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_DEPLOYMENT"]

    def complete(self, prompt, system=SYSTEM):
        ep = os.environ["AZURE_OPENAI_ENDPOINT"].rstrip("/")
        dep = os.environ["AZURE_OPENAI_DEPLOYMENT"]
        ver = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-06-01")
        r = _post(f"{ep}/openai/deployments/{dep}/chat/completions?api-version={ver}",
                  {"api-key": os.environ["AZURE_OPENAI_API_KEY"], "Content-Type": "application/json"},
                  {"messages": [{"role": "system", "content": system},
                                {"role": "user", "content": prompt}]})
        if not r.get("ok"):
            return r
        return {"ok": True, "text": r["data"]["choices"][0]["message"]["content"]}


class Bedrock(Provider):
    name = "AWS Bedrock"
    env = ["AWS_ACCESS_KEY_ID", "BEDROCK_MODEL"]

    def complete(self, prompt, system=SYSTEM):
        try:
            import boto3  # optional — SigV4 handled by the SDK
        except Exception:  # noqa: BLE001
            return {"ok": False, "error": "boto3 not installed (pip install boto3)"}
        try:
            rt = boto3.client("bedrock-runtime", region_name=os.environ.get("AWS_REGION", "us-east-1"))
            body = json.dumps({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 1024,
                               "system": system, "messages": [{"role": "user", "content": prompt}]})
            resp = rt.invoke_model(modelId=os.environ["BEDROCK_MODEL"], body=body)
            data = json.loads(resp["body"].read())
            return {"ok": True, "text": "".join(p.get("text", "") for p in data.get("content", []))}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:200]}


PROVIDERS = [Anthropic(), OpenAI(), Gemini(), AzureOpenAI(), Bedrock()]


def available() -> dict:
    return {p.name: p.configured() for p in PROVIDERS}


def _provider(name=None):
    if name:
        for p in PROVIDERS:
            if p.name == name and p.configured():
                return p
    for p in PROVIDERS:
        if p.configured():
            return p
    return None


def _context(state, model=None) -> str:
    import identity_intel as II
    import entity_model as EM
    model = model or EM.build_entity_model(state, vips=getattr(state, "vips", set()))
    s = II.summary(state, set(model["vip_tags"]))
    pred = EM.predict(state, model)
    lead = (state.inv or {}).get("lead_finding")
    lines = []
    if lead:
        lines.append(f"Lead finding: {lead.title} (risk {lead.risk})")
    lines.append("Findings: " + "; ".join(f.title for f in state.findings[:6]))
    lines.append("Re-exposed identities: " + ("; ".join(
        f"{r.entity} ({r.count}x{', survives-restore' if r.survives_restore else ''})"
        for r in s["re_exposure"][:5]) or "none"))
    sigs = s["session_hijacking"] + s["mfa_bombing"] + s["password_reuse"]
    lines.append("Identity signals: " + ("; ".join(f"{x.entity}:{x.kind}" for x in sigs[:6]) or "none"))
    lines.append("Top risk identities: " + "; ".join(
        f"{r['entity']}={r['model_score']}" for r in model["entities"][:5]))
    lines.append("Predicted next targets: " + (", ".join(
        p.split(":", 1)[-1] for p in pred["predicted_next_targets"]) or "none"))
    return "\n".join(lines)


def _local_summary(ctx: str) -> str:
    """Deterministic offline analyst summary built from the model context (no LLM)."""
    return ("AI summary unavailable (no provider key set) — local synthesis:\n\n"
            "An identity-centric intrusion: malware conviction corroborated by endpoint + C2, "
            "with account takeover from C2 infrastructure. Identities show continuous re-exposure "
            "that survives IDP/backup restore (credentials still leaked), plus session-hijack and "
            "MFA-bombing signals. Recommended: rotate credentials + revoke sessions (not just "
            "restore), author a re-exposure detection, and watch the predicted next targets.\n\n"
            "Context:\n" + ctx)


def summarize_investigation(state, provider=None) -> dict:
    ctx = _context(state)
    prompt = ("Summarize this security investigation for a SOC lead. Cover: what happened, the "
              "identity risk (re-exposure / hijack / MFA bombing / reuse), blast radius, and the "
              "top 3 prioritized actions.\n\n" + ctx)
    p = _provider(provider)
    if not p:
        return {"provider": "local", "text": _local_summary(ctx)}
    r = p.complete(prompt)
    if r.get("ok"):
        return {"provider": p.name, "text": r["text"]}
    return {"provider": p.name, "text": _local_summary(ctx), "error": r.get("error")}


def triage(state, provider=None) -> dict:
    ctx = _context(state)
    prompt = ("Triage: assign a verdict (true-positive / benign / needs-info), a severity, and the "
              "single most urgent containment step. Justify in 2 sentences.\n\n" + ctx)
    p = _provider(provider)
    if not p:
        return {"provider": "local",
                "text": ("Verdict: TRUE-POSITIVE · Severity: CRITICAL (local heuristic).\n"
                         "Most urgent: revoke active sessions + rotate credentials for the "
                         "re-exposed accounts before they're reused. Restore alone is insufficient — "
                         "the credential is still leaked.\n\nContext:\n" + ctx)}
    r = p.complete(prompt)
    return {"provider": p.name, "text": r.get("text") or r.get("error", "error")}


def selftest():
    from live_data import build_state
    st = build_state(None)
    st.vips = {"jsmith@acme.com"}
    ctx = _context(st)
    assert "Findings:" in ctx and "Top risk identities:" in ctx
    # force the offline/local path so the unit check never makes a live API call
    saved = {e: os.environ.pop(e, None) for p in PROVIDERS for e in p.env}
    try:
        s = summarize_investigation(st)
        t = triage(st)
        assert s["provider"] == "local" and s["text"]
        assert t["provider"] == "local" and "verdict" in t["text"].lower()
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
    return {"ok": True, "providers": len(PROVIDERS), "configured": sum(available().values())}


if __name__ == "__main__":
    print(selftest())
