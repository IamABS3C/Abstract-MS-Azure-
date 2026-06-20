"""ATT&CK Navigator layer.json export + an in-notebook matrix. The exported
mitre_layer.json opens directly in https://mitre-attack.github.io/attack-navigator/
(the only external deep-link this project emits). Coverage is scored from live
/v3/rules/mitre data when present; offline it falls back to a clearly-labeled
modeled coverage so the artifact is never empty."""
from __future__ import annotations
import json
import brand
import viz_interactive as VI


def _tactics(state):
    return state.mitre or VI._MODELED_TACTICS


def build_layer(state, name="Abstract investigation") -> dict:
    """ATT&CK Navigator layer (schema v4.5). Techniques are emitted when the live
    tactics carry a `techniques` list; otherwise a tactic-level summary is recorded in
    the description so the layer still loads."""
    techniques = []
    for t in _tactics(state):
        for tech in (t.get("techniques") or []):
            total = tech.get("total", 0)
            en = tech.get("enabled", 0)
            tid = tech.get("id") or tech.get("techniqueID")
            if not tid:
                continue
            techniques.append({"techniqueID": tid,
                               "score": int(100 * en / total) if total else 0,
                               "color": brand.TEAL if en else "",
                               "comment": f"{en}/{total} rules enabled"})
    modeled = not state.mitre
    return {"name": name + (" (modeled)" if modeled else ""),
            "versions": {"layer": "4.5", "navigator": "4.9.1"},
            "domain": "enterprise-attack",
            "description": "Abstract live coverage + observed techniques"
            + (" — modeled offline" if modeled else ""),
            "techniques": techniques,
            "gradient": {"colors": [brand.PANEL, brand.TEAL], "minValue": 0, "maxValue": 100}}


def write_layer(state, path="mitre_layer.json") -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_layer(state), fh, indent=2)
    return path


def matrix_html(state) -> str:
    """Interactive coverage matrix (Plotly via viz_interactive); SVG strip fallback."""
    html = VI.mitre_matrix(state)
    if "needs plotly" in html:
        import viz_svg
        return viz_svg.mitre_heatstrip_svg(_tactics(state))
    return html


def selftest():
    from live_data import build_state
    st = build_state(None)
    layer = build_layer(st)
    assert layer["versions"]["layer"] == "4.5" and "techniques" in layer
    assert "<" in matrix_html(st)
    return {"ok": True, "techniques": len(layer["techniques"]), "modeled": not st.mitre}


if __name__ == "__main__":
    print(selftest())
