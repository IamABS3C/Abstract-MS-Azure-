"""Single source of Abstract brand truth — palette, fonts, official logos.
Every viz/report imports from here. Official colors per the Abstract brand guide."""
from __future__ import annotations
import os

PINK, PINK_MID, PINK_DEEP = "#FF216B", "#E8005D", "#C2004C"
BG, WHITE = "#060608", "#FFFFFF"
TEAL, AMBER, BLUE = "#01e69d", "#f5c61e", "#2e9bf0"
INK, MUT, PANEL = "#e9e9f0", "#8a8a99", "#101016"
TYPE_COLOR = {"identity": TEAL, "account": BLUE, "host": "#b388ff", "nhi": AMBER,
              "agent": PINK, "device": "#b388ff", "session": "#feca57",
              "ip": "#ff6b6b", "domain": "#ff9f43", "url": "#feca57", "hash": "#9b9b9b"}
FONT_STACK = ('"Barlow","Barlow Semi Condensed",-apple-system,BlinkMacSystemFont,'
              '"Segoe UI",Roboto,sans-serif')
MONO_STACK = '"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace'

_LOGO_DIR = "/Users/mherbert/.claude/projects/-Users-mherbert/memory/assets"


def logo_svg(variant: str = "white") -> str:
    """Return official Abstract logo SVG markup ('white'|'black'|'mark'); '' if absent."""
    path = os.path.join(_LOGO_DIR, f"abstract-logo-{variant}.svg")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def theme_css() -> str:
    """A cohesive dark 'hunter/hacker' theme so console + widget text is always high-contrast,
    regardless of the Jupyter light/dark setting. Inject once (top of the notebook) with
    display(HTML(brand.theme_css())). Also styles the .as-shell container used by the console/wizard."""
    return f"""<style>
:root {{ --as-bg:{BG}; --as-panel:{PANEL}; --as-ink:{INK}; --as-mut:{MUT};
        --as-pink:{PINK}; --as-teal:{TEAL}; --as-amber:{AMBER}; --as-blue:{BLUE}; }}
/* ---- output content legibility on any theme ---- */
.jp-OutputArea-output, .output_area, .jp-RenderedHTMLCommon, .rendered_html {{
    color:var(--as-ink) !important; background:transparent !important; font-family:{FONT_STACK}; }}
.jp-RenderedHTMLCommon a, .rendered_html a, .as-shell a {{ color:var(--as-teal) !important; text-decoration:none; }}
.jp-RenderedHTMLCommon a:hover, .as-shell a:hover {{ text-decoration:underline; }}
.jp-RenderedHTMLCommon table, .rendered_html table {{ color:var(--as-ink) !important; }}
.jp-RenderedHTMLCommon th, .rendered_html th {{ background:#15151d !important; color:var(--as-teal) !important; }}
.jp-RenderedHTMLCommon td, .rendered_html td {{ border-color:#22222c !important; }}
/* ---- ipywidgets: labels, inputs, readouts ---- */
.jupyter-widgets, .widget-label, .widget-readout, .widget-html-content, .widget-inline-hbox .widget-label {{
    color:var(--as-ink) !important; font-family:{FONT_STACK}; }}
.widget-text input, .widget-textarea textarea, .widget-dropdown select, .widget-combobox input,
.jupyter-widgets input[type=text], .jupyter-widgets input[type=password], .jupyter-widgets select,
.jupyter-widgets textarea {{
    background:#15151d !important; color:var(--as-ink) !important; border:1px solid #2a2a35 !important;
    border-radius:6px !important; }}
.widget-text input:focus, .widget-dropdown select:focus, .jupyter-widgets input:focus {{
    border-color:var(--as-teal) !important; box-shadow:0 0 0 2px rgba(1,230,157,.25) !important; }}
.widget-slider .noUi-connect, .jupyter-widgets .ui-slider-range {{ background:var(--as-pink) !important; }}
/* ---- tabs (classic + lumino/phosphor) ---- */
.p-TabBar-tab, .lm-TabBar-tab {{ color:var(--as-mut) !important; background:transparent !important; }}
.p-TabBar-tab.p-mod-current, .lm-TabBar-tab.lm-mod-current {{
    color:var(--as-pink) !important; background:var(--as-panel) !important;
    border-top:2px solid var(--as-pink) !important; }}
/* ---- the console / wizard shell: modern dark w/ neon glow ---- */
.as-shell {{ color:var(--as-ink);
    background:
      radial-gradient(1100px 380px at 10% -10%, rgba(255,33,107,.12), transparent 60%),
      radial-gradient(900px 360px at 100% 0%, rgba(1,230,157,.08), transparent 55%),
      linear-gradient(180deg,#0a0a10 0%,{BG} 100%);
    border:1px solid #23232e; border-radius:14px; padding:16px 18px;
    box-shadow:0 0 0 1px rgba(255,33,107,.06), 0 18px 50px rgba(0,0,0,.5); }}
.as-shell, .as-shell * {{ font-family:{FONT_STACK}; }}
.as-shell code, .as-shell pre {{ font-family:{MONO_STACK}; color:#cdd6e2; background:#0f0f16; }}
.as-shell h1,.as-shell h2,.as-shell h3,.as-shell h4,.as-shell b {{ color:var(--as-ink); }}
.as-shell hr {{ border:none; border-top:1px solid #23232e; }}
.as-grid {{ background-image:linear-gradient(rgba(1,230,157,.05) 1px,transparent 1px),
    linear-gradient(90deg,rgba(1,230,157,.05) 1px,transparent 1px); background-size:22px 22px; }}
</style>"""


def theme_html():
    """Convenience: an ipywidgets-free HTML string that injects the theme + a subtle grid backdrop."""
    return theme_css()


def selftest():
    assert PINK == "#FF216B"
    assert "<style>" in theme_css() and "--as-ink" in theme_css()
    assert set(TYPE_COLOR) >= {"identity", "nhi", "agent", "device", "session"}
    assert logo_svg("mark") == "" or "<svg" in logo_svg("mark")
    return {"ok": True, "pink": PINK, "logo_present": bool(logo_svg("white"))}


if __name__ == "__main__":
    print(selftest())
