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


def selftest():
    assert PINK == "#FF216B"
    assert set(TYPE_COLOR) >= {"identity", "nhi", "agent", "device", "session"}
    assert logo_svg("mark") == "" or "<svg" in logo_svg("mark")
    return {"ok": True, "pink": PINK, "logo_present": bool(logo_svg("white"))}


if __name__ == "__main__":
    print(selftest())
