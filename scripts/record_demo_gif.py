"""Record docs/demo.gif from the real /gateway/demo page (the side-by-side "backend alone vs through the gateway" view).

Not part of the gateway or its tests, and its dependencies are not in any requirements file:

    python -m venv .venv-demo && .venv-demo/bin/pip install playwright pillow      # Windows: .venv-demo\\Scripts
    GATEWAY_IP_RATE_LIMIT=0 DEMO_RATE_LIMIT=1000 uvicorn gateway.app:app --port 8123
    .venv-demo/bin/python scripts/record_demo_gif.py --base http://127.0.0.1:8123

It drives the installed Microsoft Edge (`channel="msedge"`, no browser download); use --channel chrome for Chrome.

What is recorded, so the GIF cannot be read as more than it is:
  * the page is the unmodified demo page; the only interference is at the network layer: each run is sent with a fresh `session_id`, because the
    demo page sends none and every run would otherwise share one session, whose adaptive risk score (rises after each block) would make later cases
    depend on earlier ones. So each case below is what that prompt gets on its own, as in a first request.
  * the cases are the demo's own (the author's), chosen to show both outcomes: three blocked attacks, one benign prompt allowed, and one attack the gateway
    does NOT stop. They are not a detection rate: the held-out numbers are in the README's Results section.
"""
import argparse
import io
import json
import uuid
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[1]

# (case id, ms to hold the result on screen, caption under the result). The page paints every ALLOWED verdict red, even for a benign prompt,
# so the caption says what the frame is showing.
SEQUENCE = [
    ("GW-001", 3400, "Classic override. The backend alone complies; the gateway blocks it with a rule."),
    ("GW-015", 3400, "Out-of-scope data request. The backend alone dumps the org database; the gateway blocks it with a rule."),
    ("GW-007", 3400, "Roleplay jailbreak. No rule matches; the classifier blocks it."),
    ("GW-036", 3400, "A benign request: allowed on both sides, as it should be (this page shows every ALLOWED in red)."),
    ("GW-033", 3800, "A miss: this social-engineering prompt gets through the gateway."),
]
CAPTION_HEIGHT = 46


def _font(size: int):
    for name in ("segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def frame(page, box, caption: str = ""):
    """A screenshot with a caption band under it (so every frame says what it shows)."""
    shot = Image.open(io.BytesIO(page.screenshot(clip=box))).convert("RGB")
    canvas = Image.new("RGB", (shot.width, shot.height + CAPTION_HEIGHT), (13, 17, 23))
    canvas.paste(shot, (0, 0))
    ImageDraw.Draw(canvas).text((18, shot.height + 13), caption, fill=(230, 237, 243), font=_font(19))
    return canvas


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8123")
    ap.add_argument("--out", default=str(REPO / "docs" / "demo.gif"))
    ap.add_argument("--channel", default="msedge")
    ap.add_argument("--width", type=int, default=1000)
    ap.add_argument("--height", type=int, default=940)
    ap.add_argument("--colors", type=int, default=96)
    ap.add_argument("--debug-dir", default="", help="also write every frame as a PNG here, for looking at the result")
    args = ap.parse_args()

    frames: list[tuple[Image.Image, int]] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(channel=args.channel, headless=True)
        page = browser.new_page(viewport={"width": args.width, "height": args.height})

        def fresh_session(route):
            body = json.loads(route.request.post_data or "{}")
            body["session_id"] = "gif-" + uuid.uuid4().hex[:8]
            route.continue_(post_data=json.dumps(body))

        page.route("**/gateway/demo/run", fresh_session)

        for case_id, hold_ms, caption in SEQUENCE:
            page.goto(args.base + "/gateway/demo", wait_until="networkidle")
            page.wait_for_selector(f"#case option[value='{case_id}']", state="attached")
            if page.is_visible("#guide-body"):
                page.click(".guide-header")             # collapse the how-to panel so the two result columns are on screen
            page.select_option("#case", case_id)
            page.wait_for_timeout(250)
            box = {"x": 0, "y": 0, "width": args.width, "height": args.height}
            frames.append((frame(page, box, f"{case_id}: the same prompt will go to the backend directly and through the gateway."), 1200))
            page.click("#run")
            page.wait_for_function("document.getElementById('g-verdict').textContent.trim() !== '—'", timeout=30000)
            page.wait_for_timeout(300)
            frames.append((frame(page, box, caption), hold_ms))     # both verdicts
        browser.close()

    if args.debug_dir:
        Path(args.debug_dir).mkdir(parents=True, exist_ok=True)
        for i, (im, _) in enumerate(frames):
            im.save(Path(args.debug_dir) / f"frame{i:02d}.png")

    palettised = [im.quantize(colors=args.colors, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE) for im, _ in frames]
    out = Path(args.out)
    palettised[0].save(out, save_all=True, append_images=palettised[1:], duration=[d for _, d in frames], loop=0, optimize=True, disposal=1)
    print(f"{out} written: {len(frames)} frames, {out.stat().st_size / 1024:.0f} KiB")


if __name__ == "__main__":
    main()
