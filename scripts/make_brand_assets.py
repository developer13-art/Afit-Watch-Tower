#!/usr/bin/env python3
"""
Derive every brand image this system ships from one emblem file.

The source of truth is ``personnel-app/public/brand/afit-emblem.png``. Everything else — the
personnel app's web favicon, its Android launcher icons at all five densities, its adaptive-icon
foreground layers, its native splash screens, and the monitoring console's favicon and rail logo —
is generated from it, so replacing the emblem is one command instead of fourteen hand-saved PNGs
that silently disagree with each other.

    python scripts/make_brand_assets.py [path/to/official_emblem.png]

Run it from the repository root. With a source path, the script first normalises that file into
the emblem above (drops the dark surround painted outside the crest's rounded frame, crops,
resizes to 512px); without one it regenerates the derived set from the emblem already here.

Requires Pillow. The launcher and splash assets only matter to a native build, so this is a
build-time tool and deliberately not part of ``npm run verify`` or ``pytest``.
"""

from __future__ import annotations

import sys
from collections import deque
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "personnel-app"
EMBLEM = APP / "public" / "brand" / "afit-emblem.png"
RES = APP / "android" / "app" / "src" / "main" / "res"
CONSOLE_IMG = ROOT / "src" / "watchtower" / "api" / "web" / "static" / "img"

EMBLEM_SIZE = 512
# A pixel belongs to the surround when it is dark and has no colour in it. The crest's own
# shadowed areas are dark too, but they are not connected to the border, and only border-
# connected pixels are removed — that is why this is a flood fill and not a threshold.
SURROUND_LUMA_MAX = 40
SURROUND_SPREAD_MAX = 24

# Launcher icon side per density bucket, and the adaptive-icon canvas (108dp) per bucket.
MIPMAP_SIZES = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
ADAPTIVE_SIZES = {"mdpi": 108, "hdpi": 162, "xhdpi": 216, "xxhdpi": 324, "xxxhdpi": 432}
# Adaptive icons are masked to a circle by the launcher and only the centre 66dp of the 108dp
# canvas is guaranteed visible. The emblem carries its own frame and wordmark, so it goes inside
# that safe zone whole rather than being cropped by a mask that would cut the wordmark off.
ADAPTIVE_SAFE_FRACTION = 0.62

# Capacitor's own splash canvases, matched to the sizes the generated android/ project ships.
SPLASH_SIZES = {
    "drawable": (480, 320),
    "drawable-port-mdpi": (320, 480),
    "drawable-port-hdpi": (480, 800),
    "drawable-port-xhdpi": (720, 1280),
    "drawable-port-xxhdpi": (960, 1600),
    "drawable-port-xxxhdpi": (1280, 1920),
    "drawable-land-mdpi": (480, 320),
    "drawable-land-hdpi": (800, 480),
    "drawable-land-xhdpi": (1280, 720),
    "drawable-land-xxhdpi": (1600, 960),
    "drawable-land-xxxhdpi": (1920, 1280),
}
SPLASH_BACKGROUND = (8, 11, 17)  # backgroundColor in capacitor.config.ts
SPLASH_FRACTION = 0.6


def is_surround(r: int, g: int, b: int) -> bool:
    return max(r, g, b) <= SURROUND_LUMA_MAX and (max(r, g, b) - min(r, g, b)) <= SURROUND_SPREAD_MAX


def strip_surround(im: Image.Image) -> Image.Image:
    """Make the border-connected dark surround transparent, leaving the crest frame intact.

    Worked on the raw pixel buffer rather than per-pixel access because the supplied artwork is
    1.6 megapixels and this walks all of it.
    """
    rgba = im.convert("RGBA")
    width, height = rgba.size
    data = bytearray(rgba.tobytes())
    visited = bytearray(width * height)
    queue: deque[int] = deque()

    def seed(index: int) -> None:
        if is_surround(data[index], data[index + 1], data[index + 2]) and not visited[index // 4]:
            visited[index // 4] = 1
            queue.append(index)

    for x in range(width):
        seed(x * 4)
        seed(((height - 1) * width + x) * 4)
    for y in range(height):
        seed(y * width * 4)
        seed((y * width + width - 1) * 4)
    while queue:
        index = queue.popleft()
        pixel = index // 4
        x, y = pixel % width, pixel // width
        data[index + 3] = 0
        for nx, ny in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)):
            if 0 <= nx < width and 0 <= ny < height:
                neighbour = (ny * width + nx) * 4
                if not visited[neighbour // 4] and is_surround(
                    data[neighbour], data[neighbour + 1], data[neighbour + 2]
                ):
                    visited[neighbour // 4] = 1
                    queue.append(neighbour)
    cleaned = Image.frombytes("RGBA", rgba.size, bytes(data))
    boxed = cleaned.crop(cleaned.getbbox() or cleaned.size)
    side = max(boxed.size)
    square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    square.paste(boxed, ((side - boxed.width) // 2, (side - boxed.height) // 2))
    return square.resize((EMBLEM_SIZE, EMBLEM_SIZE), Image.LANCZOS)


def backdrop_colour(emblem: Image.Image) -> tuple[int, int, int]:
    """The dominant dark field of the artwork, so the launcher background reads as continuous."""
    rgb = emblem.convert("RGB")
    pixels = rgb.load()
    total = [0, 0, 0]
    count = 0
    for y in range(0, rgb.height, 4):
        for x in range(0, rgb.width, 4):
            sample = pixels[x, y]
            if max(sample) <= 90:
                for i in range(3):
                    total[i] += sample[i]
                count += 1
    if not count:
        return (8, 11, 17)
    return tuple(round(v / count) for v in total)  # type: ignore[return-value]


def on_backdrop(
    emblem: Image.Image, size: int, background: tuple[int, int, int, int], scale: float = 1.0
) -> Image.Image:
    canvas = Image.new("RGBA", (size, size), background)
    side = max(1, round(size * scale))
    art = emblem.resize((side, side), Image.LANCZOS)
    canvas.paste(art, ((size - side) // 2, (size - side) // 2), art)
    return canvas


def circular(im: Image.Image) -> Image.Image:
    mask = Image.new("L", im.size, 0)
    ImageDraw.Draw(mask).ellipse((0, 0, im.width - 1, im.height - 1), fill=255)
    out = im.copy()
    out.putalpha(mask)
    return out


def splash(emblem: Image.Image, width: int, height: int) -> Image.Image:
    canvas = Image.new("RGBA", (width, height), (*SPLASH_BACKGROUND, 255))
    side = max(1, round(min(width, height) * SPLASH_FRACTION))
    art = emblem.resize((side, side), Image.LANCZOS)
    canvas.paste(art, ((width - side) // 2, (height - side) // 2), art)
    return canvas


def write(im: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # The stock splash canvases are RGB; keeping that avoids changing what Android does with
    # the alpha channel for a file that is only ever drawn on an opaque background.
    (im.convert("RGB") if path.name == "splash.png" else im).save(path, "PNG", optimize=True)
    print(f"wrote {path.relative_to(ROOT)} {im.size[0]}x{im.size[1]} {path.stat().st_size} bytes")


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(__doc__)
        return 2
    if len(argv) == 2:
        source = Path(argv[1])
        if not source.is_file():
            print(f"no such file: {source}")
            return 1
        EMBLEM.parent.mkdir(parents=True, exist_ok=True)
        strip_surround(Image.open(source)).save(EMBLEM, "PNG", optimize=True)
        print(f"normalised {source} -> {EMBLEM.relative_to(ROOT)} ({EMBLEM.stat().st_size} bytes)")

    emblem = Image.open(EMBLEM).convert("RGBA")
    if emblem.width != emblem.height:
        print(f"{EMBLEM} must be square, got {emblem.size}")
        return 1
    background = (*backdrop_colour(emblem), 255)

    # Web: a favicon is fetched on every cold load of a sign-in page, so it gets its own small
    # file rather than the 512px artwork.
    write(emblem.resize((64, 64), Image.LANCZOS), APP / "public" / "favicon.png")
    write(on_backdrop(emblem, 180, background), APP / "public" / "apple-touch-icon.png")

    # The monitoring console draws the same emblem in a 34px rail mark and a 40px login mark, so
    # 128px is enough for a 3x display without putting a 380 KB file on every page load.
    write(emblem.resize((64, 64), Image.LANCZOS), CONSOLE_IMG / "favicon.png")
    write(emblem.resize((128, 128), Image.LANCZOS), CONSOLE_IMG / "afit-emblem.png")

    for density, size in MIPMAP_SIZES.items():
        folder = RES / f"mipmap-{density}"
        write(on_backdrop(emblem, size, background), folder / "ic_launcher.png")
        write(circular(on_backdrop(emblem, size, background)), folder / "ic_launcher_round.png")
        write(
            on_backdrop(emblem, ADAPTIVE_SIZES[density], (0, 0, 0, 0), ADAPTIVE_SAFE_FRACTION),
            folder / "ic_launcher_foreground.png",
        )

    for folder, (w, h) in SPLASH_SIZES.items():
        write(splash(emblem, w, h), RES / folder / "splash.png")

    launcher_background = RES / "values" / "ic_launcher_background.xml"
    launcher_background.write_text(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<resources>\n"
        f'    <color name="ic_launcher_background">#{background[0]:02X}{background[1]:02X}{background[2]:02X}</color>\n'
        "</resources>\n",
        encoding="utf-8",
    )
    print(f"updated {launcher_background.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
