"""Derive the header logo asset from the approved full EXPC logo.

Source (v1.0): assets/logo_Header_right.png (2030x775, RGB); earlier
releases used assets/new_logo_full.png (2172x724). The file has the
transparency checkerboard BAKED INTO its pixels (no alpha channel), so it
cannot be placed on the dark header as-is. This script removes ONLY that
neutral-grey checkerboard:

  * a pixel is background when it is neutral (R~G~B) and mid-grey -- the
    checker tones are ~135 and ~200, the artwork is saturated gold or dark
    outline / shadow;
  * antialiased edges get a ramped alpha and are un-mixed against a locally
    diffused estimate of the checker tone behind them (no grey halo);
  * every fully opaque artwork pixel keeps its exact original RGB.

Nothing is cropped, recoloured, redrawn or re-proportioned. The output is
downscaled with premultiplied (alpha-correct) Lanczos resampling to 2x the
header slot and written as raw RGBA (+ a PNG preview for review).

Usage:  python scripts/key_logo.py
"""

from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "logo_Header_right.png"
OUT_RGBA = ROOT / "assets" / "expc-header-logo-full.rgba"
OUT_PNG = ROOT / "assets" / "expc-header-logo-full.png"
# Header slot height is 104 points; embed at 2x for HiDPI. The width
# follows the SOURCE aspect ratio exactly (no squash / stretch / crop).
OUT_H = 208

# Background classifier thresholds.
CHROMA_BG = 16.0  # max-min channel spread of a checker pixel
CHROMA_FG = 46.0  # spread from which a pixel is certainly artwork
LUMA_LO = 104.0  # checker tones live in [~115, ~225]
LUMA_HI = 232.0


def diffuse_background(rgb: np.ndarray, bg: np.ndarray, iters: int = 24) -> np.ndarray:
    """Fill non-background pixels with the nearby checker tone (iterative
    normalized 3x3 averaging seeded by the background pixels)."""
    val = np.where(bg[..., None], rgb, 0.0)
    w = bg.astype(np.float64)
    for _ in range(iters):
        pv = np.pad(val, ((1, 1), (1, 1), (0, 0)), mode="edge")
        pw = np.pad(w, 1, mode="edge")
        sv = sum(pv[dy : dy + val.shape[0], dx : dx + val.shape[1]] for dy in range(3) for dx in range(3))
        sw = sum(pw[dy : dy + w.shape[0], dx : dx + w.shape[1]] for dy in range(3) for dx in range(3))
        grown = sw > 0
        est = np.where(grown[..., None], sv / np.maximum(sw, 1e-9)[..., None], 0.0)
        # Known background keeps its own value; unknown pixels take the estimate.
        val = np.where(bg[..., None], rgb, est)
        w = np.where(bg, 1.0, np.minimum(sw, 1.0) * (grown > 0))
    return val


def main() -> None:
    rgb = np.asarray(Image.open(SRC).convert("RGB")).astype(np.float64)
    chroma = rgb.max(axis=2) - rgb.min(axis=2)
    luma = rgb.mean(axis=2)
    in_bg_luma = (luma >= LUMA_LO) & (luma <= LUMA_HI)

    # Alpha: 0 for neutral mid-grey, ramping to 1 with chroma; dark or very
    # bright (flare) pixels are artwork.
    ramp = np.clip((chroma - CHROMA_BG) / (CHROMA_FG - CHROMA_BG), 0.0, 1.0)
    alpha = np.where(in_bg_luma, ramp, 1.0)
    bg = alpha <= 0.0

    back = diffuse_background(rgb, bg)
    a3 = alpha[..., None]
    # Un-mix partially transparent pixels: P = a*F + (1-a)*B  =>  F.
    fg = np.where(a3 > 0, (rgb - (1.0 - a3) * back) / np.maximum(a3, 1e-6), 0.0)
    fg = np.clip(fg, 0, 255)
    # Fully opaque artwork keeps its exact original pixels.
    fg = np.where(a3 >= 1.0, rgb, fg)

    rgba = np.dstack([fg, alpha * 255.0]).round().astype(np.uint8)
    full = Image.fromarray(rgba, "RGBA")
    # Alpha-correct downscale (premultiplied), aspect ratio preserved exactly.
    sw, sh = full.size
    OUT_SIZE = (round(OUT_H * sw / sh), OUT_H)
    assert abs(sw / sh - OUT_SIZE[0] / OUT_SIZE[1]) < 0.005, "aspect must be preserved"
    small = full.convert("RGBa").resize(OUT_SIZE, Image.Resampling.LANCZOS).convert("RGBA")
    OUT_RGBA.write_bytes(small.tobytes())
    small.save(OUT_PNG)
    print(f"wrote {OUT_RGBA.name} {OUT_SIZE} and {OUT_PNG.name}")
    opaque = (alpha >= 1.0).mean() * 100
    clear = (alpha <= 0.0).mean() * 100
    print(f"opaque {opaque:.1f}%  transparent {clear:.1f}%  edge {100 - opaque - clear:.1f}%")


if __name__ == "__main__":
    main()
