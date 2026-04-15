"""
SecretSauce — Icon Generator
Author: K. Boykov

Generates icon16.png, icon48.png, icon128.png using only Python stdlib.
Run once before loading the extension:
    python generate-icons.py
"""

import struct
import zlib
import math
import os

def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    chunk = chunk_type + data
    crc   = struct.pack('>I', zlib.crc32(chunk) & 0xFFFFFFFF)
    return struct.pack('>I', len(data)) + chunk + crc

def create_png(size: int) -> bytes:
    """Create a SecretSauce icon PNG of the given size."""
    PNG_SIG = b'\x89PNG\r\n\x1a\n'

    # IHDR: width, height, bit_depth=8, color_type=2 (RGB), compress=0, filter=0, interlace=0
    ihdr_data = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
    ihdr = make_chunk(b'IHDR', ihdr_data)

    cx = size / 2.0
    cy = size / 2.0
    r_outer = size * 0.48
    r_inner = size * 0.30

    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter type: None
        for x in range(size):
            dist = math.sqrt((x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2)

            if dist > r_outer:
                # Outside circle — deep space background
                raw.extend([7, 9, 26])     # --b0: #07091a
            elif dist > r_outer - 1.5:
                # Anti-alias edge blend
                t = (r_outer - dist) / 1.5
                raw.extend([
                    int(7  + t * ( 99 -  7)),
                    int(9  + t * (102 -  9)),
                    int(26 + t * (241 - 26)),
                ])
            else:
                # Inside circle: indigo gradient #6366f1 → #4338ca
                gx = (x + 0.5) / size
                gy = (y + 0.5) / size
                t  = (gx + gy) / 2.0   # 0 = top-left, 1 = bottom-right

                # #6366f1 (99,102,241) → #4338ca (67,56,202)
                pr = int( 99 - t * ( 99 -  67))
                pg = int(102 - t * (102 -  56))
                pb = int(241 - t * (241 - 202))

                # "S" glyph — white letter centred in the circle
                if _is_letter_S(x, y, size):
                    raw.extend([255, 255, 255])
                else:
                    raw.extend([pr, pg, pb])

    compressed = zlib.compress(bytes(raw), 9)
    idat = make_chunk(b'IDAT', compressed)
    iend = make_chunk(b'IEND', b'')

    return PNG_SIG + ihdr + idat + iend


def _is_letter_S(x: int, y: int, size: int) -> bool:
    """
    Rasterise a bold 'S' glyph inside the icon.
    Uses a simple analytical approach scaled to the icon size.
    """
    if size < 16:
        return False

    # Normalise to [0,1] relative to inner area
    pad = size * 0.22
    nx  = (x - pad) / (size - 2 * pad)   # 0..1
    ny  = (y - pad) / (size - 2 * pad)   # 0..1

    if nx < 0 or nx > 1 or ny < 0 or ny > 1:
        return False

    stroke = 0.18  # relative stroke width

    # Horizontal bars (top, mid, bottom)
    top_bar    = (0.05 <= nx <= 0.85) and (0.03 <= ny <= 0.03 + stroke)
    mid_bar    = (0.15 <= nx <= 0.85) and (0.47 <= ny <= 0.47 + stroke)
    bot_bar    = (0.15 <= nx <= 0.90) and (0.94 - stroke <= ny <= 0.97)

    # Left vertical (bottom half)
    left_vert  = (0.03 <= nx <= 0.03 + stroke) and (0.50 <= ny <= 0.94)

    # Right vertical (top half)
    right_vert = (0.85 - stroke <= nx <= 0.88) and (0.06 <= ny <= 0.50)

    return top_bar or mid_bar or bot_bar or left_vert or right_vert


def main():
    os.makedirs('icons', exist_ok=True)
    for size in (16, 48, 128):
        data = create_png(size)
        path = f'icons/icon{size}.png'
        with open(path, 'wb') as f:
            f.write(data)
        print(f'  OK  {path}  ({len(data)} bytes)')
    print('\nDone! Reload the extension in chrome://extensions.')


if __name__ == '__main__':
    main()
