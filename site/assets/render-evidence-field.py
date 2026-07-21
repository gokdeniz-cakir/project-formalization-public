from pathlib import Path
from random import Random

from PIL import Image, ImageDraw, ImageFont, PngImagePlugin


WIDTH, HEIGHT = 3840, 1440
ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "dtls-ack-trace-field-v3.png"
FONT_PATH = Path(r"C:\Windows\Fonts\CascadiaMono.ttf")

INK = (17, 23, 20)
GREEN = (8, 122, 95)
RED = (201, 52, 44)
MUTED = (88, 100, 94)


def font(size):
    return ImageFont.truetype(str(FONT_PATH), size)


def rgba(color, alpha):
    return (*color, alpha)


image = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
draw = ImageDraw.Draw(image)
rng = Random(4096)

# Sparse registration marks keep the image feeling like a preserved trace sheet.
for x in range(100, WIDTH, 160):
    height = 22 if x % 640 else 46
    draw.line((x, 348, x, 348 + height), fill=rgba(MUTED, 100), width=2)
draw.line((100, 348, WIDTH - 100, 348), fill=rgba(MUTED, 88), width=2)

draw.text((102, 278), "FORMAL-RUN / DTLS13_ACK_CAPACITY", font=font(24), fill=rgba(GREEN, 188))
draw.text((WIDTH - 970, 278), "SOURCE 922d04b3  /  PROPERTY ACK-WRITE-CAPACITY", font=font(20), fill=rgba(MUTED, 155))

counts = [0, 1024, 2048, 3072, 4095, 4096]
written = [count * 16 for count in counts]
reserved = [value & 0xFFFF for value in written]

# The two traces agree until the final uint16 narrowing step drops reserved bytes to zero.
plot_left, plot_top = 250, 470
plot_width, plot_height = WIDTH - 500, 470
plot_bottom = plot_top + plot_height
draw.line((plot_left, plot_bottom, plot_left + plot_width, plot_bottom), fill=rgba(INK, 118), width=2)
draw.line((plot_left, plot_top, plot_left, plot_bottom), fill=rgba(INK, 92), width=2)

for fraction, label in ((0, "0"), (.25, "16 KiB"), (.5, "32 KiB"), (.75, "48 KiB"), (1, "64 KiB")):
    y = round(plot_bottom - plot_height * fraction)
    draw.line((plot_left, y, plot_left + plot_width, y), fill=rgba(MUTED, 42), width=2)
    draw.text((112, y - 13), label, font=font(18), fill=rgba(MUTED, 130))

def point(index, value):
    x = plot_left + round(plot_width * index / (len(counts) - 1))
    y = plot_bottom - round(plot_height * value / 65536)
    return x, y

written_points = [point(index, value) for index, value in enumerate(written)]
reserved_points = [point(index, value) for index, value in enumerate(reserved)]
draw.line(written_points, fill=rgba(GREEN, 175), width=5, joint="curve")
draw.line(reserved_points, fill=rgba(INK, 142), width=3, joint="curve")

for index, count in enumerate(counts):
    x, y = written_points[index]
    draw.line((x, plot_bottom, x, plot_bottom + 18), fill=rgba(MUTED, 112), width=2)
    draw.text((x - 34, plot_bottom + 28), f"{count:,}", font=font(18), fill=rgba(MUTED, 145))
    draw.ellipse((x - 7, y - 7, x + 7, y + 7), outline=rgba(GREEN, 190), width=3)

wrap_x, wrap_y = reserved_points[-1]
draw.line((written_points[-2], reserved_points[-2], wrap_x, wrap_y), fill=rgba(RED, 202), width=5)
draw.rectangle((wrap_x - 9, wrap_y - 9, wrap_x + 9, wrap_y + 9), outline=rgba(RED, 225), width=4)
draw.text((wrap_x - 410, wrap_y + 46), "uint16(65,536) = 0", font=font(25), fill=rgba(RED, 210))

# A byte-level ledger makes the field specific without competing with the live controls.
ledger_y = 1080
draw.text((102, ledger_y), "BOUNDARY LEDGER", font=font(20), fill=rgba(GREEN, 175))
draw.line((102, ledger_y + 38, WIDTH - 102, ledger_y + 38), fill=rgba(MUTED, 85), width=2)
rows = [
    ("CONTROL", "record[4095]", "actual 65,520 B", "reserved 65,520 B", "HOLDS", GREEN),
    ("WITNESS", "record[4096]", "actual 65,536 B", "reserved 0 B", "VIOLATION", RED),
]
for index, row in enumerate(rows):
    y = ledger_y + 76 + index * 72
    positions = (102, 680, 1480, 2300, 3200)
    for x, value in zip(positions, row[:-1]):
        draw.text((x, y), value, font=font(22), fill=rgba(row[-1] if x == 3200 else INK, 170))
    draw.line((102, y + 44, WIDTH - 102, y + 44), fill=rgba(MUTED, 48), width=2)

# Deterministic micro-marks imply solver exploration without inventing prose or results.
for lane in range(8):
    base_y = 390 + lane * 92
    for step in range(42):
        x = 260 + step * 80 + rng.randint(-12, 12)
        if x >= WIDTH - 220:
            continue
        length = rng.choice((8, 12, 18, 26))
        alpha = rng.randint(28, 58)
        draw.line((x, base_y, x + length, base_y), fill=rgba(MUTED, alpha), width=2)

metadata = PngImagePlugin.PngInfo()
metadata.add_text("Title", "DTLS 1.3 ACK capacity verification trace field")
metadata.add_text("Source", "wolfSSL 5.9.0, commit 922d04b3")
metadata.add_text("Property", "bytes_written <= uint16_reserved")
metadata.add_text("Boundary", "4095 records: 65520/65520; 4096 records: 65536/0")
image.save(OUTPUT, optimize=True, pnginfo=metadata)
print(f"Wrote {OUTPUT} ({WIDTH}x{HEIGHT}, RGBA)")
