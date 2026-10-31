"""Draws the MccX launcher icon: rounded-square glass, edge ring, wordmark."""

from PIL import Image, ImageDraw, ImageFont, ImageFilter

OUT = r"E:\deepseek\xehn-vpn\res"
FONT = r"C:\Windows\Fonts\segoeuib.ttf"
S = 1024          # master size
CORNER = S * 0.22 # iOS-ish squircle radius


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def make_master():
    # Background: diagonal gradient, deep blue -> near-black.
    top = (37, 99, 235)      # #2563EB
    bottom = (12, 18, 32)    # #0C1220
    grad = Image.new("RGB", (S, S))
    px = grad.load()
    for y in range(S):
        for x in range(S):
            t = (x * 0.35 + y * 0.65) / S
            px[x, y] = lerp(top, bottom, min(1.0, t * 1.15))
    grad = grad.convert("RGBA")

    # Rounded-square mask.
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=CORNER, fill=255)
    icon = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    icon.paste(grad, (0, 0), mask)

    draw = ImageDraw.Draw(icon)

    # Soft cyan glow behind the mark.
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse([S * 0.18, S * 0.18, S * 0.82, S * 0.82], fill=(34, 211, 238, 60))
    glow = glow.filter(ImageFilter.GaussianBlur(S * 0.09))
    icon = Image.alpha_composite(icon, Image.composite(glow, Image.new("RGBA", (S, S), (0, 0, 0, 0)), mask))
    draw = ImageDraw.Draw(icon)

    # Edge ring: thin, brighter on the top-left, fades out.
    ring = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    rd = ImageDraw.Draw(ring)
    inset = S * 0.085
    rd.ellipse([inset, inset, S - inset, S - inset], outline=(34, 211, 238, 110), width=int(S * 0.010))
    fade = Image.new("L", (S, S), 0)
    fd = ImageDraw.Draw(fade)
    fd.rectangle([0, S * 0.5, S, S], fill=110)       # dim the bottom half
    ring.putalpha(Image.composite(ring.getchannel("A"), Image.new("L", (S, S), 0), fade))
    icon = Image.alpha_composite(icon, ring)
    draw = ImageDraw.Draw(icon)

    # Wordmark: "Mcc" in white, the "X" in the accent colour.
    font = ImageFont.truetype(FONT, int(S * 0.265))
    full = draw.textbbox((0, 0), "MccX", font=font, anchor="mm")
    tw = full[2] - full[0]
    prefix = draw.textbbox((0, 0), "Mcc", font=font, anchor="lm")
    pw = prefix[2] - prefix[0]
    x0 = S / 2 - tw / 2
    cy = S / 2

    shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    sd.text((x0, cy + S * 0.012), "Mcc", font=font, fill=(0, 0, 0, 140), anchor="lm")
    sd.text((x0 + pw, cy + S * 0.012), "X", font=font, fill=(0, 0, 0, 140), anchor="lm")
    shadow = shadow.filter(ImageFilter.GaussianBlur(S * 0.012))
    icon = Image.alpha_composite(icon, Image.composite(shadow, Image.new("RGBA", (S, S), (0, 0, 0, 0)), mask))
    draw = ImageDraw.Draw(icon)

    draw.text((x0, cy), "Mcc", font=font, fill=(255, 255, 255, 255), anchor="lm")
    draw.text((x0 + pw, cy), "X", font=font, fill=(34, 211, 238, 255), anchor="lm")


    return icon


def main():
    master = make_master()
    master.save(rf"{OUT}\..\build\icon-master.png")
    master.resize((512, 512), Image.LANCZOS).save(rf"{OUT}\..\build\icon-preview.png")

    densities = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
    for name, size in densities.items():
        folder = rf"{OUT}\mipmap-{name}"
        import os
        os.makedirs(folder, exist_ok=True)
        master.resize((size, size), Image.LANCZOS).save(rf"{folder}\ic_launcher.png")
    print("icons written")


if __name__ == "__main__":
    main()


