#!/usr/bin/env python3
"""
Generate a professional GitHub Social Preview Image (1280x640)
for Project Netra-Core repository.
"""
import os

# Check if we can use PIL
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("⚠ PIL not available - generating HTML preview instead")

def generate_html_preview():
    """Generate an HTML-based preview that can be screenshotted."""
    html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Project Netra-Core - Social Preview</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            background: #000;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        .preview {
            width: 1280px;
            height: 640px;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            position: relative;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            color: white;
        }
        .grid-bg {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(102, 252, 241, 0.1) 1px, transparent 1px),
                linear-gradient(90deg, rgba(102, 252, 241, 0.1) 1px, transparent 1px);
            background-size: 40px 40px;
            opacity: 0.5;
        }
        .content {
            position: relative;
            z-index: 2;
            text-align: center;
            padding: 40px;
        }
        .shield {
            font-size: 80px;
            margin-bottom: 20px;
            filter: drop-shadow(0 0 20px rgba(102, 252, 241, 0.8));
        }
        .title {
            font-size: 72px;
            font-weight: 900;
            letter-spacing: 4px;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #66fcf1, #45a29e);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .subtitle {
            font-size: 28px;
            color: #c5c6c7;
            margin-bottom: 40px;
            letter-spacing: 2px;
            font-weight: 300;
        }
        .badge {
            display: inline-block;
            padding: 12px 30px;
            background: rgba(102, 252, 241, 0.1);
            border: 2px solid #66fcf1;
            border-radius: 30px;
            color: #66fcf1;
            font-size: 18px;
            font-weight: 600;
            letter-spacing: 1px;
            margin: 5px;
        }
        .version {
            position: absolute;
            top: 40px;
            right: 60px;
            color: #66fcf1;
            font-size: 16px;
            font-weight: 600;
            letter-spacing: 2px;
        }
        .classification {
            position: absolute;
            top: 40px;
            left: 60px;
            color: #ff4b4b;
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 3px;
            border: 2px solid #ff4b4b;
            padding: 8px 20px;
            border-radius: 4px;
        }
        .footer {
            position: absolute;
            bottom: 40px;
            left: 0;
            right: 0;
            text-align: center;
            color: #666;
            font-size: 14px;
            letter-spacing: 1px;
        }
        .modules {
            margin-top: 30px;
            display: flex;
            gap: 20px;
            justify-content: center;
            flex-wrap: wrap;
        }
        .module {
            background: rgba(255, 255, 255, 0.05);
            padding: 10px 20px;
            border-radius: 6px;
            border-left: 3px solid #66fcf1;
            font-size: 14px;
            color: #c5c6c7;
        }
    </style>
</head>
<body>
    <div class="preview">
        <div class="grid-bg"></div>
        <div class="classification">RESTRICTED</div>
        <div class="version">v6.1.2</div>
        <div class="content">
            <div class="shield">🛡️</div>
            <div class="title">PROJECT NETRA-CORE</div>
            <div class="subtitle">Government Cyber-Defense & Forensic Engine</div>
            <div class="badge">Zero-Trust Architecture</div>
            <div class="badge">HMAC-SHA256 Ledger</div>
            <div class="badge">AI Legal NLP</div>
            <div class="modules">
                <div class="module">Android Triage</div>
                <div class="module">Steganalysis</div>
                <div class="module">Cloud Audit</div>
                <div class="module">Legal Mapping</div>
            </div>
        </div>
        <div class="footer">
            ISO 27001 • NIS 2 Compliant • Court-Admissible Evidence Chain
        </div>
    </div>
</body>
</html>"""
    
    os.makedirs("assets", exist_ok=True)
    with open("assets/social-preview.html", "w") as f:
        f.write(html)
    print(f"✓ HTML preview generated: assets/social-preview.html")
    print("  Open this file in browser and screenshot at 1280x640 resolution")


def generate_image_preview():
    """Generate PNG image using PIL."""
    os.makedirs("assets", exist_ok=True)
    
    img = Image.new('RGB', (1280, 640), color='#0f0c29')
    draw = ImageDraw.Draw(img)
    
    # Gradient background
    for y in range(640):
        ratio = y / 640
        r = int(15 + (48 - 15) * ratio)
        g = int(12 + (43 - 12) * ratio)
        b = int(41 + (99 - 41) * ratio)
        draw.line([(0, y), (1280, y)], fill=(r, g, b))
    
    # Grid overlay
    for x in range(0, 1280, 40):
        draw.line([(x, 0), (x, 640)], fill=(102, 252, 241, 20), width=1)
    for y in range(0, 640, 40):
        draw.line([(0, y), (1280, y)], fill=(102, 252, 241, 20), width=1)
    
    # Try to load fonts
    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 72)
        subtitle_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 28)
        badge_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 18)
        small_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
    except:
        title_font = ImageFont.load_default()
        subtitle_font = ImageFont.load_default()
        badge_font = ImageFont.load_default()
        small_font = ImageFont.load_default()
    
    # Shield emoji (as text)
    draw.text((600, 100), "🛡", fill=(102, 252, 241), font=title_font, anchor="mm")
    
    # Title
    draw.text((640, 220), "PROJECT NETRA-CORE", fill=(102, 252, 241), 
              font=title_font, anchor="mm")
    
    # Subtitle
    draw.text((640, 280), "Government Cyber-Defense & Forensic Engine", 
              fill=(197, 198, 199), font=subtitle_font, anchor="mm")
    
    # Badges
    badges = ["Zero-Trust", "HMAC-SHA256", "AI Legal NLP"]
    x_offset = 640 - (len(badges) * 150) // 2
    for badge in badges:
        draw.rectangle([(x_offset, 340), (x_offset + 130, 375)], 
                      outline=(102, 252, 241), width=2)
        draw.text((x_offset + 65, 357), badge, fill=(102, 252, 241), 
                 font=badge_font, anchor="mm")
        x_offset += 150
    
    # Classification
    draw.rectangle([(60, 40), (240, 80)], outline=(255, 75, 75), width=2)
    draw.text((150, 60), "RESTRICTED", fill=(255, 75, 75), 
             font=small_font, anchor="mm")
    
    # Version
    draw.text((1220, 60), "v6.1.2", fill=(102, 252, 241), 
             font=small_font, anchor="mm")
    
    # Footer
    draw.text((640, 600), "ISO 27001 • NIS 2 Compliant • Court-Admissible Evidence Chain", 
             fill=(102, 102, 102), font=small_font, anchor="mm")
    
    img.save("assets/social-preview.png", "PNG")
    print(f"✓ Image generated: assets/social-preview.png (1280x640)")


if __name__ == "__main__":
    if PIL_AVAILABLE:
        generate_image_preview()
    else:
        generate_html_preview()
    
    print("\n📋 Upload Instructions:")
    print("   1. Go to: https://github.com/<owner>/<repo>/settings")
    print("   2. Scroll to 'Social Preview' section")
    print("   3. Click 'Edit' and upload the generated image")
    print("   4. Recommended size: 1280x640 pixels")
