#!/usr/bin/env python3
import base64, sys

with open('e:/_26_Use_Orange_New_set_/session_manager/orange_mascot.png', 'rb') as f:
    b64 = base64.b64encode(f.read()).decode()

img_tag = f'<img src="data:image/jpeg;base64,{b64}" width="28" height="28" style="border-radius:6px;display:block;">'

with open('e:/_26_Use_Orange_New_set_/session_manager/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

old = '''      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="11" fill="#F47B20"/>
        <circle cx="12" cy="12" r="6" fill="#fff" opacity="0.9"/>
        <circle cx="12" cy="12" r="3" fill="#F47B20"/>
      </svg>'''

new = f'      {img_tag}'

if old in content:
    content = content.replace(old, new)
    print("SVG replaced successfully")
else:
    print("SVG pattern NOT found - searching...")
    # Find what's around 'logo'
    idx = content.find('<div id="logo">')
    if idx >= 0:
        print(repr(content[idx:idx+300]))
    sys.exit(1)

with open('e:/_26_Use_Orange_New_set_/session_manager/main.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done.")
