with open("public/dashboard.html", encoding="utf-8") as f:
    html = f.read()

# Replace hardcoded metric values with 0
html = html.replace('id="m1">31', 'id="m1">0')
html = html.replace('id="m2">24', 'id="m2">0')
html = html.replace('id="m3">4', 'id="m3">0')
html = html.replace('id="m4">3', 'id="m4">0')
html = html.replace('<span class="badge">3</span>', '<span class="badge">0</span>')
html = html.replace('77% of total', '0% of total')

with open("public/dashboard.html", "w", encoding="utf-8") as f:
    f.write(html)
print("Done")
