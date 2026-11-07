import os
def hx(h): h=h.lstrip('#'); return tuple(int(h[i:i+2],16) for i in (0,2,4))
def cmyk(r,g,b):
    r,g,b=r/255,g/255,b/255; k=1-max(r,g,b)
    return (0,0,0,100) if k==1 else tuple(round(100*x) for x in ((1-r-k)/(1-k),(1-g-k)/(1-k),(1-b-k)/(1-k),k))
def lab(r,g,b):
    def lin(c): c/=255; return c/12.92 if c<=0.04045 else ((c+0.055)/1.055)**2.4
    R,G,B=lin(r),lin(g),lin(b)
    X=(R*.4124+G*.3576+B*.1805)/.95047; Y=R*.2126+G*.7152+B*.0722; Z=(R*.0193+G*.1192+B*.9505)/1.08883
    f=lambda t: t**(1/3) if t>0.008856 else 7.787*t+16/116
    return (round(116*f(Y)-16), round(500*(f(X)-f(Y))), round(200*(f(Y)-f(Z))))
cols=[("Encre","#0B0C10","#ECEDF2"),("Plume","#1C223A","#ECEDF2"),("Pervenche","#8697EC","#0B0C10"),("Ambre","#F6A821","#0B0C10"),("Or de la clé","#FFD000","#0B0C10"),("Brume","#ECEDF2","#0B0C10")]
sw=""
for n,h,fg in cols:
    r,g,b=hx(h); c=cmyk(r,g,b); l=lab(r,g,b)
    sw+=f'<div class="sw" style="background:{h};color:{fg}"><b>{n}</b><span>HEX {h[1:].upper()}<br>RGB {r} {g} {b}<br>CMYK {c[0]} {c[1]} {c[2]} {c[3]}<br>LAB {l[0]} {l[1]} {l[2]}</span></div>'
FONTS='<link rel="stylesheet" href="https://api.fontshare.com/v2/css?f[]=chubbo@400,500,700&display=swap"><link rel="stylesheet" href="https://api.fontshare.com/v2/css?f[]=switzer@300,400,500,600&display=swap"><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap">'
CSS=f'''<meta charset="utf-8">{FONTS}<style>
*{{box-sizing:border-box}}body{{margin:0;background:#07080B;color:#ECEDF2;font-family:Switzer;font-weight:400;padding:28px;width:1080px}}
.p{{border:1.5px solid #2A2F3F;border-radius:34px;overflow:hidden;position:relative}}
.wm{{font-family:Chubbo;font-weight:700;letter-spacing:-.01em;display:inline-flex;align-items:baseline;line-height:1}}
.n{{display:inline-block;width:.19em;height:.19em;background:#F6A821;border-radius:.05em;margin-left:.05em}}
.ic{{border-radius:23.5%;display:block}}
.row{{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin-top:22px}}
.sw{{border-radius:26px;padding:22px 24px;display:flex;flex-direction:column;gap:10px;font:14px/1.5 'JetBrains Mono';min-height:170px}}
.sw b{{font-family:Chubbo;font-weight:700;font-size:19px}}
.h{{font-family:Chubbo;font-weight:700;font-size:26px;letter-spacing:-.005em}}
.cap{{font-family:Switzer;font-weight:300;font-size:16px;color:#A9AEBD;line-height:1.55}}
img.photo{{width:100%;height:100%;object-fit:cover;display:block}}
</style>'''
def LOGO(size,col="#ECEDF2",ic=None,font=None,extra=""):
    st=f"font-size:{size}px;color:{col}"+(f";font-family:{font};font-weight:700" if font else "")
    return f'<div style="display:flex;align-items:center;gap:{int(size*.24)}px;{extra}"><img class="ic" src="../icon.svg" width="{ic or int(size*1.15)}"><span class="wm" style="{st}">crenel<span class="n"></span></span></div>'
pat='''<svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg"><defs><pattern id="pt" width="150" height="150" patternUnits="userSpaceOnUse">
<rect width="150" height="150" fill="#F6A821"/><g fill="#0B0C10"><circle cx="38" cy="40" r="20"/><circle cx="38" cy="40" r="9" fill="#F6A821"/><rect x="54" y="34" width="56" height="13" rx="6.5"/><rect x="88" y="44" width="11" height="20" rx="5.5"/><rect x="103" y="44" width="9" height="15" rx="4.5"/>
<path d="M112 98c2 14 4 16 18 18c-14 2-16 4-18 18c-2-14-4-16-18-18c14-2 16-4 18-18z"/><path d="M14 150v-28a6 6 0 0 1 6-6h16a6 6 0 0 1 6 6v8h12v-8a6 6 0 0 1 6-6h16a6 6 0 0 1 6 6v28z"/></g></pattern></defs><rect width="100%" height="100%" fill="url(#pt)"/></svg>'''
grid='<svg viewBox="0 0 1024 1024" style="position:absolute;inset:0;width:100%;height:100%"><g fill="none" stroke="#ECEDF2" stroke-opacity=".55" stroke-width="3" stroke-dasharray="14 12">'
for v in (128,256,384,512,640,768,896): grid+=f'<line x1="{v}" y1="0" x2="{v}" y2="1024"/><line x1="0" y1="{v}" x2="1024" y2="{v}"/>'
grid+='<line x1="0" y1="0" x2="1024" y2="1024"/><line x1="1024" y1="0" x2="0" y2="1024"/><circle cx="478" cy="590" r="360"/><circle cx="595" cy="631" r="126"/><circle cx="438" cy="437" r="62"/><circle cx="709" cy="385" r="58"/><line x1="440" y1="660" x2="980" y2="586"/></g></svg>'
open("guide/01-planche.html","w").write(f'''<html><head>{CSS}</head><body>
<div class="p" style="height:470px;display:flex;align-items:center;justify-content:center;background:#0B0C10;border-color:#F6A821">{LOGO(130)}</div>
<div class="row"><div class="p" style="height:440px;background:#0E1016"><img src="../icon.svg" style="position:absolute;inset:70px;width:calc(100% - 140px);opacity:.38;border-radius:23.5%"><div style="position:absolute;inset:70px">{grid}</div></div>
<div class="p" style="height:440px;background:#8697EC;display:grid;place-items:center;border-color:#8697EC"><img class="ic" src="../icon.svg" width="300" style="box-shadow:0 24px 60px -18px rgba(20,24,50,.6)"></div></div>
<div class="p" style="height:300px;margin-top:22px;border-color:#F6A821">{pat}</div>
<div class="row"><div class="p" style="height:430px;background:#F6F5F1;display:grid;place-items:center;border-color:#F6F5F1"><div style="position:relative"><img class="ic" src="../icon.svg" width="250"><div style="position:absolute;right:-30px;top:-30px;width:78px;height:78px;border-radius:50%;background:#F2393A;color:#fff;font:600 44px Switzer;display:grid;place-items:center;border:5px solid #F6F5F1">3</div></div></div>
<div class="p" style="height:430px"><img class="photo" src="../mockups/mock-flat.png" style="object-position:50% 45%"></div></div>
<div class="p" style="height:560px;margin-top:22px"><img class="photo" src="../mockups/mock-laptop.png"></div>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:22px;margin-top:22px">{sw}</div>
</body></html>''')
def box(u,inner,ratio):
    return f'''<div style="display:flex;align-items:center;gap:28px;margin:30px 0">
<div style="font:700 18px Chubbo;width:90px;text-align:right;color:#F6A821">{ratio}</div>
<div style="position:relative;padding:{u}px;border:1.5px dashed #555B70;background:repeating-linear-gradient(45deg,#121420 0 10px,#0E1018 10px 20px)">
<div style="background:#0B0C10;outline:1.5px solid #555B70">{inner}</div>
<div style="position:absolute;left:-1px;top:-1px;width:{u}px;height:{u}px;background:#1E2232;border-right:1px solid #555B70;border-bottom:1px solid #555B70;font:12px 'JetBrains Mono';color:#9EA3B2;display:grid;place-items:center">x</div>
<div style="position:absolute;right:-1px;bottom:-1px;width:{u}px;height:{u}px;background:#1E2232;border-left:1px solid #555B70;border-top:1px solid #555B70;font:12px 'JetBrains Mono';color:#9EA3B2;display:grid;place-items:center">x</div></div></div>'''
stack=lambda ic,fs: f'<div style="display:flex;flex-direction:column;align-items:center;gap:26px"><img class="ic" src="../icon.svg" width="{ic}"><span class="wm" style="font-size:{fs}px">crenel<span class="n"></span></span></div>'
open("guide/02-zone.html","w").write(f'''<html><head>{CSS}</head><body style="padding:60px">
<div class="h">Zone de protection</div>
<p class="cap" style="max-width:840px;margin:14px 0 10px">Garder autour du logo un espace vide égal à <b style="color:#ECEDF2;font-weight:500">x</b>. Version horizontale : x vaut la moitié de la hauteur de l'icône. Version empilée : x vaut le quart de la hauteur de l'icône. Ni texte, ni bord, ni image dans cette zone.</p>
{box(75,LOGO(118,ic=150),"x = 50 %")}
<div style="height:1px;background:#2A2F3F;margin:20px 0"></div>
{box(58,stack(230,100),"x = 25 %")}
</body></html>''')
def tile(content,ok,label,bg="#0B0C10"):
    if ok: mark='<div style="position:absolute;top:14px;right:14px;width:34px;height:34px;border-radius:50%;background:#F6A821;display:grid;place-items:center;font:700 18px Switzer;color:#0B0C10">✓</div>'
    else: mark='<div style="position:absolute;top:14px;right:14px;width:34px;height:34px;border-radius:50%;background:#F2393A;display:grid;place-items:center;font:700 16px Switzer;color:#fff">✕</div>'
    return f'<div style="display:grid;gap:10px"><div class="p" style="height:200px;background:{bg};display:grid;place-items:center;border-radius:24px">{content}{mark}</div><div class="cap" style="color:#ECEDF2;font-weight:400">{label}</div></div>'
sm=lambda **k: LOGO(34,**k)
donts=[(sm(),True,"Sur fond sombre uni"),
 (f'<div style="transform:scaleX(1.45)">{sm()}</div>',False,"Ne pas déformer"),
 (f'<div style="transform:rotate(-14deg)">{sm()}</div>',False,"Ne pas faire pivoter"),
 (f'<div style="display:flex;align-items:center;gap:11px"><img class="ic" src="../icon.svg" width="40" style="filter:hue-rotate(150deg) saturate(1.6)"><span class="wm" style="font-size:34px;color:#57D29E">crenel<span class="n" style="background:#57D29E"></span></span></div>',False,"Ne pas changer les couleurs"),
 (f'<div style="display:flex;align-items:center;gap:11px"><img class="ic" src="../icon.svg" width="40"><span style="font:italic 300 34px Arial;letter-spacing:.18em;color:#ECEDF2">crenel</span></div>',False,"Ne pas changer la police"),
 (f'<div style="filter:drop-shadow(6px 8px 0 #F2393A) drop-shadow(0 0 12px #fff)">{sm()}</div>',False,"Ni ombre ni effet"),
 (sm(),False,"Pas sur un fond chargé"),
 (f'<div style="display:flex;align-items:center;gap:11px"><img class="ic" src="../icon.svg" width="40"><span class="wm" style="font-size:34px;color:#2A2E3E">crenel<span class="n"></span></span></div>',False,"Garder un contraste suffisant")]
cells="".join(tile(c,ok,l,"repeating-linear-gradient(35deg,#F6A821 0 18px,#8697EC 18px 36px,#ECEDF2 36px 54px)" if l.startswith("Pas sur") else "#0B0C10") for c,ok,l in donts)
mins='''<div style="display:flex;gap:56px;align-items:flex-end;margin:22px 0 6px">
<div style="display:grid;gap:12px"><div style="display:flex;gap:18px;align-items:flex-end"><img class="ic" src="../favicon-48.png" width="16"><img class="ic" src="../favicon-48.png" width="24"><img class="ic" src="../icon.svg" width="32"><img class="ic" src="../icon.svg" width="48"></div><span class="cap">Icône : 16 px minimum, favicon recadré sous 32 px</span></div>
<div style="display:grid;gap:12px"><div style="display:flex;align-items:center;gap:7px"><img class="ic" src="../icon.svg" width="22"><span class="wm" style="font-size:20px">crenel<span class="n"></span></span></div><span class="cap">Logo complet : 110 px de large minimum</span></div></div>'''
open("guide/03-regles.html","w").write(f'''<html><head>{CSS}</head><body style="padding:60px">
<div class="h">Tailles minimales</div>{mins}
<div style="height:1px;background:#2A2F3F;margin:30px 0"></div>
<div class="h" style="margin-bottom:22px">Usages à éviter</div>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:22px">{cells}</div>
</body></html>''')
open("guide/04-typo.html","w").write(f'''<html><head>{CSS}</head><body style="padding:60px">
<div class="h">Typographie</div>
<p class="cap" style="max-width:880px;margin:14px 0 30px">Une paire : <b style="color:#ECEDF2;font-weight:500">Chubbo</b>, grasse et trapue, pour le logo et les titres ; <b style="color:#ECEDF2;font-weight:500">Switzer</b>, en léger, pour les descriptions et l'interface. JetBrains Mono pour le code. Chubbo est rare et ses formes rondes répondent au choucas sans faire enfantin ; Switzer reste neutre et très lisible à côté. Chubbo et Switzer : Fontshare, licence ITF gratuite y compris en commercial.</p>
<div class="p" style="padding:44px;background:#0B0C10;display:grid;gap:30px">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:30px">
<div><div style="font:700 150px/0.9 Chubbo">Aa</div><div style="font:700 28px Chubbo;margin-top:14px">Chubbo</div><div class="cap">Logo 700 · Titres 700 et 500</div></div>
<div><div style="font:300 150px/0.9 Switzer">Aa</div><div style="font:500 28px Switzer;margin-top:14px">Switzer</div><div class="cap">Descriptions 300 · Interface 400 et 500</div></div></div>
<div style="border-top:1px solid #1E2130;padding-top:28px;display:grid;gap:14px">
<div style="font:700 56px/1.02 Chubbo;letter-spacing:-.01em">Attaquez votre app <span style="color:#F6A821">avant</span> qu'on le fasse.</div>
<div style="font:300 22px/1.55 Switzer;color:#B4B8C6;max-width:760px">Crenel trouve les secrets exposés et les failles d'autorisation entre comptes, prouve chacune par une requête rejouable, puis la garde en CI.</div>
<div style="font:400 17px/1.7 'JetBrains Mono';color:#9EA3B2"><span style="color:#F6A821">$</span> npx crenel scan<br>CRIT  sk_live_ dans dist/app.js:5   prouvé</div></div></div>
<div class="h" style="font-size:20px;margin:36px 0 14px">Les 10 paires testées</div>
<img src="../typo/pairs-10.png" style="width:100%;border-radius:20px;border:1px solid #1E2130">
</body></html>''')
open("guide/05-mockups.html","w").write(f'''<html><head>{CSS}</head><body>
<div class="p" style="height:680px"><img class="photo" src="../mockups/mock-laptop.png"></div>
<div class="row"><div class="p" style="height:640px"><img class="photo" src="../mockups/mock-hand.png"></div><div class="p" style="height:640px"><img class="photo" src="../mockups/mock-flat.png"></div></div>
<div class="p" style="aspect-ratio:4/3;margin-top:22px"><img class="photo" src="../mockups/studio-phones.png"></div>
<div class="row"><div class="p" style="aspect-ratio:4/3"><img class="photo" src="../mockups/studio-icon-phone.png"></div><div class="p" style="aspect-ratio:4/3"><img class="photo" src="../mockups/studio-laptop.png"></div></div>
</body></html>''')
print("ok")
