#!/usr/bin/env python3
"""Rig and animate the Crenel mascot from brand/icon.svg.

The drawing is never edited. The script only:
  * wraps existing parts in groups that carry a pivot and an animation,
  * adds hidden extensions *outside* the 1024 frame (body below / left, wing tip
    left of x=0) so that a tilted or jumping bird never shows its cut edges,
  * adds a glow, a sheen and the CSS.
At rest (or with prefers-reduced-motion) every scene renders exactly like icon.svg.

Usage: python3 build.py   (writes ../crenel-*.svg)
"""
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent.parent / "icon.svg"
OUT = HERE.parent
BASE = SRC.read_text()

# ---------------------------------------------------------------- easing
SINE = "cubic-bezier(.37,0,.63,1)"
INOUT = "cubic-bezier(.65,0,.35,1)"
OUT_ = "cubic-bezier(.2,.8,.3,1)"      # quick start, long settle
SNAP = "cubic-bezier(.1,.9,.2,1)"      # very snappy
IN_ = "cubic-bezier(.55,0,.85,.35)"    # gather speed
LIN = "linear"


def one(s, old, new):
    assert s.count(old) == 1, (old[:70], s.count(old))
    return s.replace(old, new)


def num(v):
    return f"{v:.3f}".rstrip("0").rstrip(".")


def kf(name, dur, pts):
    """pts: list of (time_s, css_declarations, easing_to_next)."""
    pts = sorted(pts, key=lambda p: p[0])
    assert pts[0][0] == 0 and abs(pts[-1][0] - dur) < 1e-6, (name, pts[0][0], pts[-1][0], dur)
    body = []
    for t, css, ease in pts:
        e = f";animation-timing-function:{ease}" if ease else ""
        body.append(f"{num(t / dur * 100)}%{{{css}{e}}}")
    return f"@keyframes {name}{{{''.join(body)}}}"


def follow(events, shape=(1, -.55, .25, -.08), step=.12, end=None, rest=0):
    """Damped follow-through: each event (t, amplitude) springs and settles.
    Returns a list of (t, value) samples (value in `unit`)."""
    pts = [(0, rest)]
    for t, a in events:
        pts.append((t, rest))
        for i, k in enumerate(shape):
            pts.append((t + step * (i + 1) * (1 + .25 * i), rest + a * k))
        pts.append((t + step * (len(shape) + 1) * 1.6, rest))
    if end is not None:
        assert pts[-1][0] < end, ("follow-through runs past the loop", pts[-1][0], end)
        pts.append((end, rest))
    return pts


def rot_track(name, dur, pts, ease=SINE):
    return kf(name, dur, [(t, f"transform:rotate({num(v)}deg)", ease) for t, v in pts])


def tilt_tf(a):
    """Head tilt = whole bird rotating on its feet. The bird is cropped by the
    frame's bottom edge, so it sinks a little while it leans, keeping that edge
    below the frame (no seam, no gap)."""
    import math
    d = (445 if a > 0 else 318) * math.sin(math.radians(abs(a)))
    return f"translateY({num(d)}px) rotate({num(a)}deg)"


def shift(pts, d):
    return [(t + d, v) for t, v in pts]


# ---------------------------------------------------------------- rig
def rig(svg, viewbox=None, size=None):
    if viewbox:
        svg = one(svg, 'width="1024" height="1024" viewBox="0 0 1024 1024"',
                  f'width="{size}" height="{size}" viewBox="{viewbox}"')
    svg = one(svg, "<!-- SVG created with Arrow, by QuiverAI (https://quiver.ai) -->\n", "")

    def grab(gid):
        m = re.search(rf'  <g id="{gid}"[^>]*>\n.*?\n  </g>\n', svg, re.S)
        return m.group(0)

    crest, body, eyes = grab("bird-crest"), grab("bird-head-and-body"), grab("golden-eyes")
    wing, key, beak, sparks = grab("left-wing"), grab("gold-key"), grab("bird-beak"), grab("sparkle-highlights")
    start = svg.index(crest)
    end = svg.index(sparks) + len(sparks)
    assert svg[start:end] == crest + body + eyes + wing + key + beak + sparks

    # crest: one group per feather (shape + its rim stroke), pivot at the feather root
    lines = crest.strip("\n").split("\n")
    assert len(lines) == 8
    crest_r = (f'{lines[0]}\n    <g class="fr">\n  {lines[1]}\n  {lines[2]}\n    </g>\n'
               f'    <g class="fl">\n  {lines[3]}\n  {lines[4]}\n    </g>\n'
               f'    <g class="ft">\n  {lines[5]}\n  {lines[6]}\n    </g>\n{lines[7]}\n')

    # eyes: .eye (blink) > .lid (squint) > socket + .iris (gaze) > eye + .glint
    def eye_block(side, sock, e, refl):
        return (f'    <g class="eye eye-{side}"><g class="lid">\n      {sock}\n'
                f'      <g class="iris">\n      {e}\n      <g class="glint">\n      {refl}\n'
                f'      </g></g>\n    </g></g>\n')
    el = eyes.strip("\n").split("\n")
    assert len(el) == 8
    eyes_r = el[0] + "\n" + eye_block("l", *[x.strip() for x in el[1:4]]) + \
        eye_block("r", *[x.strip() for x in el[4:7]]) + el[7] + "\n"

    # wing: tip continuation left of x=0 (never visible at rest)
    wing_r = one(wing, '  <g id="left-wing">\n', '  <g id="left-wing">\n'
                 '    <path d="M3 816 C-17 856 -37 906 -54 966 L-26 970 L3 954 Z" fill="#17203b"/>\n'
                 '    <path d="M3 856 C-17 900 -33 940 -46 966 C-30 968 -12 970 3 970.5 Z" fill="url(#wing-base)"/>\n')

    # body: skirt below / left of the frame, coloured like the body's bottom edge
    skirt = (
        '  <g id="body-skirt">\n'
        '    <path d="M24 828 L0 822 C-28 880 -84 1000 -160 1330 L708 1330 L716 1170 C726 1092 740 1036 752 1000 L24 1000 Z" fill="url(#skirt-fill)"/>\n'
        '    <path d="M744 1023 C730 1070 718 1150 708 1330" fill="none" stroke="url(#right-rim)" stroke-width="2.6"/>\n'
        '  </g>\n')

    # sparkles: key stars travel with the key, the three sky stars stay put
    def star(gid):
        m = re.search(rf'    <g id="{gid}"[^>]*>\n(.*?)\n    </g>\n', sparks, re.S)
        return m.group(0).replace(m.group(1), f'      <g class="tw tw-{gid}">\n{m.group(1)}\n      </g>')
    sky = "".join(star(s) for s in ["large-yellow-star", "small-yellow-star", "white-background-star"])
    keystars = star("key-ring-star") + star("key-shaft-star")
    sparks_r = f'  <g id="sparkle-highlights">\n{sky}  </g>\n'

    sheen = ('  <g clip-path="url(#key-clip)"><g transform="rotate(18 700 640)">'
             '<rect class="sheen" x="330" y="380" width="70" height="520" fill="url(#sheen)" opacity="0"/>'
             '</g></g>\n')
    halo = '  <use class="halo" href="#key-outline" fill="#ffe14d" filter="url(#key-glow)" opacity="0"/>\n'

    rigged = (
        '  <g class="mx"><g class="my"><g class="sq"><g class="tilt">\n'
        f'  <g class="crest">\n{crest_r}  </g>\n'
        f'{skirt}{body}  <g class="wing">\n{wing_r}  </g>\n'
        '  <g class="face">\n'
        f'{eyes_r}{halo}'
        f'  <g class="key"><g class="keyswing">\n{key}{sheen}  </g></g>\n'
        f'  <g class="beak">\n{beak}  </g>\n'
        f'  <g class="key"><g class="keyswing" id="key-sparkles">\n{keystars}  </g></g>\n'
        '  </g>\n'
        '  </g></g></g></g>\n'
        f'{sparks_r}'
    )
    # the wing now sits under the face group: it overlaps neither the eyes, the key nor the beak
    svg = svg[:start] + rigged + svg[end:]

    defs = (
        '    <linearGradient id="skirt-fill" gradientUnits="userSpaceOnUse" x1="-400" y1="0" x2="760" y2="0"><stop offset="0.0000" stop-color="#6a70a4"/><stop offset="0.3457" stop-color="#696fa3"/><stop offset="0.4310" stop-color="#485079"/><stop offset="0.5603" stop-color="#293251"/><stop offset="0.6897" stop-color="#252d4c"/><stop offset="0.8190" stop-color="#2f385c"/><stop offset="0.9310" stop-color="#46517d"/><stop offset="0.9784" stop-color="#596294"/><stop offset="1.0000" stop-color="#5d6699"/></linearGradient>\n'
        '    <linearGradient id="sheen" x1="0" y1="0" x2="1" y2="0">\n'
        '      <stop offset="0" stop-color="#fffbe0" stop-opacity="0"/>\n'
        '      <stop offset=".5" stop-color="#fffbe0" stop-opacity=".75"/>\n'
        '      <stop offset="1" stop-color="#fffbe0" stop-opacity="0"/>\n'
        '    </linearGradient>\n'
        '    <filter id="key-glow" x="-30%" y="-40%" width="160%" height="180%"><feGaussianBlur stdDeviation="14"/></filter>\n'
        '  </defs>')
    svg = one(svg, "  </defs>", defs)
    return svg


# pivots, in drawing coordinates
PIVOTS = """
.mx,.my,.sq,.tilt,.crest,.fr,.fl,.ft,.wing,.face,.key,.keyswing,.beak,.halo{transform-box:view-box}
.sq{transform-origin:430px 1024px}
.tilt{transform-origin:440px 1000px}
.fr{transform-origin:545px 172px}
.fl{transform-origin:418px 172px}
.ft{transform-origin:470px 162px}
.wing{transform-origin:335px 612px}
.keyswing{transform-origin:590px 540px}
.beak{transform-origin:640px 424px}
.eye,.lid,.iris,.glint,.tw,.sheen{transform-box:fill-box;transform-origin:center}
.eye{transform-origin:50% 60%}
.lid{transform-origin:50% 92%}
"""


def css_scene(css, title, svg):
    style = (f'  <title>{title}</title>\n  <style>\n{PIVOTS.strip()}\n{css.strip()}\n'
             '@media (prefers-reduced-motion:reduce){*{animation:none!important}}\n  </style>\n')
    return one(svg, "  <defs>", style + "  <defs>")


def blink(name, dur, starts, close=.07, hold=.04, opn=.12, closed=.06):
    pts = [(0, "transform:none", IN_)]
    for s in starts:
        pts += [(s, "transform:none", IN_), (s + close, f"transform:scaleY({closed})", None),
                (s + close + hold, f"transform:scaleY({closed})", OUT_), (s + close + hold + opn, "transform:none", None)]
    pts.append((dur, "transform:none", None))
    return kf(name, dur, pts)


def tr(pts, fn):
    return [(t, f"transform:{fn(v)}", e) for t, v, e in pts]


def stars_twinkle(prefix, delay=0.0, pre=None):
    """Independent soft twinkles for the 5 stars (start at rest)."""
    specs = [("large-yellow-star", 5.3, .4), ("small-yellow-star", 4.1, 1.6), ("white-background-star", 6.1, 2.4),
             ("key-ring-star", 4.7, .9), ("key-shaft-star", 5.6, 3.1)]
    css = (f"@keyframes {prefix}tw{{0%,100%{{transform:scale(1);opacity:1}}"
           f"35%{{transform:scale(.78);opacity:.62;animation-timing-function:{SINE}}}"
           f"62%{{transform:scale(1.06);opacity:1;animation-timing-function:{SINE}}}80%{{transform:scale(1)}}}}\n")
    for sid, d, off in specs:
        css += f".tw-{sid}{{animation:{(pre or {}).get(sid, '')}{prefix}tw {d}s {SINE} {num(delay + off)}s infinite}}\n"
    return css


# =============================================================== IDLE (7.2 s)
I = 7.2


def idle_css(p="i", delay=0.0, once=None):
    """Idle loop. `once` maps class -> 'anim spec, ' prepended (for one-shot intros)."""
    once = once or {}
    D = f" {num(delay)}s" if delay else " 0s"
    k = []
    # breathing (two breaths per loop), a hair of squash
    k.append(kf(f"{p}sq", I, [(0, "transform:none", SINE), (1.8, "transform:scaleY(1.011)", SINE),
                               (3.6, "transform:none", SINE), (4.95, "transform:none", IN_),
                               (5.05, "transform:scale(1.008,.988)", OUT_),  # nod when the key is caught
                               (5.35, "transform:scaleY(1.006)", SINE), (5.6, "transform:none", SINE),
                               (6.4, "transform:scaleY(1.008)", SINE), (I, "transform:none", None)]))
    # head: glance left, curious tilt right, back
    k.append(kf(f"{p}tilt", I, tr([(0, 0, None), (1.08, 0, SINE), (1.2, .9, OUT_), (1.58, -4.8, SINE), (1.8, -4.2, SINE),
                                    (2.38, -4.2, IN_), (2.48, -4.9, OUT_), (2.88, 6.6, SINE), (3.08, 5.9, SINE),
                                    (3.85, 5.9, INOUT), (4.38, -.6, SINE), (4.6, 0, None), (I, 0, None)],
                                   tilt_tf)))
    k.append(kf(f"{p}face", I, tr([(0, (0, 0), None), (1.15, (0, 0), INOUT), (1.62, (-9, 1), SINE), (2.45, (-9, 1), INOUT),
                                    (2.95, (8, -1), SINE), (3.9, (8, -1), INOUT), (4.45, (0, 0), None), (4.95, (0, 0), IN_),
                                    (5.05, (0, 5), OUT_), (5.32, (0, -1), SINE), (5.6, (0, 0), None), (I, (0, 0), None)],
                                   lambda v: f"translate({v[0]}px,{v[1]}px)")))
    k.append(kf(f"{p}crest", I, tr([(0, 0, None), (1.25, 0, INOUT), (1.75, 5, SINE), (2.55, 5, INOUT), (3.05, -5, SINE),
                                     (3.95, -5, INOUT), (4.55, 0, None), (I, 0, None)],
                                    lambda v: f"translate({v}px,0)")))
    # feathers: follow-through on every head move, staggered (overlap)
    ev = [(1.22, 7), (2.5, -9), (3.92, 6), (5.03, -3)]
    for cls, d, amp in [("fr", 0, .7), ("ft", .04, 1), ("fl", .08, 1.25)]:
        pts = follow([(t + d, a * amp) for t, a in ev], end=I)
        k.append(rot_track(f"{p}{cls}", I, pts))
    # eyes lead the head
    k.append(kf(f"{p}iris", I, tr([(0, (0, 0), None), (1.02, (0, 0), SNAP), (1.22, (-7, 0), None), (2.35, (-7, 0), SNAP),
                                    (2.55, (7, -1), None), (3.8, (7, -1), SNAP), (4.0, (0, 0), None), (4.45, (0, 0), SNAP),
                                    (4.62, (3, 4), None), (5.5, (3, 4), INOUT), (5.8, (0, 0), None), (I, (0, 0), None)],
                                   lambda v: f"translate({v[0]}px,{v[1]}px)")))
    k.append(blink(f"{p}blink", I, [2.4, 6.35]))
    # key adjust: beak opens, key slips, beak snaps shut, key settles
    k.append(kf(f"{p}beak", I, [(0, "transform:none", None), (4.52, "transform:none", OUT_),
                                 (4.64, "transform:scaleY(.91)", None), (4.92, "transform:scaleY(.91)", IN_),
                                 (5.0, "transform:scaleY(1.015)", OUT_), (5.15, "transform:none", None),
                                 (I, "transform:none", None)]))
    k.append(kf(f"{p}key", I, tr([(0, (0, 0), None), (4.58, (0, 0), IN_), (4.8, (4, 6), SINE), (4.97, (6, 8), SNAP),
                                   (5.09, (-3, -2), SINE), (5.27, (1.6, 0), SINE), (5.45, (-.6, 0), SINE), (5.62, (0, 0), None),
                                   (I, (0, 0), None)],
                                  lambda v: f"translate(0,{v[1]}px) rotate({num(v[0])}deg)")))
    k.append(rot_track(f"{p}wing", I, [(0, 0), (4.98, 0), (5.06, 4.5), (5.2, .6), (5.3, 1.4), (5.45, 0), (I, 0)]))
    k.append(kf(f"{p}sheen", I, [(0, "transform:translateX(0);opacity:0", None), (5.08, "transform:translateX(0);opacity:0", None),
                                  (5.09, "transform:translateX(0);opacity:1", "cubic-bezier(.4,0,.2,1)"),
                                  (5.95, "transform:translateX(640px);opacity:1", None),
                                  (5.96, "transform:translateX(640px);opacity:0", None), (I, "transform:translateX(640px);opacity:0", None)]))

    def a(cls, name):
        return f"{once.get(cls, '')}{p}{name} {I}s linear{D} infinite"
    rules = f"""
.sq{{animation:{a('sq', 'sq')}}}
.tilt{{animation:{a('tilt', 'tilt')}}}
.face{{animation:{a('face', 'face')}}}
.crest{{animation:{a('crest', 'crest')}}}
.fr{{animation:{a('fr', 'fr')}}}
.ft{{animation:{a('ft', 'ft')}}}
.fl{{animation:{a('fl', 'fl')}}}
.iris{{animation:{a('iris', 'iris')}}}
.eye{{animation:{a('eye', 'blink')}}}
.beak{{animation:{a('beak', 'beak')}}}
.keyswing{{animation:{a('keyswing', 'key')}}}
.wing{{animation:{a('wing', 'wing')}}}
.sheen{{animation:{a('sheen', 'sheen')}}}
"""
    extra_once = "".join(f".{c}{{animation:{v.rstrip(', ')}}}\n" for c, v in once.items()
                         if c not in ("sq", "tilt", "face", "crest", "fr", "ft", "fl", "iris", "eye", "beak", "keyswing", "wing", "sheen"))
    return "\n".join(k) + rules + extra_once


# =============================================================== WORKING (3.2 s)
W = 3.4


def working_css():
    k = []
    # head sweeps left <-> right, eyes lead, face parallax with a dip (arc)
    k.append(kf("wtilt", W, tr([(0, -4, None), (.9, -4, INOUT), (1.36, 4.6, SINE), (1.55, 4, None), (2.5, 4, INOUT),
                                 (2.96, -4.6, SINE), (3.15, -4, None), (W, -4, None)], tilt_tf)))
    k.append(kf("wface", W, tr([(0, (-8, 0), None), (.95, (-8, 0), INOUT), (1.18, (0, 6), INOUT), (1.42, (8, 0), None),
                                 (2.55, (8, 0), INOUT), (2.78, (0, 6), INOUT), (3.02, (-8, 0), None), (W, (-8, 0), None)],
                                lambda v: f"translate({v[0]}px,{v[1]}px)")))
    k.append(kf("wcrest", W, tr([(0, 4, None), (1.05, 4, INOUT), (1.55, -4, None), (2.65, -4, INOUT), (3.15, 4, None), (W, 4, None)],
                                 lambda v: f"translate({v}px,0)")))
    k.append(kf("wiris", W, tr([(0, -8, None), (.8, -8, INOUT), (1.12, 8, None), (2.4, 8, INOUT), (2.72, -8, None), (W, -8, None)],
                                lambda v: f"translate({v}px,0)")))
    # nod on each arrival
    k.append(kf("wsq", W, [(0, "transform:none", None), (1.36, "transform:none", OUT_), (1.46, "transform:scale(1.006,.986)", SINE),
                            (1.7, "transform:none", None), (2.96, "transform:none", OUT_),
                            (3.06, "transform:scale(1.006,.986)", SINE), (W, "transform:none", None)]))
    ev = [(.95, -8), (2.55, 8)]
    for cls, d, amp in [("fr", 0, .7), ("ft", .04, 1), ("fl", .07, 1.25)]:
        k.append(rot_track(f"w{cls}", W, follow([(t + d, a * amp) for t, a in ev], step=.095, end=W)))
    k.append(rot_track("wkey", W, follow([(.98, -4), (2.58, 4)], step=.095, end=W)))
    # wing taps while it reads (two taps per side)
    taps = [(0, 0)]
    for t in (.22, .46, 1.82, 2.06):
        taps += [(t, 0), (t + .07, 1), (t + .19, 0)]
    taps.append((W, 0))
    k.append(kf("wwing", W, [(t, "transform:translate(9px,-15px) rotate(5deg)" if v else "transform:none", OUT_ if v else IN_)
                              for t, v in taps]))
    k.append(blink("wblink", W * 2, [1.0]))
    k.append(f"@keyframes wpulse{{0%,100%{{transform:scale(.86);opacity:.7}}50%{{transform:scale(1.04);opacity:1}}}}")
    rules = f"""
.tilt{{animation:wtilt {W}s linear infinite}}
.face{{animation:wface {W}s linear infinite}}
.crest{{animation:wcrest {W}s linear infinite}}
.iris{{animation:wiris {W}s linear infinite}}
.sq{{animation:wsq {W}s linear infinite}}
.fr{{animation:wfr {W}s linear infinite}}
.ft{{animation:wft {W}s linear infinite}}
.fl{{animation:wfl {W}s linear infinite}}
.keyswing{{animation:wkey {W}s linear infinite}}
.wing{{animation:wwing {W}s linear infinite}}
.eye{{animation:wblink {W*2}s linear infinite}}
.tw{{animation:wpulse {W/2}s {SINE} infinite}}
.tw-key-ring-star{{animation-delay:0s}}
.tw-key-shaft-star{{animation-delay:-.27s}}
.tw-small-yellow-star{{animation-delay:-.53s}}
.tw-large-yellow-star{{animation-delay:-.8s}}
.tw-white-background-star{{animation-delay:-1.07s}}
"""
    return "\n".join(k) + rules


# =============================================================== FOUND (2.7 s once, then idle)
F = 2.7


def found_css():
    k = []
    k.append(kf("fmy", F, tr([(0, 0, None), (.26, 0, OUT_), (.5, -14, "cubic-bezier(.3,0,.7,.5)"), (.6, -15, IN_), (.8, 0, None),
                               (F, 0, None)], lambda v: f"translateY({v}px)")))
    k.append(kf("fsq", F, [(0, "transform:none", OUT_), (.24, "transform:scale(1.035,.93)", SNAP),
                            (.4, "transform:scaleY(1.022)", SINE), (.6, "transform:none", None),
                            (.78, "transform:none", OUT_), (.84, "transform:scale(1.03,.95)", OUT_),
                            (1.0, "transform:scaleY(1.009)", SINE), (1.16, "transform:none", None), (F, "transform:none", None)]))
    k.append(kf("ftilt", F, tr([(0, 0, None), (.95, 0, OUT_), (1.3, 5.2, SINE), (1.45, 4.6, None), (2.1, 4.6, INOUT),
                                 (2.55, 0, None), (F, 0, None)], tilt_tf)))
    k.append(kf("fface", F, tr([(0, 0, None), (1.0, 0, OUT_), (1.38, 6, None), (2.12, 6, INOUT), (2.6, 0, None), (F, 0, None)],
                                lambda v: f"translate({v}px,0)")))
    # feathers: lifted by the squash, dragged down by the take-off, flick on landing
    base = [(0, 0), (.2, 1.5), (.3, -13), (.42, -18), (.6, -13), (.76, -1), (.88, -7), (1.02, 3), (1.16, -1.2), (1.3, 0), (F, 0)]
    for cls, d, amp in [("fr", 0, .7), ("ft", .03, 1), ("fl", .06, 1.15)]:
        pts = [(0, 0)] + [(min(t + d, F - .01), v * amp) for t, v in base[1:-1]] + [(F, 0)]
        k.append(rot_track(f"f{cls}", F, pts))
    # key: lags on take-off, floats at the apex, swings on landing
    k.append(rot_track("fkey", F, [(0, 0), (.26, 0), (.45, 6), (.62, -4), (.88, 7), (1.05, -3.5), (1.22, 1.4), (1.38, 0), (F, 0)]))
    k.append(rot_track("fwing", F, [(0, 0), (.26, 0), (.36, 14), (.5, 1), (.58, 2.5), (.7, 0), (.82, 0), (.9, 6), (1.05, 0), (F, 0)], ease=OUT_))
    # eyes: brace, wide at the apex, sly squint once it has it
    k.append(kf("flid", F, [(0, "transform:none", OUT_), (.22, "transform:scaleY(.72)", OUT_), (.42, "transform:scale(1.06)", SINE),
                             (.9, "transform:none", OUT_), (1.08, "transform:scaleY(.55)", None),
                             (2.0, "transform:scaleY(.55)", INOUT), (2.3, "transform:none", None), (F, "transform:none", None)]))
    k.append(kf("firis", F, tr([(0, (0, 0), None), (.3, (0, 0), SNAP), (.46, (5, 4), None), (1.35, (5, 4), INOUT),
                                 (1.65, (-2, 0), None), (2.1, (-2, 0), INOUT), (2.4, (0, 0), None), (F, (0, 0), None)],
                                lambda v: f"translate({v[0]}px,{v[1]}px)")))
    k.append("@keyframes fsheen{0%{transform:translateX(0);opacity:0}1%{opacity:1}99%{transform:translateX(640px);opacity:1}100%{transform:translateX(640px);opacity:0}}")
    k.append("@keyframes fhalo{0%{opacity:0}28%{opacity:.8}100%{opacity:0}}")
    k.append("@keyframes fflash{0%,100%{filter:brightness(1)}30%{filter:brightness(1.13)}}")
    k.append(f"@keyframes fburst{{0%{{transform:scale(1)}}28%{{transform:scale(1.45) rotate(18deg);animation-timing-function:{SINE}}}"
             f"60%{{transform:scale(.92) rotate(-4deg)}}100%{{transform:scale(1) rotate(0deg)}}}}")
    once = {
        "my": f"fmy {F}s linear both",
        "sq": f"fsq {F}s linear both, ",
        "tilt": f"ftilt {F}s linear both, ",
        "face": f"fface {F}s linear both, ",
        "fr": f"ffr {F}s linear both, ",
        "ft": f"fft {F}s linear both, ",
        "fl": f"ffl {F}s linear both, ",
        "keyswing": f"fkey {F}s linear both, ",
        "wing": f"fwing {F}s linear both, ",
        "lid": f"flid {F}s linear both",
        "iris": f"firis {F}s linear both, ",
        "sheen": f"fsheen .75s {INOUT} .45s both, ",
    }
    css = "\n".join(k) + "\n" + idle_css("i", delay=F, once=once)
    css += f"""
#gold-key{{animation:fflash 1.2s {OUT_} .42s both}}
.halo{{animation:fhalo 1.5s {OUT_} .42s both}}
"""
    burst = {"key-ring-star": .45, "key-shaft-star": .52, "small-yellow-star": .58, "large-yellow-star": .64, "white-background-star": .7}
    css += stars_twinkle("s", delay=F, pre={sid: f"fburst 1s linear {d}s both, " for sid, d in burst.items()})
    return css


# =============================================================== HELLO (2.6 s once, then idle)
H = 2.6


def hello_css():
    k = []
    k.append(kf("hmx", H, tr([(0, -640, "cubic-bezier(.22,.75,.3,1)"), (.55, 7, SINE), (.78, 0, None), (H, 0, None)],
                              lambda v: f"translateX({v}px)")))
    k.append(kf("hmy", H, tr([(0, 780, "cubic-bezier(.2,.7,.4,1)"), (.4, -14, IN_), (.58, 0, None), (H, 0, None)],
                              lambda v: f"translateY({v}px)")))
    k.append(kf("htilt", H, tr([(0, -14, OUT_), (.45, 3, SINE), (.72, 0, None), (1.9, 0, OUT_), (2.08, 2.4, SINE),
                                 (2.4, 0, None), (H, 0, None)], tilt_tf)))
    k.append(kf("hsq", H, [(0, "transform:none", None), (.56, "transform:none", OUT_), (.62, "transform:scale(1.035,.94)", OUT_),
                            (.8, "transform:scaleY(1.006)", SINE), (.96, "transform:none", None), (H, "transform:none", None)]))
    base = [(0, 0), (.3, -11), (.56, -6), (.68, 1), (.82, -3.6), (.96, 1.2), (1.1, 0), (H, 0)]
    for cls, d, amp in [("fr", 0, .7), ("ft", .03, 1), ("fl", .06, 1.15)]:
        pts = [(0, 0)] + [(t + d, v * amp) for t, v in base[1:-1]] + [(H, 0)]
        k.append(rot_track(f"h{cls}", H, pts))
    k.append(rot_track("hkey", H, [(0, -9), (.55, 4), (.72, -3), (.9, 1.2), (1.05, 0), (H, 0)]))
    # the wave: anticipation, raise, two flicks, drop with a small overshoot
    # the wave: the wing lifts off the body (up and out), two crisp flicks, then folds back
    def wg(v):
        r, x, y = v
        return f"translate({num(x)}px,{num(y)}px) rotate({num(r)}deg)"
    k.append(kf("hwing", H, tr([(0, (0, 0, 0), None), (.92, (0, 0, 0), IN_), (1.0, (0, 0, 6), SNAP),
                                 (1.16, (20, 42, -78), SINE), (1.28, (10, 38, -70), SINE), (1.4, (20, 42, -78), SINE),
                                 (1.52, (10, 38, -70), SINE), (1.66, (18, 42, -76), IN_), (1.9, (0, 0, 0), OUT_),
                                 (2.0, (2, 0, -3), SINE), (2.12, (0, 0, 0), None), (H, (0, 0, 0), None)], wg)))
    k.append(kf("hlid", H, [(0, "transform:none", None), (1.05, "transform:none", OUT_), (1.25, "transform:scaleY(.68)", None),
                             (1.8, "transform:scaleY(.68)", INOUT), (2.05, "transform:none", None), (H, "transform:none", None)]))
    k.append(kf("hiris", H, tr([(0, (6, -4), None), (.5, (6, -4), SNAP), (.68, (0, 0), None), (H, (0, 0), None)],
                                lambda v: f"translate({v[0]}px,{v[1]}px)")))
    k.append(f"@keyframes hpop{{0%{{transform:scale(0) rotate(-30deg);opacity:0}}55%{{transform:scale(1.2) rotate(6deg);opacity:1;"
             f"animation-timing-function:{SINE}}}100%{{transform:scale(1) rotate(0deg);opacity:1}}}}")
    once = {
        "mx": f"hmx {H}s linear both",
        "my": f"hmy {H}s linear both",
        "sq": f"hsq {H}s linear both, ",
        "tilt": f"htilt {H}s linear both, ",
        "fr": f"hfr {H}s linear both, ",
        "ft": f"hft {H}s linear both, ",
        "fl": f"hfl {H}s linear both, ",
        "keyswing": f"hkey {H}s linear both, ",
        "wing": f"hwing {H}s linear both, ",
        "lid": f"hlid {H}s linear both",
        "iris": f"hiris {H}s linear both, ",
    }
    css = "\n".join(k) + "\n" + idle_css("i", delay=H, once=once)
    pop = {"key-ring-star": .62, "key-shaft-star": .74, "small-yellow-star": .86, "large-yellow-star": .98, "white-background-star": 1.1}
    css += stars_twinkle("s", delay=H, pre={sid: f"hpop .5s linear {d}s both, " for sid, d in pop.items()})
    return css


# =============================================================== LOADER (2.4 s, cropped)
L = 2.4


def loader_css():
    k = []
    k.append(kf("ltilt", L, tr([(0, -4, None), (.55, -4, INOUT), (1.05, 4.4, SINE), (1.2, 4, None), (1.75, 4, INOUT),
                                 (2.25, -4.4, SINE), (L, -4, None)], lambda v: f"rotate({num(v)}deg)")))
    k.append(kf("lface", L, tr([(0, (-5, 0), None), (.6, (-5, 0), INOUT), (.85, (0, 6), INOUT), (1.1, (5, 0), None),
                                 (1.8, (5, 0), INOUT), (2.05, (0, 6), INOUT), (2.3, (-5, 0), None), (L, (-5, 0), None)],
                                lambda v: f"translate({v[0]}px,{v[1]}px)")))
    k.append(kf("liris", L, tr([(0, -8, None), (.48, -8, INOUT), (.75, 8, None), (1.68, 8, INOUT), (1.95, -8, None), (L, -8, None)],
                                lambda v: f"translate({v}px,0)")))
    k.append(rot_track("lkey", L, follow([(.62, -6), (1.82, 6)], step=.07, end=L)))
    k.append(blink("lblink", L * 2, [.66], close=.09, hold=.07, opn=.16, closed=.05))
    k.append(f"@keyframes ltw{{0%,100%{{transform:scale(.5);opacity:.4}}40%{{transform:scale(1.3);opacity:1}}62%{{transform:scale(1.05);opacity:1}}}}")
    k.append("@keyframes lsheen{0%,40%{transform:translateX(0) scaleX(1.8);opacity:0}41%{opacity:1}80%{transform:translateX(640px) scaleX(1.8);opacity:1}80.1%,100%{transform:translateX(640px) scaleX(1.8);opacity:0}}")
    rules = f"""
.tilt{{animation:ltilt {L}s linear infinite;transform-origin:620px 600px}}
.face{{animation:lface {L}s linear infinite}}
.iris{{animation:liris {L}s linear infinite}}
.keyswing{{animation:lkey {L}s linear infinite}}
.eye{{animation:lblink {L*2}s linear infinite}}
.tw{{animation:ltw {L/2}s {SINE} infinite}}
.tw-key-ring-star{{animation-delay:0s}}
.tw-key-shaft-star{{animation-delay:-.4s}}
.tw-small-yellow-star{{animation-delay:-.8s}}
.tw-large-yellow-star{{animation-delay:-.6s}}
.sheen{{animation:lsheen {L}s {INOUT} infinite}}
"""
    return "\n".join(k) + rules


def main():
    scenes = {
        "crenel-idle.svg": (rig(BASE), idle_css() + stars_twinkle("s"), "Crenel"),
        "crenel-working.svg": (rig(BASE), working_css(), "Crenel is working"),
        "crenel-found.svg": (rig(BASE), found_css(), "Crenel found an issue"),
        "crenel-hello.svg": (rig(BASE), hello_css(), "Hello from Crenel"),
        "crenel-loader.svg": (rig(BASE, "250 130 720 720", 40), loader_css(), "Loading"),
    }
    for name, (svg, css, title) in scenes.items():
        out = css_scene(css, title, svg)
        (OUT / name).write_text(out)
        print(f"{name:22s} {len(out):6d} bytes")


if __name__ == "__main__":
    main()
