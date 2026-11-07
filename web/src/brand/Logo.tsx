// Crenel identity marks. The mascot is a jackdaw (choucas): its pale silvery
// nape is the species' signature, and it holds a golden key it just found,
// which is what Crenel does with the keys and secrets your app leaks. The art
// is a raster master (public/crenel-icon-1024.png) exported at a few sizes;
// these components pick the smallest file that stays sharp at 2x.

function iconFile(px: number): string {
  const need = px * 2;
  const size = need <= 64 ? 64 : need <= 180 ? 180 : need <= 512 ? 512 : 1024;
  return `crenel-icon-${size}.png`;
}

// Animated scenes rigged from the same artwork (brand/motion). `found` and
// `hello` play once and settle into idle; the others loop.
export type Mood = "idle" | "working" | "found" | "hello" | "loader";

// App-icon mark: the square artwork clipped to a squircle-like radius.
export function Mark({ size = 30, mood }: { size?: number; mood?: Mood }) {
  return (
    <img
      key={mood}
      src={mood ? `crenel-${mood}.svg` : iconFile(size)}
      width={size}
      height={size}
      alt=""
      aria-hidden="true"
      draggable={false}
      style={{ display: "block", flex: "none", borderRadius: size * 0.235 }}
    />
  );
}

export function Wordmark() {
  return (
    <span className="wm">
      crenel<span className="notch" aria-hidden="true" />
    </span>
  );
}

// The same character, larger, for the landing hero, onboarding and empty states.
export function Mascot({ size = 120, mood = "idle" }: { size?: number; mood?: Mood }) {
  return (
    <img
      key={mood}
      src={`crenel-${mood}.svg`}
      width={size}
      height={size}
      alt="Crenel, le choucas qui a trouvé une clé"
      draggable={false}
      style={{
        display: "block",
        borderRadius: size * 0.235,
        boxShadow: "0 18px 50px -18px rgba(0,0,0,.7), 0 0 0 1px rgba(255,255,255,.06)",
      }}
    />
  );
}
