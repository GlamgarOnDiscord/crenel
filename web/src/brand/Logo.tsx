// Crenel identity marks. Concept: a jackdaw (choucas) perched on a battlement
// crenel. The jackdaw collects shiny things, which maps to Crenel finding the
// keys and secrets your app leaks; the crenel is the fortification it guards.
// Amber-gold, deliberately not the green/cyan of every other security tool.

export function Mark({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true">
      {/* battlement */}
      <path d="M4 21h3v-2.6h3V21h3v-2.6h3V21h3v-2.6h3V21v7H4z" fill="var(--brand-deep)" />
      {/* jackdaw head */}
      <circle cx="17" cy="12.4" r="6.3" fill="var(--brand)" />
      {/* beak */}
      <path d="M23 11.3l6.1-1.7-3.4 4.5z" fill="var(--brand)" />
      {/* eye, negative space */}
      <circle cx="15.3" cy="11.3" r="1.7" fill="var(--bg)" />
      {/* leg to the crenel */}
      <path d="M11.4 20.2l-2.3 3.1" stroke="var(--brand)" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="wm">
      crenel<span className="notch" aria-hidden="true" />
    </span>
  );
}

// A fuller illustration for empty states and the landing hero.
export function Mascot({ size = 120 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 160 160" fill="none" role="img" aria-label="Crenel, le choucas de garde">
      <defs>
        <linearGradient id="mg" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="var(--brand-ink)" />
          <stop offset="1" stopColor="var(--brand)" />
        </linearGradient>
      </defs>
      {/* crenel wall */}
      <path d="M26 112h14v-12h14v12h14v-12h14v12h14v-12h14v12v26H26z" fill="var(--panel-raised)" stroke="var(--line-strong)" strokeWidth="2" />
      {/* body */}
      <ellipse cx="86" cy="86" rx="30" ry="34" fill="var(--brand-deep)" />
      {/* head */}
      <circle cx="78" cy="56" r="26" fill="url(#mg)" />
      {/* beak holding a key */}
      <path d="M100 54l30-7-16 20z" fill="var(--brand)" />
      <circle cx="132" cy="48" r="6" fill="none" stroke="var(--brand-ink)" strokeWidth="3" />
      <path d="M137 50l10 8m-4 0 3 3m-6-7 3 3" stroke="var(--brand-ink)" strokeWidth="3" strokeLinecap="round" />
      {/* eye */}
      <circle cx="72" cy="52" r="5" fill="var(--bg)" />
      <circle cx="73.5" cy="50.5" r="1.6" fill="var(--brand-ink)" />
      {/* wing */}
      <path d="M92 78c-10 6-22 6-30 2 6 14 26 16 34 4z" fill="var(--bg)" opacity="0.18" />
    </svg>
  );
}
