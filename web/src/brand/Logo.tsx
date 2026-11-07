// Crenel identity marks. Concept: a jackdaw (choucas) perched on a battlement
// crenel, holding a key in its beak. The jackdaw collects shiny things, which
// maps to Crenel finding the keys and secrets your app leaks; the crenel is the
// fortification it guards. Amber-gold, deliberately not the green/cyan of every
// other security tool.

export function Mark({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true">
      {/* battlement */}
      <path d="M4 22h3.4v-2.8h3.4V22h3.4v-2.8h3.4V22h3.4v-2.8H28V22v6H4z" fill="var(--brand-deep)" />
      {/* jackdaw head */}
      <circle cx="16.5" cy="12" r="6" fill="var(--brand)" />
      {/* beak */}
      <path d="M22 11l5.6-1.5-3.1 4.1z" fill="var(--brand)" />
      {/* key held in the beak */}
      <circle cx="27.4" cy="8.7" r="2" fill="none" stroke="var(--brand-ink)" strokeWidth="1.3" />
      <path d="M28.9 9.8l1.6 1.6m-.6-.2.7.7m-1.7-1.7.7.7" stroke="var(--brand-ink)" strokeWidth="1.3" strokeLinecap="round" />
      {/* eye, negative space */}
      <circle cx="14.9" cy="11" r="1.6" fill="var(--bg)" />
      {/* leg on the crenel */}
      <path d="M15 17.6v2.2" stroke="var(--brand-deep)" strokeWidth="1.6" strokeLinecap="round" />
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
    <svg width={size} height={size} viewBox="0 0 160 160" fill="none" role="img" aria-label="Crenel, le choucas de garde tenant une clé">
      <defs>
        <linearGradient id="mg" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="var(--brand-ink)" />
          <stop offset="1" stopColor="var(--brand)" />
        </linearGradient>
      </defs>
      {/* crenel wall */}
      <path d="M22 118h16v-13h16v13h16v-13h16v13h16v-13h16v13v28H22z" fill="var(--panel-raised)" stroke="var(--line-strong)" strokeWidth="2" />
      {/* tail */}
      <path d="M58 96l-26 10 20 8z" fill="var(--brand-deep)" />
      {/* body, two tones */}
      <ellipse cx="86" cy="86" rx="30" ry="33" fill="var(--brand-deep)" />
      <path d="M86 56c16 2 27 15 27 31 0 9-3 16-9 21-20 4-38-10-38-30 0-11 8-20 20-22z" fill="var(--brand)" opacity="0.35" />
      {/* legs on the merlon */}
      <path d="M78 118v10M94 118v10" stroke="var(--brand-deep)" strokeWidth="4" strokeLinecap="round" />
      {/* head */}
      <circle cx="78" cy="54" r="25" fill="url(#mg)" />
      {/* beak */}
      <path d="M100 52l28-6-15 19z" fill="var(--brand)" />
      {/* key, clear: bow ring + stem + two teeth */}
      <circle cx="131" cy="43" r="8" fill="none" stroke="var(--brand-ink)" strokeWidth="4" />
      <path d="M138 48l16 16" stroke="var(--brand-ink)" strokeWidth="4" strokeLinecap="round" />
      <path d="M150 60l5 5M146 64l4 4" stroke="var(--brand-ink)" strokeWidth="4" strokeLinecap="round" />
      {/* eye */}
      <circle cx="72" cy="50" r="5.2" fill="var(--bg)" />
      <circle cx="73.6" cy="48.4" r="1.7" fill="var(--brand-ink)" />
    </svg>
  );
}
