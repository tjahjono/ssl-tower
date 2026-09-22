/** @type {import('tailwindcss').Config} */
module.exports = {
  // Go files are scanned too: status badge classes are chosen in
  // internal/delivery/http/render.go, not in the templates.
  content: [
    "./internal/delivery/http/templates/**/*.html",
    "./internal/delivery/http/static/*.js",
    "./internal/**/*.go",
  ],
  theme: {
    extend: {
      // Pure OS-native stack, deliberately with no webfont (Inter or
      // otherwise) in it — "system-ui" alone already resolves to each
      // platform's actual UI font (Segoe UI Variable on Windows 11, San
      // Francisco on macOS/iOS, Roboto on Android/ChromeOS), which reads as
      // a native app rather than the generic web-template look a bundled
      // Inter fallback gives every other AI-scaffolded project. The CSP
      // (middleware.go's securityHeaders, default-src 'self') blocks
      // external font CDNs by design, so this also avoids a font-src
      // exception that would otherwise be needed for nothing.
      fontFamily: {
        sans: ["system-ui", "-apple-system", "Segoe UI", "Roboto", "Helvetica Neue", "Arial", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "Liberation Mono", "monospace"],
      },
      // Theme-aware semantic colors — CSS-variable-backed so light/dark mode
      // (see web/input.css's `:root` / `[data-theme="light"]` blocks) swaps
      // every consumer of these at once instead of doubling every class with
      // a `dark:` variant. The `<alpha-value>` placeholder is Tailwind's own
      // mechanism for keeping opacity modifiers (`bg-card/40`) working with a
      // CSS-variable color — see https://tailwindcss.com/docs/customizing-colors#using-css-variables.
      colors: {
        surface: "rgb(var(--color-surface) / <alpha-value>)",
        card: "rgb(var(--color-card) / <alpha-value>)",
        line: "rgb(var(--color-line) / <alpha-value>)",
        ink: "rgb(var(--color-ink) / <alpha-value>)",
        "ink-1": "rgb(var(--color-ink-1) / <alpha-value>)",
        "ink-2": "rgb(var(--color-ink-2) / <alpha-value>)",
        "ink-3": "rgb(var(--color-ink-3) / <alpha-value>)",
        "ink-4": "rgb(var(--color-ink-4) / <alpha-value>)",
        "ink-5": "rgb(var(--color-ink-5) / <alpha-value>)",
        "ink-6": "rgb(var(--color-ink-6) / <alpha-value>)",
        "hue-emerald": "rgb(var(--color-hue-emerald) / <alpha-value>)",
        "hue-emerald-strong": "rgb(var(--color-hue-emerald-strong) / <alpha-value>)",
        "hue-amber": "rgb(var(--color-hue-amber) / <alpha-value>)",
        "hue-amber-strong": "rgb(var(--color-hue-amber-strong) / <alpha-value>)",
        "hue-orange": "rgb(var(--color-hue-orange) / <alpha-value>)",
        "hue-rose": "rgb(var(--color-hue-rose) / <alpha-value>)",
        "hue-rose-strong": "rgb(var(--color-hue-rose-strong) / <alpha-value>)",
        "hue-sky": "rgb(var(--color-hue-sky) / <alpha-value>)",
        "hue-sky-strong": "rgb(var(--color-hue-sky-strong) / <alpha-value>)",
        "hue-fuchsia": "rgb(var(--color-hue-fuchsia) / <alpha-value>)",
        "hue-fuchsia-strong": "rgb(var(--color-hue-fuchsia-strong) / <alpha-value>)",
        // brand: the primary accent (buttons, focus rings, checkbox/radio
        // accents) — a fixed literal color, not theme-variable-backed,
        // matching the fixed "sky-500/400" it replaces (the primary accent
        // was never theme-toggled before this either). Best-known
        // approximation of OCBC's signature red — confirm against exact
        // brand guidelines and adjust here if it doesn't match. Deliberately
        // NOT the same hue as hue-rose (the existing danger/critical/
        // destructive color, a pink-leaning red) — brand-500 is a purer,
        // more orange-leaning red so a primary "Generate" button and a
        // "Delete" button never read as the same signal.
        brand: {
          400: "#EB4060",
          500: "#E4002B",
        },
      },
    },
  },
  plugins: [],
};
