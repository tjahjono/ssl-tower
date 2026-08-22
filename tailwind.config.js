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
      fontFamily: {
        sans: ["ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Inter", "Roboto", "Helvetica Neue", "Arial", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "Liberation Mono", "monospace"],
      },
    },
  },
  plugins: [],
};
