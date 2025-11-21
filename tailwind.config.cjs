/** @type {import('tailwindcss').Config} */
const defaultTheme = require("tailwindcss/defaultTheme")
module.exports = {
  content: ["./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue,mjs}"],
  darkMode: "class", // allows toggling dark mode manually
  theme: {
    extend: {
      fontFamily: {
        sans: ["JetBrains Mono", "Roboto", "sans-serif", ...defaultTheme.fontFamily.sans],
      },
      colors: {
        'default-blue': 'var(--color-default-blue)',
        'default-red': 'var(--color-default-red)',
        'default-green': 'var(--color-default-green)',
      },
    },
  },
  plugins: [require("@tailwindcss/typography")],
}
