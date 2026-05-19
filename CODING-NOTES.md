# CODING-NOTES — khurksecret

## What This Project Is
Shamir's Secret Sharing web app — split secrets into N shares, reconstruct with K threshold. Browser-only, no server needed.

## Tech Stack
- Vanilla JavaScript (no TypeScript)
- No framework — plain HTML/CSS/JS
- No build step needed

## Structure
```
/
├── index.html           # Single-page app
├── style.css
├── script.js
└── package.json         # Minimal (if exists)
```

## Build & Dev
- **Run:** Open index.html in a browser (no build step)
- Or serve with any static file server: `python3 -m http.server 8000` or `npx serve .`

## Deploy
- GitHub Pages (handled via repo settings or manual)

## TypeScript
- No TypeScript. All vanilla JS.

## Tests & Lint
- None

## Known Gotchas
- All crypto happens in the browser — no data ever hits a server
- Shamir's Secret Sharing is information-theoretically secure but requires trusted entropy
- Large secrets = many shares = slow. Test with realistic payload sizes.
- No build step means no tree-shaking, no minification — keep dependencies minimal

## Previous Bugs / Regressions
*(Fill in as they happen)*
