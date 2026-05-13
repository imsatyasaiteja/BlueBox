# BlueBox React UI

React dashboard for the BlueBox forensic logger. The app provides anomaly monitoring, logger controls, and forensic replay views against the BlueBox backend API.

## Project Layout

```text
bluebox_react/
  src/
    api/          API client
    components/   Shared layout, controls, charts, and status sections
    hooks/        API refresh/action hooks
    pages/        Main dashboard pages
    store/        Zustand app state
    utils/        Formatting helpers
  index.html
  package.json
  package-lock.json
  vite.config.js
  tailwind.config.js
  postcss.config.js
  jsconfig.json
```

Generated folders such as `node_modules` and `dist` are intentionally excluded from the cleaned project tree. Recreate them with install/build commands.

## Development

```bash
cd UI_layer/bluebox_react
npm install
npm run dev
```

The Vite dev server runs on `http://localhost:3000` and proxies `/api/*` requests to `http://localhost:8080`.

## Build

```bash
npm run build
npm run preview
```

## Main Scripts

```bash
npm run dev      # start local Vite development server
npm run build    # create production build in dist/
npm run preview  # preview production build locally
```
