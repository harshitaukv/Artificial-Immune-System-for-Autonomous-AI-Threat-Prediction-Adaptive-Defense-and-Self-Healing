import React from 'react'
import { createRoot } from 'react-dom/client'
import { HashRouter } from 'react-router-dom'
import App from './App'
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import './styles.css'

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    {/* HashRouter: the dashboard is served as static files from FastAPI, so
        hash routing works regardless of how the bundle is mounted. */}
    <HashRouter>
      <App />
    </HashRouter>
  </React.StrictMode>
)
