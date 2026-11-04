import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './index.css';

// Institutional tooling: a session screen must never be restored from cache.
// This only affects the web target; the Capacitor WebView loads from disk.
if (!document.querySelector('meta[name="referrer"]')) {
  const referrer = document.createElement('meta');
  referrer.name = 'referrer';
  referrer.content = 'no-referrer';
  document.head.appendChild(referrer);
}

const container = document.getElementById('root');
if (!container) throw new Error('Root container missing in index.html');

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
