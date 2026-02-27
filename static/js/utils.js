// utils.js — shared frontend helpers
// accumulated over time, some of these are only used in one place

/**
 * Debounce a function call. Standard implementation.
 */
function debounce(fn, delay) {
  let timer;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

// throttle — similar to debounce but ensures fn runs at most once per interval
function throttle(fn, interval) {
  let last = 0;
  return function (...args) {
    const now = Date.now();
    if (now - last >= interval) {
      last = now;
      fn.apply(this, args);
    }
  };
}


/* format bytes to human readable */
function fmtBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
  return val + ' ' + units[i];
}

// basic html entity escaping for user content
function escapeHtml(str) {
  if (!str) return '';
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return str.replace(/[&<>"']/g, function (c) { return map[c]; });
}

function copyToClipboard(text) {
  // try modern API first, fall back to execCommand
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text);
  }
  // fallback
  const tmp = document.createElement('textarea');
  tmp.value = text;
  tmp.style.position = 'fixed';
  tmp.style.left = '-9999px';
  document.body.appendChild(tmp);
  tmp.select();
  document.execCommand('copy');
  document.body.removeChild(tmp);
  return Promise.resolve();
}


// format a date relative to now (used in recent results, activity feed)
function timeAgo(ts) {
  const diff = Date.now() - ts;
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return 'just now';
  const mins = Math.floor(secs / 60);
  if (mins < 60) return mins + 'm ago';
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h ago';
  const d = Math.floor(hrs / 24);
  if (d < 30) return d + 'd ago';
  return Math.floor(d / 30) + 'mo ago';
}

// TODO: add a proper toast notification system instead of alert()
function showToast(msg, type) {
  console.log('[toast]', type, msg);
}


// color helpers used across dashboard and reports
const THREAT_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  clean: '#10b981'
};

function getThreatColor(level) {
  return THREAT_COLORS[level] || '#6b7280';
}


// function parseQueryParams() {
//   const params = {};
//   window.location.search.slice(1).split('&').forEach(p => {
//     const [k, v] = p.split('=');
//     if (k) params[decodeURIComponent(k)] = decodeURIComponent(v || '');
//   });
//   return params;
// }


function slugify(text) {
  return text.toString().toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^\w\-]+/g, '')
    .replace(/\-\-+/g, '-')
    .replace(/^-+/, '')
    .replace(/-+$/, '');
}

/* truncate text with ellipsis */
function truncate(str, n) {
  if (!str) return '';
  n = n || 80;
  return str.length > n ? str.substring(0, n - 1) + '…' : str;
}

// simple class toggle helper
function toggleClass(el, cls) {
  if (el.classList.contains(cls)) {
    el.classList.remove(cls);
  } else {
    el.classList.add(cls);
  }
}
