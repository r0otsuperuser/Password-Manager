// background.js — service worker (Manifest V3)

const NATIVE_HOST = "com.pwmanager.autofill";
const LOCK_ALARM_NAME = "pwmanager-lock-check";
const DEFAULT_TIMEOUT_MINUTES = 10;

// port/unlocked are global state for the service worker (not per-tab/popup).
// If two concurrent requests arrive (e.g. two tabs opening the popup at the
// same time), they share the same port and the same pendingRequests queue —
// there's no per-caller isolation.
let port = null;
let unlocked = false;

// FIFO queue that matches each postMessage with its response via shift().
// NOTE: this is only safe because backend.c processes and responds to
// each message synchronously and sequentially (see native_server in
// backend.c — there are no concurrent requests on the native side). If
// the native host ever starts responding out of order, this pairing
// breaks silently and a response could be delivered to the wrong
// promise (e.g. one site's credential answered as if it were another's).
let pendingRequests = [];

function isLocked() {
  return !port || !unlocked;
}

function lock() {
  if (port) {
    try { port.disconnect(); } catch (e) { /* may already be disconnected */ }
  }
  port = null;
  unlocked = false;

  pendingRequests.forEach((p) => p.reject(new Error("session locked")));
  pendingRequests = [];

  chrome.storage.session.remove("lastActivity");
  chrome.alarms.clear(LOCK_ALARM_NAME);
}

function touchActivity() {
  // storage.session (not .local) by design: this data should only exist
  // while the browser is open. It disappears automatically when Chrome
  // closes, so no trace of "when the session was last active" is left
  // persisted on disk between one browsing session and the next.
  chrome.storage.session.set({ lastActivity: Date.now() });
}

function ensurePort() {
  if (port) return port;

  // The browser starts the ./pwmanager native process here.
  port = chrome.runtime.connectNative(NATIVE_HOST);

  // Without onDisconnect, when the OS tells Chrome that pwmanager native
  // has exited, the extension's session would still think it's unlocked.
  port.onDisconnect.addListener(() => {
    if (chrome.runtime.lastError) {
      console.error("Native host disconnected:", chrome.runtime.lastError.message);
    }
    lock();
  });

  port.onMessage.addListener((response) => { // receives backend.c's response
    const pending = pendingRequests.shift();
    if (!pending) return; // unexpected response, ignore

    if (response && response.error) {
      // backend.c returns {"error": "..."} instead of status/credentials
      // when the operation fails (see write_message in backend.c).
      pending.reject(new Error(response.error));
    } else {
      pending.resolve(response);
    }
  });

  return port;
}

function sendToNative(message) {
  return new Promise((resolve, reject) => {
    const p = ensurePort();
    pendingRequests.push({ resolve, reject });
    p.postMessage(message);
  });
}

async function unlock(masterPassword) {
  const { authToken } = await chrome.storage.local.get("authToken");
  if (!authToken) {
    throw new Error("No token configured. Open the extension's options page.");
  }

  const response = await sendToNative({
    action: "unlock",
    master_password: masterPassword,
    auth_token: authToken,
  });

  if (response && response.status === "unlocked") {
    unlocked = true;
    touchActivity();
    await ensureLockAlarm();
    return true;
  }

  // unlock failed: no point keeping the native process open
  lock();
  throw new Error("Failed to unlock");
}

// Credentials are only released to HTTPS pages (plus localhost for development):
// on plain HTTP, anyone on the network path could read or tamper with the page.
function isAllowedUrl(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return false;
  }
  if (u.protocol === "https:") return true;
  return u.protocol === "http:" &&
    (u.hostname === "localhost" || u.hostname === "127.0.0.1");
}

async function getCredentialsFor(url) {
  if (isLocked()) {
    throw new Error("locked");
  }

  if (!isAllowedUrl(url)) {
    throw new Error("autofill is only allowed on HTTPS pages")
  }

  touchActivity();

  return sendToNative({ action: "get_credentials", url });

}

async function getTimeoutMinutes() {
  const { sessionTimeoutMinutes } = await chrome.storage.local.get("sessionTimeoutMinutes");
  const n = Number(sessionTimeoutMinutes);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MINUTES;
}

async function ensureLockAlarm() {
  // Coarse granularity (about a minute) is enough for an inactivity check.
  chrome.alarms.create(LOCK_ALARM_NAME, { periodInMinutes: 1 });
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== LOCK_ALARM_NAME) return;
  if (isLocked()) return;

  const { lastActivity } = await chrome.storage.session.get("lastActivity");
  if (!lastActivity) {
    lock();
    return;
  }

  const timeoutMinutes = await getTimeoutMinutes();
  const elapsedMs = Date.now() - lastActivity;

  if (elapsedMs >= timeoutMinutes * 60 * 1000) {
    lock();
  }
});

// _sender is not validated here. This is only safe because the current
// manifest.json declares no content_scripts and no externally_connectable —
// meaning no web page or external extension can call sendMessage on this
// extension today; only the popup/options page can. If that ever changes
// (e.g. a content_script is added), this listener would start accepting
// UNLOCK/GET_CREDENTIALS from external origins without anything here
// needing to change — in that case, validate _sender.id === chrome.runtime.id
// (and possibly _sender.origin) before the switch below.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case "STATUS": {
          sendResponse({ ok: true, unlocked: !isLocked() });
          break;
        }

        case "UNLOCK": {
          await unlock(msg.masterPassword);
          sendResponse({ ok: true });
          break;
        }

        case "GET_CREDENTIALS": {
          const credentials = await getCredentialsFor(msg.url);
          sendResponse({ ok: true, credentials });
          break;
        }

        case "LOCK": {
          lock();
          sendResponse({ ok: true });
          break;
        }

        default:
          sendResponse({ ok: false, error: "unknown message type" });
      }
    } catch (err) {
      sendResponse({ ok: false, error: err.message });
    }
  })();

  return true; // keeps the channel open for the async response
});