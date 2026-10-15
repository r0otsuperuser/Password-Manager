// front.js — popup script. Delegates everything to background.js (the service worker),
// which keeps the native-host session alive between popup opens.

const status = document.getElementById("status");
const lockedBadge = document.getElementById("lockedBadge");
const unlockForm = document.getElementById("unlockForm");
const masterInput = document.getElementById("masterPassword");
const sendButton = document.getElementById("send");

function sendToBackground(message) {
  return chrome.runtime.sendMessage(message);
}

async function refreshStatus() {
  const res = await sendToBackground({ type: "STATUS" });
  const unlocked = res && res.ok && res.unlocked;

  unlockForm.style.display = unlocked ? "none" : "block";
  lockedBadge.textContent = unlocked ? "Session unlocked" : "Session locked";
  lockedBadge.style.color = unlocked ? "green" : "#888";

  return unlocked;
}

refreshStatus().catch(() => {
  lockedBadge.textContent = "Session locked"
})

function showError(message) {
  status.style.color = "red"
  status.textContent = "Error: " + message
}

async function fillCredentials() {
  let unlocked = await refreshStatus();

  if (!unlocked) {
    const masterPassword = masterInput.value;
    if (!masterPassword) {
      status.style.color = "red";
      status.textContent = "Enter the master password.";
      return;
    }

    let unlockRes;
    try {
      unlockRes = await sendToBackground({ type: "UNLOCK", masterPassword });
    } finally {
      masterInput.value = ""; // clear the field even if the call throws
    }

    if (!unlockRes || !unlockRes.ok) {
      showError(unlockRes ? unlockRes.error : "no response from background");
      return;
    }

    await refreshStatus();
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    showError("no active tab");
    return;
  }

  const credRes = await sendToBackground({ type: "GET_CREDENTIALS", url: tab.url });

  if (!credRes || !credRes.ok) {
    showError(credRes ? credRes.error : "no response from background");
    return;
  }

  const { username, password } = credRes.credentials;

  if (!username) {
    status.style.color = "orange";
    status.textContent = "No credentials found for this site.";
    return;
  }

  // allFrames: true is needed because some sites (e.g. institutional or bank portals)
  // load the login form inside an <iframe>, and without this the autofill
  // wouldn't reach that frame.
  //
  // This opens a risk surface: ANY iframe on the page would be scanned by
  // the selectors, including third-party iframes (ads, chat widgets,
  // embedded checkout from another domain) — if a field there happens to
  // match the selectors, the credential would leak into that frame.
  //
  // Mitigation: we pass the expected origin (the tab's, not the frame's)
  // and validate it inside autofill() BEFORE touching any field. This
  // allows same-origin iframes (the common case) and blocks any
  // frame with a different origin, even if the selectors match.
  const expectedOrigin = new URL(tab.url).origin;

  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    func: autofill,
    args: [username, password, expectedOrigin],
  });

  // Each frame returns true if it filled at least one field.
  const filled = results.some((r) => r.result === true);
  if (filled) {
    status.style.color = "green";
    status.textContent = "Filled.";
  } else {
    status.style.color = "orange";
    status.textContent = "No login fields found on this page.";
  }
}

sendButton.addEventListener("click", async () => {
  status.style.color = "";
  status.textContent = "";

  try {
    await fillCredentials();
  } catch (err) {
    showError(err && err.message ? err.message : "unexpected failure");
  }
});

function autofill(username, password, expectedOrigin) {
  // Bail out if this frame isn't the same origin as the tab the user is
  // actually looking at — prevents the credential from being typed into
  // a third-party iframe (ads, widgets, embedded checkout) whose field
  // happens to match the selectors below.
  if (window.location.origin !== expectedOrigin) {
    return;
  }

  // Selectors for the username/ID field
  const userSelectors = [
    "input[data-testid*='cpf' i]",
    "input[data-testid*='user' i]",
    "input[data-testid*='login' i]",
    "input[id*='cpf' i]",
    "input[id*='cnpj' i]",
    "input[name*='user' i]",
    "input[name*='login' i]",
    "input[name*='cpf' i]",
    "input[name*='cnpj' i]",
    "input[name*='document' i]",
    "input[autocomplete='username']",
    "input[type='email']",
    "input[type='text']",
    "input[type='tel']",
  ]

  const passSelectors = [
    "input[type='password']",
    "input[data-testid*='pass' i]",
    "input[name*='pass' i]",
  ]

  function isVisible(field) {
    return !!(field.offsetWidth || field.offsetHeight || field.getClientRects().length);
  }

  function looksLikeSearch(field) {
    const hint = `${field.type} ${field.name} ${field.id} ${field.placeholder}`;
    return /search|busca|pesquis/i.test(hint);
  }

  function findField(selectors) {
    for (const selector of selectors) {
      for (const el of document.querySelectorAll(selector)) {
        if (isVisible(el) && !el.disabled && !el.readOnly && !looksLikeSearch(el)) {
          return el;
        }
      }
    }
    return null;
  }

  function simulateTyping(field, value) {
    if (!field) return false;

    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value"
    ).set;

    field.focus();

    // Clear the field first (simulates select-all + delete)
    nativeInputValueSetter.call(field, "");
    field.dispatchEvent(new InputEvent("input", {
      bubbles: true, cancelable: true, inputType: "deleteContentBackward",
    }));

    let typed = "";
    for (const char of value) {
      typed += char;

      field.dispatchEvent(new KeyboardEvent("keydown", { key: char, bubbles: true }));
      field.dispatchEvent(new KeyboardEvent("keypress", { key: char, bubbles: true }));

      nativeInputValueSetter.call(field, typed);

      field.dispatchEvent(new InputEvent("input", {
        bubbles: true,
        cancelable: true,
        inputType: "insertText",
        data: char,
      }));

      field.dispatchEvent(new KeyboardEvent("keyup", { key: char, bubbles: true }));
    }

    field.dispatchEvent(new Event("change", { bubbles: true }));
    field.blur();
    return true
  }

  const userFilled = simulateTyping(findField(userSelectors), username);
  const passFilled = simulateTyping(findField(passSelectors), password);

  return userFilled || passFilled;
}