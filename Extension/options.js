const tokenInput = document.getElementById("token");
const status = document.getElementById("status");

// Pre-fills the field if a token is already saved, to make it easy to check
chrome.storage.local.get("authToken").then(({ authToken }) => {
  if (authToken) tokenInput.value = authToken;
});

document.getElementById("save").addEventListener("click", async () => {
  const token = tokenInput.value.trim();

  if (!/^[0-9a-fA-F]{64}$/.test(token)) {
    status.style.color = "red";
    status.textContent = "Invalid token. Must be 64 hexadecimal characters.";
    return;
  }

  await chrome.storage.local.set({ authToken: token });
  status.style.color = "green";
  status.textContent = "Token saved successfully.";
});

// requires "options_page": "options.html" in manifest.json
