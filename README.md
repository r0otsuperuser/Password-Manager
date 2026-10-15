# PwManager

> A local, libsodium-encrypted password manager in C with a Chrome autofill extension, built to make strong, unique passwords practical and to keep them off the screen.

The vault is a single SQLite file (`vault.db`) encrypted with [libsodium](https://doc.libsodium.org/). There is no server, no online account and no cloud sync: the file stays with the user, who decides where to keep it.

## Why this project?

Weak and reused passwords are among the most common causes of account takeover: one breach at a single site exposes every other account that shares the same password. The usual obstacle is practical, since nobody can memorize dozens of long, unique passwords.

PwManager removes that obstacle locally. It generates strong random passwords (16 to 128 characters), stores one unique credential per site in an encrypted vault, and fills them in through a browser extension, so the user only has to remember a single master password.

It also treats **shoulder surfing** as part of the threat model: every password prompt hides its input, and retrieved or generated passwords are copied straight to the clipboard instead of being printed on screen.

## Highlights

- **Argon2 (`SENSITIVE`) key derivation** and per-record authenticated encryption (`crypto_secretbox`)
- **No password on screen**: hidden input everywhere and automatic clipboard copy
- **Atomic master password change**: every record is re-encrypted in one SQLite transaction, with rollback on any failure
- **Extension hardening**: HTTPS-only autofill, same-origin iframe check, and a pairing token stored only as a hash
- **Automatic inactivity lock** for the browser session

---

## Features

- **Encrypted vault**: each credential is encrypted individually with `crypto_secretbox` (XSalsa20-Poly1305), using its own random nonce.
- **Strong key derivation**: the key is derived from the master password with `crypto_pwhash` (Argon2) using the `SENSITIVE` CPU and memory limits, which makes GPU brute-force attacks much more expensive.
- **The master password is never stored**: the vault only keeps a known message (`vault-check`) encrypted with the derived key. A correct password re-derives the key and decrypts that message.
- **Full CLI**: create a vault, add, look up and delete credentials, generate passwords and change the master password.
- **Shoulder-surfing protection**: the master password and credential passwords are typed with terminal echo disabled, and `get` / `gen` copy the password to the clipboard via `xclip` instead of displaying it. The password is only printed as a fallback when `xclip` is not installed.
- **Password generator** (16 to 128 characters) using `randombytes_uniform`, guaranteeing at least one lowercase letter, one uppercase letter, one digit and one symbol, followed by a shuffle.
- **Atomic master password change**: all credentials are re-encrypted inside a SQLite transaction. If any record fails, the transaction is rolled back and the vault stays intact.
- **Browser extension** with autofill through Native Messaging.

---

## Architecture

```
┌──────────────────────┐      chrome.runtime       ┌──────────────────────┐
│  popup (front.js)    │ ────────────────────────► │  background.js       │
│  master password, UI │ ◄──────────────────────── │  service worker      │
└──────────────────────┘                           │  keeps the session   │
                                                   └──────────┬───────────┘
                                                              │ Native Messaging
                                                              │ (stdio, JSON with
                                                              │  4-byte length prefix)
                                                   ┌──────────▼───────────┐
                                                   │ pwmanager native     │
                                                   │ (backend.c)          │
                                                   │ checks token + pwd   │
                                                   │ decrypts vault.db    │
                                                   └──────────────────────┘
```

| File | Purpose |
|---|---|
| `main.c` | CLI: `init`, `add`, `get`, `del`, `gen`, `newpw`, `native`, plus cryptography and database access |
| `backend.c` / `backend.h` | Native host: message protocol, minimal JSON parser, token validation, per-domain credential lookup |
| `Extension/manifest.json` | Extension manifest (MV3) |
| `Extension/background.js` | Service worker: manages the native port, the unlock state and automatic locking on inactivity |
| `Extension/front.js` / `Extension/popup.html` | Popup: unlocking and triggering autofill |
| `Extension/options.js` / `Extension/options.html` | Settings page where the extension token is saved |
| `com.pwmanager.autofill.json` | Native messaging host manifest (registers the executable with Chrome) |
| `pwmanager_native_host.sh` | Script Chrome runs to start `./pwmanager native` in the vault folder |

### Database schema

```sql
CREATE TABLE credentials (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  nonce      BLOB NOT NULL,
  ciphertext BLOB NOT NULL      -- encrypted "site=...\nusername=...\npassword=..."
);

CREATE TABLE vault (
  id               INTEGER PRIMARY KEY CHECK (id = 1),
  salt             BLOB NOT NULL,
  kdf_alg          TEXT NOT NULL,
  opslimit         INTEGER NOT NULL,
  memlimit         INTEGER NOT NULL,
  check_nonce      BLOB NOT NULL,
  check_ciphertext BLOB NOT NULL,
  auth_token       BLOB NOT NULL   -- only the HASH of the extension token
);
```

---

## Requirements

- Linux (clipboard copy uses `xclip`)
- `gcc`, `libsodium` and `libsqlite3` (with development headers)
- `xclip` (optional, but recommended)
- Google Chrome or Chromium (for the extension)

On Debian/Ubuntu:

```bash
sudo apt install build-essential libsodium-dev libsqlite3-dev xclip
```

---

## Building

```bash
make
```

Or directly:

```bash
gcc -Wall -Wextra -O2 main.c backend.c -o pwmanager -lsodium -lsqlite3
```

> Never commit your `vault.db`. The provided `.gitignore` already excludes it.

---

## CLI usage

```text
./pwmanager init          Create and initialize a new vault database
./pwmanager add           Add new credentials to the vault
./pwmanager get           List and copy credentials to clipboard
./pwmanager del           Select and remove a credential
./pwmanager gen <length>  Generate a password (length between 16 and 128)
./pwmanager native        Start the Native Messaging host for the browser extension
./pwmanager newpw         Set a new master password
```

`vault.db` is created and read **in the current directory**. `init` refuses to overwrite an existing vault.

### First run

```bash
./pwmanager init
```

Choose a master password. When it finishes, the program prints a **64-character hexadecimal authentication token**. It is shown **only once** and is used to pair the extension with the vault. Only the token's hash is stored in the database.

---

## Installing the extension (Chrome)

1. **Generate a key pair** to give the extension a stable ID (see [Why a fixed extension ID?](#why-a-fixed-extension-id) below):
   ```bash
   # private key: keep it secret, never commit it
   openssl genrsa -out key.pem 2048

   # public key in DER format
   openssl rsa -in key.pem -pubout -outform DER -out key.der

   # public key as a single base64 line, for the manifest
   base64 -w0 key.der

   # the extension ID derived from that public key
   openssl dgst -sha256 -binary key.der | head -c 16 | od -An -tx1 | tr -d ' \n' | tr '0-9a-f' 'a-p'
   ```
2. Add the base64 output to `Extension/manifest.json` as a `key` field:
   ```json
   {
     "manifest_version": 3,
     "name": "PwManager Autofill",
     "key": "<BASE64_PUBLIC_KEY>",
     ...
   }
   ```
3. Open `chrome://extensions`, enable **Developer mode** and click **Load unpacked**, selecting the `Extension/` folder. Confirm that the ID shown by Chrome matches the one computed in step 1.
4. Edit `com.pwmanager.autofill.json`:
   - `path`: **absolute** path to `pwmanager_native_host.sh`
   - `allowed_origins`: `chrome-extension://<EXTENSION_ID>/`
5. Edit `pwmanager_native_host.sh` and replace `/path/to/PwManager` with the folder that contains the `pwmanager` binary and `vault.db`. Then make it executable:
   ```bash
   chmod +x pwmanager_native_host.sh
   ```
6. Register the native host:
   ```bash
   mkdir -p ~/.config/google-chrome/NativeMessagingHosts
   cp com.pwmanager.autofill.json ~/.config/google-chrome/NativeMessagingHosts/
   ```
   For Chromium, use `~/.config/chromium/NativeMessagingHosts/`.
7. Open the extension's **options** page and paste the token generated by `init`.
8. On a login page (HTTPS), open the popup, enter the master password and click **Fill Credentials**.

> The master password is typed in the popup only to unlock the session. The session is locked automatically after **10 minutes of inactivity**.


### Why a fixed extension ID?

Chrome only lets the native host be launched by the extensions listed in `allowed_origins`, and that list uses the extension ID. For an unpacked extension, Chrome derives the ID from the folder path unless the manifest has a `key` field. Without it, moving or re-cloning the project changes the ID and the native host silently stops accepting the extension.

The `key` field holds the **public** key, and the ID is a hash of it, so the ID stays the same on any machine. Only `key.pem` (the private key) is sensitive: it is excluded by `.gitignore` and must never be committed. The `key` value in `manifest.json` and the resulting ID are public and safe to share.

### Troubleshooting: extension disappears after restarting the browser

On some setups, an extension loaded with **Load unpacked** is removed when the browser restarts. If that happens, pack it instead:

1. Open `chrome://extensions` and enable **Developer mode**.
2. Click **Pack extension**, set the extension root directory to `Extension/` and select your existing `key.pem` as the private key file.
3. Install the generated `.crx` (for example, by dragging it onto `chrome://extensions`).

The `.crx` is created next to the `Extension/` folder (the repository root), where `.gitignore` already excludes it. Reusing the same `key.pem` keeps the extension ID unchanged, so `allowed_origins` in `com.pwmanager.autofill.json` remains valid. Installing a `.crx` from outside the Chrome Web Store may be restricted on some operating systems and Chrome versions.

---

## Security decisions

### Layers of protection

- **Argon2 key derivation (`SENSITIVE`)**: the master password is the only source of the encryption key.
- **Two-layer authentication for the extension**: Chrome's `allowed_origins` restricts who can call the native host, and the **pairing token** (compared in constant time with `sodium_memcmp` and stored only as a hash) acts as defense in depth in case the origin is misconfigured.
- **Autofill on HTTPS only** (plus `localhost` for development).
- **Frame origin validation**: autofill runs with `allFrames: true`, but only types into iframes with the **same origin** as the active tab, preventing leaks into third-party iframes (ads, chat widgets, embedded checkouts).
- **Memory hygiene**: passwords, keys, tokens and intermediate buffers are wiped with `sodium_memzero` as soon as they are no longer needed. The popup's password field is cleared even when an error occurs.
- **Inactivity lock**: `chrome.alarms` checks the last activity time, kept in `storage.session`, which is not persisted to disk between browser sessions.
- **Input limits**: Native Messaging messages are capped at 1 MB and field sizes are checked.

### Deliberate decision: no second factor to open the vault

PwManager does **not** implement a second authentication factor (for example a local secret key, key file or hardware token) that would keep the vault closed even if the master password is discovered.

This was a design choice based on the threat model:

- Services like 1Password keep the vault on **servers**, where a data breach is a real risk, and a locally generated second secret (the *Secret Key*) protects the vault even against an attacker who obtains the stored data.
- Here, the vault is a file **the user stores wherever they prefer**. There is no centralized, high-value database to be attacked at scale.
- Protection therefore relies on a **strong master password** combined with a deliberately expensive KDF (Argon2 `SENSITIVE`).

**Consequence to keep in mind:** anyone who obtains `vault.db` **and** the master password can open the vault. The file's security depends on where the user keeps it (disk encryption, OS permissions, protected backups) and on the quality of the chosen password. Adding an extra factor remains a possible future improvement.

---

## Known limitations

- **Linux** only (depends on `xclip` and `termios`).
- Maximum of **1024 credentials** per vault.
- The clipboard is **not cleared automatically** after copying a password.
- The native host handles fields of up to 255 characters per credential, and the JSON parser is minimal: it rejects `\uXXXX` escapes above `0x7F` (raw UTF-8 is accepted).
- Domain matching uses **exact host equality** (`login.example.com` does not match `example.com`) and ignores the port.
- If several accounts exist for the same site, the extension silently fills the **first one saved**. It does not tell the user that others exist or let them choose.
- The pairing token is stored in the browser's `chrome.storage.local`.
- There is no rate limiting of master password attempts beyond the cost of Argon2.
- Portfolio/learning project: **it has not gone through an independent security audit**.

---

## Roadmap (v2)

- **Password age reminders**: notify the user when a credential has gone unchanged for too long. Old passwords are the ones most likely to appear in a past data breach, so prompting a rotation shortens the window an attacker has to use leaked credentials. This requires storing a creation/last-changed timestamp inside each encrypted record.
- Automatic clipboard clearing after a short timeout
- Optional local second factor (key file or secret key)
- Weak and duplicate password detection for entries added manually
- macOS (`pbcopy`) and Wayland (`wl-copy`) support
- Credential import and export
- **Account picker**: when a site has multiple accounts, show the user a list in the popup and fill the one they select
- Subdomain matching
- Automated tests and fuzzing of the message parser
- Firefox support

---

## Tech stack

C · libsodium · SQLite · JavaScript (Chrome Extension MV3) · Native Messaging · Bash
