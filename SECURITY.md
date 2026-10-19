# Security Policy

PwManager is a personal portfolio and learning project. It uses well-established primitives from [libsodium](https://doc.libsodium.org/), but **it has not gone through an independent security audit**. Please do not rely on it as the only protection for credentials you cannot afford to lose.

## Supported versions

Only the latest commit on the `main` branch is maintained. There are no versioned releases yet.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem, since that would expose it to everyone before it can be fixed.

Report it privately instead:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Describe the problem and, if possible, how to reproduce it.

A useful report includes:

- the affected component (CLI, native host, or browser extension) and the commit you tested
- your operating system and browser
- the steps to reproduce, and what you expected to happen
- the impact as you understand it

This is a one-person project, so replies are best effort. I will read every report, acknowledge it as soon as I can and credit you in the fix if you wish.

## Scope

In scope:

- the cryptography and vault handling (`main.c`, `backend.c`)
- the Native Messaging protocol, including message parsing and the auth token check
- the browser extension, including origin and URL validation before autofill
- anything that could leak a master password, a stored credential or a key (for example through logs, memory or the clipboard)

Out of scope:

- an attacker who already has both `vault.db` and the master password, or who controls the machine while the vault is unlocked
- weaknesses caused by a weak master password
- the limitations already listed under **Known limitations** in the [README](README.md), such as the clipboard not being cleared automatically
- vulnerabilities in third-party software (libsodium, SQLite, the browser)

## Design notes

The README explains the main design decisions, including why the vault has no second factor beyond the master password. If you think a decision is wrong, a reasoned report is welcome.
