# DieAuth

```
▓█████▄  ██▓▓█████ ▄▄▄       █    ██ ▄▄▄█████▓ ██░ ██ 
▒██▀ ██▌▓██ ▓█   ▀▒████▄     ██  ▓██▒▓  ██▒ ▓▒▓██░ ██▒
░██   █▌▒██ ▒███  ▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██▀▀██░
░▓█▄   ▌░██ ▒▓█  ▄░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ░▓█ ░██ 
░▒████▓ ░██ ░▒████▒▓█   ▓██▒▒▒█████▓   ▒██▒ ░ ░▓█▒░██▓
 ▒▒▓  ▒ ░▓  ░░ ▒░ ░▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░    ▒ ░░▒░▒
 ░ ▒  ▒  ▒ ░ ░ ░  ░ ▒   ▒▒ ░░░▒░ ░ ░     ░     ▒ ░▒░ ░
 ░ ░  ░  ▒ ░   ░     ░   ▒    ░░░ ░ ░   ░       ░  ░░ ░
   ░     ░     ░         ░  ░   ░               ░  ░  ░
 ░
```

> **Wi‑Fi Deauthentication Research Utility**
> Built for education, defensive research, and **authorized** testing only. Or Don't.. Deal with it in jail.

---

## Overview

**DieAuth** is a Bash‑based Wi‑Fi deauthentication research tool built on the **aircrack‑ng** suite. It provides an interactive, terminal‑driven workflow to **observe, demonstrate, and study IEEE 802.11 deauthentication behavior** in controlled environments.

The project emphasizes **operator awareness**, **explicit authorization**, and **cleanup safety** (automatic interface restoration, signal handling) while exposing how deauthentication frames affect access points (APs) and associated stations.

---

## ⚠️ Legal & Ethical Notice

Deauthentication attacks intentionally disrupt wireless connectivity.

* Use this software **only** on networks you own or have **explicit written permission** to test.
* Unauthorized interference with computer networks is illegal in many jurisdictions.
* **You assume full responsibility** for how this tool is used.

The author does **not** condone misuse and accepts **no liability** for actions taken by users.

---

## What DieAuth Does

### Core Capabilities

* **Interactive interface selection**
  Enumerates wireless interfaces via `iw` and validates user choice.

* **Robust monitor‑mode handling**

  * Uses `airmon-ng check kill` to prevent interface reclamation.
  * Detects the correct monitor interface across multiple `airmon-ng` output formats.
  * Restores the interface cleanly on `INT`, `TERM`, and normal exit.

* **Live reconnaissance**

  * Runs `airodump-ng` with periodic CSV output.
  * Displays live counts of discovered APs and associated clients.

* **Target intelligence (best‑effort hints)**

  * OUI/vendor lookup (local Nmap prefixes with online fallback).
  * Device‑type heuristics derived from vendor names.
  * Optional hints inferred from probed ESSIDs (phones, TVs, consoles, etc.).

---

## Attack Modes

> The descriptions below are **conceptual**. Execution requires authorization.

### 1) Cluster Bomb

* Targets a selected access point (BSSID).
* Deauthenticates **all observed clients** on that network.
* Optionally excludes the operator’s own MAC address.
* Uses client‑directed frames with broadcast fallback.

### 2) Guided Missile

* Targets **one specific client** associated with an AP.
* Presents vendor and device hints to reduce accidental targeting.
* Automatically synchronizes the monitor interface to the AP’s channel.

---

## Safety & Stability Measures

* Signal traps ensure child processes terminate cleanly.
* NetworkManager and RF state are restored on exit.
* Channel synchronization prevents common `aireplay-ng` failures.

---

## Requirements

* Linux system with:

  * **aircrack‑ng suite** (`airmon-ng`, `airodump-ng`, `aireplay-ng`)
  * `iw`, `iproute2`, `rfkill`
  * Optional: Nmap MAC prefixes database
* Wireless adapter capable of **monitor mode** and **packet injection**
* **Root privileges**

---

## Intended Use

* Wireless security education
* Defensive research and demonstrations
* Authorized penetration testing

## Non‑Goals

* No support for illegal, malicious, or unauthorized activity
* Not intended as a turnkey attack framework

---

## Disclaimer

This software is provided **“AS IS”**, without warranty of any kind. The author **disclaims all liability** for damages, legal consequences, or misuse arising from this project.

---

## License

See the `LICENSE` file for full terms. Use of this software constitutes acceptance of those terms.
