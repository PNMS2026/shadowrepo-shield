# ShadowRepo Shield — Linux Installation Guide

This guide describes how to install and run **ShadowRepo Shield** on Linux distributions, including:
* Ubuntu
* Debian
* Kali Linux
* Linux Mint
* Pop!_OS

---

## Prerequisites
* **Operating System**: 64-bit Debian-based Linux distribution (glibc 2.31 or newer).
* **Dependencies**: WebKit2GTK is required for Tauri's webview. It is usually preinstalled on desktop environments (GNOME, MATE, Cinnamon), but can be installed manually if required.

To install dependencies on Debian/Ubuntu-based systems:
```bash
sudo apt-get update
sudo apt-get install -y libwebkit2gtk-4.1-0 libgtk-3-0 libayatana-appindicator3-1
```

---

## 1. Debian Package (`.deb`) — Recommended

The `.deb` package installs the application system-wide, creates desktop menu entries, and handles application icons automatically.

### Installation
1. Download `ShadowRepo-Shield-v1.4.0.deb` from the releases directory.
2. Open a terminal and navigate to the download folder.
3. Install using `dpkg`:
   ```bash
   sudo dpkg -i ShadowRepo-Shield-v1.4.0.deb
   ```
4. If there are any missing dependency errors, resolve them using `apt`:
   ```bash
   sudo apt-get install -f
   ```

### Running the App
* Search for **ShadowRepo Shield** in your desktop environment's application launcher.
* Or run it directly from the terminal:
   ```bash
   shadowrepo-shield
   ```

---

## 2. AppImage — Portable Format

AppImage is a single, self-contained executable package that runs on most Linux distributions without installation or root access.

### Running the App
1. Download `ShadowRepo-Shield-v1.4.0.AppImage` from the releases directory.
2. Open a terminal and navigate to the download folder.
3. Grant execute permission:
   ```bash
   chmod +x ShadowRepo-Shield-v1.4.0.AppImage
   ```
4. Run the file:
   ```bash
   ./ShadowRepo-Shield-v1.4.0.AppImage
   ```

> [!NOTE]
> Under newer distributions (such as Ubuntu 22.04+), you may need to install `libfuse2` to run AppImages:
> ```bash
> sudo apt-get install -y libfuse2
> ```

---

## 3. Portable Archive (`.tar.gz`)

The `.tar.gz` package is a simple, lightweight compressed archive containing the standalone `shadowrepo-shield` executable.

### Extraction & Setup
1. Download `ShadowRepo-Shield-v1.4.0.tar.gz` from the releases directory.
2. Extract the archive:
   ```bash
   tar -xzf ShadowRepo-Shield-v1.4.0.tar.gz
   ```
3. Navigate to the extracted folder:
   ```bash
   cd shadowrepo-shield-portable
   ```
4. Run the standalone binary:
   ```bash
   ./shadowrepo-shield
   ```

---

## Files and Directories on Linux
* **App Data Path**: Configurations and local database are saved in:
  `~/.local/share/shadowrepo-shield/shadowrepo_shield.db`
* **Reports Directory**: PDF, HTML, and JSON reports are saved by default in:
  `~/.local/share/shadowrepo-shield/reports/`
* **Log File**: Application operational logs are saved at:
  `~/.local/share/shadowrepo-shield/logs/app.log`
