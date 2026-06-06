# PS5 MacPork v1.0

A native macOS GUI for backporting PS5 game dumps to lower firmware versions.

---

## Requirements

- macOS (Apple Silicon or Intel)
- Your own fakelib files (sourced separately — see below)
- Your own BPS patch files (sourced separately — see below)

---

## Installation

1. Download and unzip `PS5 MacPork.zip`
2. Move `PS5 MacPork.app` to your Applications folder (or anywhere you like)
3. Double-click to launch

> **First launch note:** macOS may show a security warning since the app isn't from the App Store.
> To open it: right-click the app → Open → Open anyway.

---

## How to use

1. **Game Dump Folder** — select your PS5 game dump folder (starts with PPSA…)
2. **Primary Fakelib Folder** — select your 6.xx or 7.xx fakelib folder
3. **Fallback Fakelib Folder** — optional, point to your 4.xx fakelib folder for games needing libSceFiber etc.
4. **Patches Folder** — select the matching BPS patches folder (6.xx/7.xx only — leave empty for 4.xx)
5. **Target Firmware** — select FW 4.xx, 5.xx, 6.xx or 7.xx
6. Click **Start Backport**

A timestamped backup folder will be created alongside your game dump before anything is modified.
Folder selections are remembered between sessions.

---

## What the tool does

The tool runs a complete pipeline automatically:

1. **FSELF → ELF** — converts fake-signed ELF files to plain ELF format for patching
2. **Fakelib installation** — applies BPS patches to fakelib system libraries and installs them into the game dump
3. **SDK downgrade** — patches the SDK version in all ELF files to match the target firmware
4. **libc.prx patch** — applies BestPig's recommended libc compatibility patch
5. **Re-sign** — converts patched ELF files back to fake-signed SELF format so the PS5 can load them

After backporting, copy the game dump folder to your PS5 and launch via ShadowMount+.

---

## Game compatibility

MacPork works for the majority of PS5 games. Compatibility depends on the game's engine and firmware requirements:

- **FW 9.xx and below** — excellent compatibility ✅
- **FW 10.xx** — good compatibility ✅
- **FW 11.xx / 12.xx (Unreal Engine)** — good compatibility ✅
- **FW 11.xx / 12.xx (Unity Engine)** — limited, pending apr emu support in ShadowMount+ ⏳

Games that inject the backport but show a black screen may require the upcoming "apr emu" feature in ShadowMount+. Once available, MacPork's output should boot seamlessly without any changes.

---

## Sourcing fakelib and patch files

Fakelib files are system libraries extracted from official PS5 firmware.
They cannot be distributed with this tool for legal reasons.
You must source them yourself from the PS5 homebrew community.

BPS patch files are provided by BestPig's BackPork project:
https://github.com/BestPig/BackPork

Additional system fakelibs (libSceRazorCpu, libSceAjm etc.) can be extracted from your own jailbroken PS5 using john-tornblom's ftpsrv:
https://github.com/ps5-payload-dev/ftpsrv

---

## Notes & disclaimer

- Game dump files must be in FSELF format (as downloaded from community sources). The tool handles conversion automatically.
- Use at your own risk. Always keep a backup of your original game dump.
- This tool does not modify or distribute any Sony intellectual property.
- Results not guaranteed on all firmware versions or all games.

---

## Support development

PS5 MacPork is free and open source. If it helped you, consider buying me a coffee:

☕ https://ko-fi.com/macpork

---

## Credits

- **idlesauce** — SDK version patching logic
  https://gist.github.com/idlesauce/2ded24b7b5ff296f21792a8202542aaa

- **BestPig** — BackPork fakelib sideloading concept and BPS patches
  https://github.com/BestPig/BackPork

- **john-tornblom** — make_fself.py (ELF → fake-signed SELF re-signing)
  https://github.com/ps5-payload-dev/sdk

- **CyB1K / dmiller423** — SelfUtil (FSELF → ELF conversion logic)
  https://github.com/CyB1K/SelfUtil-Patched

- **BackPork Kitchen** — workflow inspiration
  https://github.com/rajeshca911/PS5-BACKPORK-KITCHEN

- **Created with AI assistance** — built with the help of Claude (Anthropic)
