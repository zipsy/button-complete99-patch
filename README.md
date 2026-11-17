# B.U.T.T.O.N. — achievement patch (`COMPLETE_99` → `COMPLETE_99%`)

**B.U.T.T.O.N.** is a .NET 4 / XNA 4 game. One of its Steam achievements never
unlocks at 99 % completion: the game executable asks Steam for the achievement
stat named `COMPLETE_99`, but the actual Steam achievement (and the game's own
stats definition) is spelled `COMPLETE_99%`. This tool binary-patches the game
exe so the string it sends matches, without touching the game logic.

Nothing is recompiled and no DLLs are injected — a single string-heap entry is
appended in the .NET metadata and the one `ldstr` instruction that loads it is
retargeted. The patch runs on any OS (the patcher is pure-Python) and the
patched exe runs on Windows exactly like the original.

## What the patch does

Inside the PE's .NET metadata, the user-string heap (`#US` stream) holds the
literal `"COMPLETE_99"` (UTF-16LE, token `0x7000A22C`). The method
`checkPercentageComplete()` calls `callSteamAchievement("COMPLETE_99")` via a
single `ldstr` at file offset `0x1B301`. The patcher:

1. appends a new heap entry `"COMPLETE_99%"` (token `0x7000AC9C`) at the end of
   `#US`, as a full 0x200-aligned block (28-byte entry + 484 bytes of padding),
   so `.rsrc` and `.reloc` keep their 0x200 file alignment;
2. retargets the one `ldstr` operand to the new token;
3. fixes up everything the Windows loader validates, which is why every offset
   must be touched in lockstep (a naive string swap corrupts the file and the
   CLR throws `BadImageFormatException`, exit code `0x80131700`):
   - `#US` stream size +`0x1C`, `#GUID`/`#Blob` stream offsets +`0x200`,
   - COR20 metadata size +`0x200` and NT Header `SizeOfImage` +`0x200`,
   - `.text` `SizeOfRawData`/`VirtualSize` +`0x200`, `.rsrc`→`0x39600`,
     `.reloc`→`0x3DC00`,
   - the legacy Framework-CLR trailer: two DataDirectory RVA entries, the
     `PIMAGE_INFO` word, and the IMAGE_SECURITY / import-stub records (the
     `_CorExeMain`/`mscore.dll` chain) all +`0x200`.

All invariants (alignment, contiguity, `metadata end ≤ SizeOfImage ≤ .text`
virtual range, clean `#US` heap walk, zero stale token refs) are asserted
before the output file is written, and the result's MD5 is compared against the
known-good patched build.

## Reference files

| | MD5 | size |
|---|---|---|
| original `B.U.T.T.O.N.exe` | `613a292a7ecb478abcd6556a92b7ac64` | 252,928 |
| patched `B.U.T.T.O.N.exe` | `3aa028ce0b8d84a4be0c3a0c5c616dce` | 253,440 |

## Usage

```
python3 patch_complete99.py B.U.T.T.O.N.exe
```

```
ldstr retargeted at file 0x1B301
OK B.U.T.T.O.N-patched.exe md5 3aa028ce0b8d84a4be0c3a0c5c616dce (expected 3aa028ce0b8d84a4be0c3a0c5c616dce)
```

- The input file is **never modified**; the result is written next to it as
  `<name>-patched.exe` (`B.U.T.T.O.N.exe` → `B.U.T.T.O.N-patched.exe`).
- The patcher refuses any input whose MD5 isn't the original above (and tells
  you if you accidentally hand it the already-patched exe).
- Drop the produced `B.U.T.T.O.N-patched.exe` into the game folder, replacing
  the original.

## Requirements

Python 3, standard library only — no third-party packages
(`requirements.txt` is intentionally empty).

## Files

- `patch_complete99.py` — the patcher + built-in verification (the whole tool).

## How the fix is confirmed in-game

Launch the patched exe and play to ≥ 99 % in a round: the Steam achievement
`COMPLETE_99%` unlocks. Pre-patch, the game silently sent the wrong stat name
and it never could.

---

*Why the hex offsets look scary: this is a hand-relocated .NET 4 executable
(older 0x200-aligned layout). The patcher keeps a full invariant checklist —
any drift in one field without the matching drift in its dependents is caught
before a file is ever written.*
