# KeySafe
KeySafe is a free, open-source, fully offline Windows password manager with strong encryption, secure backups, and recovery keys.

KeySafe keeps your vault on your computer, without requiring an account or cloud service. It has a clean dark interface and is designed around authenticated encryption, recovery keys, and local backups.

## Features

- Encrypts vault contents using XChaCha20-Poly1305 and a random 256-bit vault key.
- Uses Argon2id to derive a key from your master password.
- Generates 10 emergency recovery keys for recovering access to your vault.
- Stores usernames, email addresses, passwords, websites, and secure notes.
- Organizes passwords with categories, favorites, and search.
- Generates strong, random passwords.
- Supports TOTP authentication codes, encrypted attachments, and password history.
- Creates and restores encrypted local backups.
- Supports CSV import and export, with warnings before unencrypted exports.
- Automatically locks your vault and includes optional secure clipboard controls.
- Runs locally on Windows without a KeySafe account or cloud synchronization.

## Installation

**Requirements:**
- Windows 10 or 11, 64-bit.
- .NET 10 SDK **only if building from source**.

### Download the release

1. Open the repository's **Releases** page.
2. Download the Windows x64 release ZIP.
3. Extract the **entire** ZIP to a folder.
4. Run `KeySafe.exe` from the extracted folder.

Keep the included `.dll` and other runtime files beside the executable. The Windows release is a self-contained application folder, not a standalone single-file EXE.

### Build from source

Clone or download this repository, then run:

```bat
BUILD-WINDOWS.bat
```

The batch file automatically restores dependencies, runs the available automated tests, builds the Windows x64 Release application, and performs a GUI startup check. No menu selection is required.

After a successful build, run:

```text
dist\KeySafe\KeySafe.exe
```

## Usage

Open KeySafe and create a new vault with a strong, unique master password.

Save the **10 recovery keys** displayed during setup in a separate, secure location. Losing both your master password and all valid recovery keys can permanently prevent access to your vault.

Once unlocked, you can add passwords or secure notes, generate passwords, view TOTP codes, manage categories, and create encrypted backups.

### Vault location

KeySafe v1.1.0 stores its vault data at:

```text
%LOCALAPPDATA%\KeySafe\v1.1.0\
```

The main vault file is `vault.ksv`. Do not edit or rename vault/database files while KeySafe is running.

### Security diagnostics

Run:

```bat
SECURITY-TEST-WINDOWS.bat
```

You can run the diagnostics with KeySafe open and again with KeySafe closed. The script saves timestamped text reports in `security-reports\` and performs automated tests using synthetic data rather than your live vault contents.

## Important Notes

- KeySafe is local and offline by design. It does not provide cloud synchronization or a remote account-recovery service.
- The public application includes **no migration or conversion** features for older KeySafe versions. Each version uses an isolated vault folder.
- Keep encrypted backups in a separate, secure location and periodically verify that you can restore them.
- **CSV exports are unencrypted.** Anyone with access to the exported file may be able to read your passwords. Protect or securely remove these exports after use.
- Recovery keys are intended for one-time use in the current vault state. Restoring an older vault snapshot may revive older recovery-key state.
- Encryption at rest does not protect against malware, malicious administrators, or software that can inspect your unlocked computer.
- An unsigned or unfamiliar Windows executable may trigger a SmartScreen warning. Download releases only from the official repository and verify published SHA-256 checksums when available.

## License

KeySafe is released under the MIT License. See the [LICENSE](LICENSE) file for details.

Third-party components retain their own licenses. Include the applicable third-party notices when distributing compiled releases.

## Support

If you find KeySafe useful and would like to support its development, donations are appreciated.

**Bitcoin (BTC):**

```text
bc1qzwsla74pcwrly9yc42n7x7320w2cx5w6y2ua9e
```
