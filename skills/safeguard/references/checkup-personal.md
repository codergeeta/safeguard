# Mode 2 — Security checkup (everyday users)

Walk the user through these in order, highest impact first. Ask what they already have, skip what is done, and give exact menu paths for the services they use. Do not ask them to tell you any password, code, or recovery phrase. Do the steps with them, one section at a time.

## 1. Email — the master key (15 min)
Whoever controls the email can reset everything else.
- Turn on a **passkey** or **security key** for the main email account (Google: Security → Passkeys; Microsoft: Account → Security → Advanced security options). If not possible, use an authenticator app, not SMS.
- Check **recovery phone and recovery email** are yours and current.
- Check **forwarding rules and filters** for anything that forwards or deletes mail (a favourite of attackers after takeover). Gmail: Settings → Forwarding and Filters. Outlook: Settings → Mail → Rules / Forwarding.
- **Review signed-in devices** and sign out of anything unknown.
- **Review connected apps / third-party access** and remove anything not recognised or not used.

## 2. Passwords (30 min, once)
- Use a **password manager** (built into Apple/Google/Microsoft, or a dedicated one). Unique password per site.
- Check for reused or breached passwords (Google Password Checkup, Apple Passwords → Security Recommendations, or the manager's own report).
- Change first: email, bank, phone carrier account, Apple/Google/Microsoft ID, social media, shopping sites with saved cards.
- **Do not save passwords in the browser on a shared or work PC.**

## 3. MFA everywhere it matters
- Order: email → bank → mobile carrier → Apple/Google/Microsoft → social → shopping.
- Prefer passkeys > security key > authenticator app > SMS.
- **Rule to memorise**: never approve a prompt, read out a code, or enter a code at a page you did not start yourself. Real companies never ask for your code.
- Add a **carrier PIN / port-out lock** with your mobile carrier to stop SIM swaps.

## 4. Devices
- Turn on **automatic updates** for the OS, browser, and phone apps. Restart when asked.
- Keep built-in protection on (Windows Security / Defender, macOS XProtect, Google Play Protect).
- **Browser extensions**: remove any you do not actively use; extensions can read every page and steal sessions.
- Install software only from the official site or app store. No cracked software, game cheats, "free" premium apps, or installers from search ads — the top infostealer sources.
- **Screen lock** and device encryption on (BitLocker/Device Encryption, FileVault, phone passcode).
- Separate user account for children, without admin rights.

## 5. Money
- Turn on **transaction alerts** for every card and bank account.
- Set a **daily limit** for transfers / UPI where the bank allows.
- **Credit freeze** with credit bureaus (free in the US at Equifax, Experian, TransUnion; check your country's equivalent).
- Never move money to a "safe account" — banks never ask this.

## 6. Home network
- Change the router's **admin password** from the default.
- Update the router **firmware**; if the router no longer gets updates (end of life), replace it.
- Turn off **remote administration** and **UPnP** unless needed; use WPA3 or WPA2-AES Wi-Fi.
- Use a separate guest network for smart-home gadgets and visitors.

## 7. Backups (protects against ransomware and loss)
- 3-2-1: three copies, two kinds of storage, one off-site/cloud.
- At least one backup that is **not always connected** (or cloud with version history).
- Test a restore once.

## 8. Family plan
- Agree a **family code word** for emergency calls (defeats deepfake voice scams).
- Tell older relatives: banks, police, tax offices, and tech support never ask for gift cards, crypto, codes, remote access, or secrecy.
- Put trusted contacts / legacy contacts on Apple/Google accounts.

## Wrap-up
Summarise what is done, what is left, and one habit to keep. Offer a reminder to repeat the checkup every 6 months.
