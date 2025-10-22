# Wifi Hacks
hacks  for your school wifi, all here!

> [!WARNING]
> I'm not responsible for any trouble this gets you into. Do this at your own risk.

# 💻 First Method: Crosh >_

Open the Crosh shell: Press Control + Alt + T on your Chromebook keyboard. Crosh is described as similar to a Command Prompt (CMD) for Chromebooks.

View running processes: Type top to see the processes running on the network.

In a school setting, this should display other connected computers.

Access advanced help options: Open a new tab and type help_advanced. This will display a list of advanced commands related to the Wi-Fi connection.
Last, disconnect the network: Typing either disconnect_ethernet or disconnect_lan will shut down the Wi-Fi network.

# Other exploits

CVE-2022-2587 (Remote Memory Corruption): Microsoft uncovered a ChromeOS component memory corruption vulnerability exploitable through crafted audio or Bluetooth streams, enabling remote code execution (RCE) .


CVE-2024-7965 / CVE-2024-7971: Critical Chrome V8 vulnerabilities in ChromeOS ≤ v128 enabling heap corruption and type confusion leading to remote code execution and network bypass attacks .


CVE-2023-126: Arbitrary code execution vulnerability in ChromeOS components affecting network operations and device enrollment controls .


# Exploits for Bypassing Network Restrictions 🛜

Rigtools: Extension exploit allowing network manipulation and disabling security extensions such as GoGuardian or Securly; patched as of ChromeOS 129 .​

BadRecovery / BR1CK: Unenrollment exploits that also reset network configurations to escape managed network restrictions .​

Securly Kill: Uses uBlock Origin and JavaScript injection to disable Securly’s network filter extension .​

Chromium Issue #40089045: Abuse of Crosh, the ChromeOS crash reporter, and built-in extensions (e.g., PDF, image loader) to spin up unauthorized processes, escalating privileges .​

# Historical System Exploits 🕓

Command Execution Chain: Exploits in ChromeOS subsystems like cups, shill (network manager), and upstart leading to root command execution .​

Wifi Credential Extraction: Techniques using exported logs from chrome://net-export to decode managed Chromebook Wi-Fi passwords .

A well-documented and patched ChromeOS exploit example is the **Chromebook Pico Ducky “Breakout” exploit**, which demonstrated how ChromeOS could be manipulated to escape restricted environments through physical input device injection . Here are the general steps of this now-mitigated exploit for educational and research context:[1]

# EXTRA EXPLOIT

### Overview
The exploit took advantage of a vulnerability in the **Crosh terminal** command handling system. It used a **USB-based Human Interface Device (HID)** (commonly a Raspberry Pi Pico configured as a “Rubber Ducky”) to simulate rapid keyboard input sequences that unlocked developer commands in otherwise restricted environments .[1]

### Stages of the Exploit

1. **Preparation**  
   The attacker configured a USB microcontroller (e.g., Pico or BadUSB) to emulate a keyboard and programmed it with a payload consisting of Crosh commands .[1]

2. **Triggering Crosh**  
   When the device was plugged into the Chromebook, it automatically invoked **Crosh** (using the keyboard shortcut Ctrl + Alt + T) and typed sequences to open hidden developer options .[1]

3. **Command Injection**  
   The HID script quickly executed debug or networking commands (like `shell`, `shill`, or `set_cellular_ppp`) that were normally restricted. Older ChromeOS builds did not properly verify privilege contexts, allowing partial shell access .[1]

4. **Privilege Escalation Attempt**  
   By exploiting flawed input validation in the Crosh parser, the attacker could manipulate command responses that granted access to deeper system layers—essentially bypassing some managed restrictions .[1]

5. **Payload Execution / Persistence (Post‑Exploit)**  
   Once Crosh accepted these commands, arbitrary diagnostics were run, and additional command sequences established limited file system access, enabling “escape” from kiosk‑mode or managed session restrictions.  

### Aftermath
Google patched this method in later ChromeOS releases by:
- Implementing stricter HID event sanitation;  
- Requiring authentication checks for Crosh commands;  
- Completely isolating user‑accessible terminals from privileged subsystems .[2]

This exploit no longer functions on up‑to‑date systems but remains a notable example of how **hardware‑assisted command injection** can reveal design weaknesses in Crosh’s sandboxxing.

# Links 🔗 : 

[1](https://av.tib.eu/media/62215)
[2](https://www.hkcert.org/security-bulletin/chromeos-multiple-vulnerabilities_20250820)
[3](https://cb.whale.x10.mx/docs/exploits/v101/)
[4](https://www.youtube.com/watch?v=OX-mLW47H3E)
[5](https://www.alphr.com/crosh-commands/)
[6](https://www.reddit.com/r/k12sysadmin/comments/10ecqqv/sh1mmerme_chromebook_unenrollment_tool/)
[7](https://www.microsoft.com/en-us/security/blog/2022/08/19/uncovering-a-chromeos-remote-memory-corruption-vulnerability/)
[8](https://www.crowdstrike.com/en-us/blog/crowdstrike-falcon-blocks-git-vulnerability-cve-2025-48384/)
[9](https://www.androidauthority.com/crosh-commands-3395990/)
[10](https://www.chromium.org/chromium-os/developer-library/guides/bugs/security-severity-guidelines/)
[11](https://socprime.com/blog/cve-2025-10585-zero-day-vulnerability/)
[12](https://news.ycombinator.com/item?id=15712270)
[13](https://its.ny.gov/2023-126)
[14](https://issues.chromium.org/40052058)
[15](https://chromium.googlesource.com/chromiumos/docs/+/master/security_severity_guidelines.md)
[16](https://www.mishcon.com/news/lessons-from-google-chromes-fourth-zero-day-exploit-of-2025)
[17](https://github.com/catfoolyou/Block-Bypass)
[18](https://issuetracker.google.com/40054458)
[19](https://www.youtube.com/watch?v=P9AD_ZrI19o&vl=bn)
[20](https://github.com/3kh0/ext-remover)
