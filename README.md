```[tasklist]
### Persistence methods
- [ ] Cron/at (create new or modify existing one)
  - [ ] Crontab carriage return defense evasion technique
- [ ] Systemd service/timer (create new or modify existing one)
- [ ] SUID to GTFObin
- [ ] Create non-root uid 0 user
- [ ] Create new user
- [ ] Add ssh key
- [ ] Shared object hooking
- [ ] Add process capabilities to a binary
- [ ] shell configurations (/etc/bash.bashrc, /etc/bash_logout, ~/.bashrc, ~/.bash_profile, ~/.bash_login,
~/.profile, ~.bash_logout, ~/.bash_logout, /etc/profile, /etc/profile.d (create new or modify existing one)
- [ ] web shell --> ask user input? Or php/asp(x) etc.?
- [ ] Message of the day (create new or modify existing one)
- [ ] rc.local/rc.common and rc.* (create new or modify existing one)
- [ ] udev (create new or modify existing one) https://ch4ik0.github.io/en/posts/leveraging-Linux-udev-for-persistence/
- [ ] APT
- [ ] Dynamic Linker Hijacking, add to ld.so.preload (LD_PRELOAD)
- [ ] Change existing user credentials
- [ ] init.d (create new or modify existing one)
- [ ] LKM
- [ ] /etc/passwd file write
- [ ] sudo hijacking
- [ ] ICMP backdoor https://github.com/droberson/icmp-backdoor
- [ ] Backdoored version of ls/cat/other system binary
- [ ] git backdooring https://hadess.io/the-art-of-linux-persistence/
- [ ] PAM module https://attack.mitre.org/techniques/T1556/003/, https://rosesecurityresearch.com/crafting-malicious-pluggable-authentication-modules-for-persistence-privilege-escalation-and-lateral-movement
- [ ] XDG autostart
- [ ] Maybe's:
  - [ ] symlinks somehow
  - [ ] chroot environments
  - [ ] rogue container
  - [ ] sudoers file modification
  - [ ] port knocking
  - [ ] malicious dpkg package?
  - [ ] Trap signal https://attack.mitre.org/techniques/T1546/005/
- [ ] Make it executable in memory
```
