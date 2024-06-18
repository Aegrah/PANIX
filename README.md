```[tasklist]
### Persistence methods
- [x] Cron/at (create new or modify existing one)
- [x] Systemd service/timer (create new or modify existing one)
- [x] SUID to GTFObin
- [x] Create non-root uid 0 user
- [x] Create new user
- [x] Add ssh key
- [ ] Shared object hooking
- [x] Add process capabilities to a binary
- [x] shell configurations (/etc/bash.bashrc, /etc/bash_logout, ~/.bashrc, ~/.bash_profile, ~/.bash_login,
~/.profile, ~.bash_logout, ~/.bash_logout, /etc/profile, /etc/profile.d (create new or modify existing one)
- [ ] web shell --> ask user input? Or php/asp(x) etc.?
- [x] Message of the day (create new or modify existing one)
- [x] rc.local/rc.common and rc.* (create new or modify existing one)
- [ ] udev (create new or modify existing one) https://ch4ik0.github.io/en/posts/leveraging-Linux-udev-for-persistence/
- [x] APT
- [ ] Dynamic Linker Hijacking, add to ld.so.preload (LD_PRELOAD)
- [x] Change existing user credentials
- [x] init.d (create new or modify existing one)
- [ ] LKM
- [x] /etc/passwd file write
- [ ] sudo hijacking
- [ ] ICMP backdoor https://github.com/droberson/icmp-backdoor
- [ ] Backdoored version of ls/cat/other system binary
- [ ] git backdooring https://hadess.io/the-art-of-linux-persistence/
- [ ] PAM module https://attack.mitre.org/techniques/T1556/003/, https://rosesecurityresearch.com/crafting-malicious-pluggable-authentication-modules-for-persistence-privilege-escalation-and-lateral-movement
- [x] XDG autostart
- [ ] Maybe's:
  - [ ] symlinks somehow
  - [ ] chroot environments
  - [ ] rogue container
  - [x] sudoers file modification
  - [ ] port knocking
  - [ ] malicious dpkg package?
  - [ ] Trap signal https://attack.mitre.org/techniques/T1546/005/
  - [ ] init/kernel level; ls24
- [ ] Make it executable in memory
```
