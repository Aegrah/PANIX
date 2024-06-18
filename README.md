```[tasklist]
### Persistence methods
- [x] Cron/at (create new or modify existing one)
- [x] Systemd service/timer (create new or modify existing one)
- [x] SUID to GTFObin
- [x] Create non-root uid 0 user
- [x] Create new user
- [x] Add ssh key
- [x] Add process capabilities to a binary
- [x] shell configurations (/etc/bash.bashrc, /etc/bash_logout, ~/.bashrc, ~/.bash_profile, ~/.bash_login,
~/.profile, ~.bash_logout, ~/.bash_logout, /etc/profile, /etc/profile.d (create new or modify existing one)
- [x] Message of the day (create new or modify existing one)
- [x] rc.local/rc.common and rc.* (create new or modify existing one)
- [x] APT
- [x] Change existing user credentials
- [x] init.d (create new or modify existing one)
- [x] XDG autostart
- [x] /etc/passwd file write
- [x] sudoers file modification
- [x] Backdoored version of ls/cat/other system binary
- [ ] sudo hijacking
- [ ] Shared object hooking
- [ ] web shell --> ask user input? Or php/asp(x) etc.?
- [ ] udev (create new or modify existing one) https://ch4ik0.github.io/en/posts/leveraging-Linux-udev-for-persistence/
- [ ] Dynamic Linker Hijacking, add to ld.so.preload (LD_PRELOAD)
- [ ] LKM
- [ ] ICMP backdoor https://github.com/droberson/icmp-backdoor
- [ ] git backdooring https://hadess.io/the-art-of-linux-persistence/
- [ ] PAM module https://attack.mitre.org/techniques/T1556/003/, https://rosesecurityresearch.com/crafting-malicious-pluggable-authentication-modules-for-persistence-privilege-escalation-and-lateral-movement

- [ ] Maybe's:
  - [ ] symlinks somehow
  - [ ] chroot environments
  - [ ] rogue container
  - [ ] port knocking
  - [ ] malicious dpkg package?
  - [ ] Trap signal https://attack.mitre.org/techniques/T1546/005/
  - [ ] init/kernel level; ls24
- [ ] Make it executable in memory
```
