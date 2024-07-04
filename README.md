<p align="center">
  <img src="https://github.com/Aegrah/ALPHA/assets/78494512/d85bd368-c392-469e-b668-8ee20247ec4c" height="250">
  <h2 align="center"><a href="https://github.com/Aegrah/ALPHA/">ALPHA</a></h2>
  <p align="center">Aegrah's Linux Persistence Honed Assistant</p>
  <p align="center">
    <a href="https://twitter.com/RFGroenewoud">
      <img src="https://img.shields.io/badge/%E2%9C%A8-Twitter%20-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="Twitter" />
    </a>
    <a href="https://www.linkedin.com/in/ruben-groenewoud/">
      <img src="https://img.shields.io/badge/%E2%9C%A8-LinkedIn-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="LinkedIn" />
    </a>
    <a href="https://www.rgrosec.com/">
      <img src="https://img.shields.io/badge/%E2%9C%A8-Blog-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="Blog" />
    </a>
    <a href="https://github.com/Aegrah">
      <img src="https://img.shields.io/badge/%E2%9C%A8-GitHub-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="GitHub" />
    </a>
  </p>
</p>

![](https://i.imgur.com/waxVImv.png)

ALPHA is a Linux persistence tool designed for security research, detection engineering, penetration testing and CTFs. Unlike some tools, ALPHA is not built for stealth but rather to be used openly in a purple team fashion.

It is compatible with popular distributions based on Debian and Fedora, such as Ubuntu, Debian, CentOS, and Red Hat. Compatibility with Arch Linux may vary depending on the persistence mechanism used. Customizability is built into most mechanisms, allowing users to adjust settings to suit their specific OS environment.

## Main Features

| Feature                          | Description                                     |
|----------------------------------|-------------------------------------------------|
| **At Job Persistence**           | Establish persistence through `at` jobs.        |
| **Authorized Keys Management**   | Establish persistence through malicious `authorized_keys` entry. |
| **Backdoor User**                | Establish persistence through creation of a backdoor user with UID 0. |
| **Bind Shell**                   | Establish persistence through a bind shell.     |
| **Capabilities Backdoor**        | Establish persistence through Linux capabilities. |
| **Cron Job Persistence**         | Establish persistence through cron jobs.        |
| **Create User**                  | Create a new user for persistence.              |
| **Git Persistence**              | Establish persistence through Git hooks or pagers. |
| **Generator Persistence**        | Establish persistence through system generator. |
| **Init.d Backdoor**              | Establish persistence through `init.d` with custom settings. |
| **Malicious Docker Container**   | Set up a malicious Docker container for persistence. |
| **MOTD Backdoor**                | Establish persistence through MOTD with custom settings. |
| **Package Manager Persistence**  | Establish persistence through package managers like APT, YUM, or DNF. |
| **Password Management**          | Manage user passwords or add users for persistence. |
| **Rc.local Backdoor**            | Establish persistence through `rc.local` with custom settings. |
| **Shell Profile Persistence**    | Persist changes in shell profiles.              |
| **SSH Key Persistence**          | Persist SSH keys for persistence.               |
| **Sudoers Backdoor**             | Establish persistence through sudoers.          |
| **SUID Backdoor**                | Establish persistence through SUID binaries.    |
| **System Binary Backdoor**       | Establish persistence through a system binary.  |
| **Systemd Service Persistence**  | Establish persistence through systemd services. |
| **Udev Persistence**             | Establish persistence through Udev with custom settings. |
| **XDG Autostart Persistence**    | Establish persistence through XDG autostart entries. |



### [Setup](link-to-setup-section) &nbsp;&middot;&nbsp; [Applications](link-to-) &nbsp;&middot;&nbsp; [Instructions](link-to-instructions)

![](https://i.imgur.com/waxVImv.png)

List of publications in which this tool is used in a purple teaming fashion:

- [Linux Detection Engineering - The Basics of Linux Persistence](link)
- [Linux Detection Engineering - Beyond the Basics of Linux Persistence](link)

![](https://i.imgur.com/waxVImv.png)

### Setup
Write me a boilerplate template here for setup of a tool

### Examples
Write me a boilerplate template here for some examples on how to establish persistence with ALPHA

## Share 

Share [ALPHA](https://github.com/Aegrah/ALPHA) ...

[![GitHub Repo stars](https://img.shields.io/badge/share%20on-reddit-red?logo=reddit)](https://reddit.com/submit?url=[https://github.com/Aegrah/ALPHA](https://github.com/Aegrah/ALPHA)&title=Aegrah's%20Linux%20Persistence%20Honed%20Assistant%20\(ALPHA\))
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-hacker%20news-orange?logo=ycombinator)](https://news.ycombinator.com/submitlink?u=https://github.com/Aegrah/ALPHA)
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-twitter-03A9F4?logo=twitter)](https://twitter.com/share?url=https://github.com/Aegrah/ALPHA&text=Aegrah's%20Linux%20Persistence%20Honed%20Assistant%20\(ALPHA\))
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-facebook-1976D2?logo=facebook)](https://www.facebook.com/sharer/sharer.php?u=https://github.com/Aegrah/ALPHA)
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-linkedin-3949AB?logo=linkedin)](https://www.linkedin.com/shareArticle?url=https://github.com/Aegrah/ALPHA&title=Aegrah's%20Linux%20Persistence%20Honed%20Assistant%20(ALPHA))


## Disclaimer
ALPHA is intended for authorized security testing and research purposes only. Misuse of this tool for malicious activities is not condoned and is entirely at the user's own risk. By using ALPHA, you agree that you are responsible for your own actions.

## References
For more information and advanced usage, refer to the following:
- [ALPHA - Go-to tool for Linux Persistence](link)

## To Do's for now.

```[tasklist]
### Persistence methods
- [ ] malicious dpkg/rpm packages
- [ ] sudo hijacking
- [ ] web shell --> ask user input? Or php/asp(x) etc.?
- [ ] Dynamic Linker Hijacking, add to ld.so.preload (LD_PRELOAD)
- [ ] LKM
- [ ] ICMP backdoor https://github.com/droberson/icmp-backdoor
- [ ] PAM module https://attack.mitre.org/techniques/T1556/003/, https://rosesecurityresearch.com/crafting-malicious-pluggable-authentication-modules-for-persistence-privilege-escalation-and-lateral-movement
- [ ] Shared object hooking
```
