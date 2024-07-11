<p align="center">
  <img src="https://github.com/Aegrah/ALPHA/assets/78494512/2b21f530-9763-4c10-af8c-9ca97443f351" alt="ALPHA logo" width="1010" height="500"> 
  <h2 align="center"><a href="https://github.com/Aegrah/ALPHA/">ALPHA</a></h2>
</p>

![](https://i.imgur.com/waxVImv.png)

ALPHA is a Linux persistence tool designed for security research, detection engineering, penetration testing, and CTFs. Unlike some tools, ALPHA is not built for stealth; its features are easily detectable unless the target's security posture is lacking.

ALPHA is compatible with popular Debian and Red hat-based distributions, including Ubuntu, Debian and CentOS. Compatibility with Arch Linux may vary depending on the persistence mechanism used. Most mechanisms are customizable, allowing users to adjust settings to suit their specific OS environment.

![](https://i.imgur.com/waxVImv.png)

## Features
ALPHA provides a versatile suite of tools for simulating and researching Linux persistence mechanisms. The table below displays the main features.

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

![](https://i.imgur.com/waxVImv.png)

### Support
ALPHA offers comprehensive support/compatibility for each of the features across various Linux distributions and environments.

| Distribution | Suppport |
|--------------|----------|
|Debian X.X|Supported|
|Ubuntu X.X|Supported|
|RHEL X.X|Supported|
|CENTOS X.X|Supported|

If any `default` command fails, the `--custom` flag is available in most features, which will allow you to customize the path/command to be executed, and tailor the persistence mechanism to your environment. 

Any PR or issue adding a new feature or idea is welcome!

![](https://i.imgur.com/waxVImv.png)

### Setup
Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.
```
alpha@alpha-demo:~$ sudo ./alpha.sh

 ▄▄▄       ██▓     ██▓███   ██░ ██  ▄▄▄
▒████▄    ▓██▒    ▓██░  ██▒▓██░ ██▒▒████▄
▒██  ▀█▄  ▒██░    ▓██░ ██▓▒▒██▀▀██░▒██  ▀█▄
░██▄▄▄▄██ ▒██░    ▒██▄█▓▒ ▒░▓█ ░██ ░██▄▄▄▄██
 ▓█   ▓██▒░██████▒▒██▒ ░  ░░▓█▒░██▓ ▓█   ▓██▒
 ▒▒   ▓▒█░░ ▒░▓  ░▒▓▒░ ░  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░
  ▒   ▒▒ ░░ ░ ▒  ░░▒ ░      ▒ ░▒░ ░  ▒   ▒▒ ░
  ░   ▒     ░ ░   ░░        ░  ░░ ░  ░   ▒
      ░  ░    ░  ░          ░  ░  ░      ░  ░

Aegrah's Linux Persistence Honed Assistant (ALPHA)
Github: https://github.com/Aegrah/ALPHA
Twitter: https://twitter.com/RFGroenewoud

Root User Options:

  --cron                Cron job persistence
  --ssh-key             SSH key persistence
  --systemd             Systemd service persistence
  --generator           Set up generator persistence
  --at                  At job persistence
  --shell-profile       Shell profile persistence
  --xdg                 XDG autostart persistence
  --authorized-keys     Authorized keys management
  --create-user         Create a new user
  --backdoor-user       Set up a backdoor user
  --password-change     Change user password
  --passwd-user         Add user to /etc/passwd with specified settings
  --sudoers             Set up sudoers backdoor
  --suid                Set up SUID backdoor
  --cap                 Set up capabilities backdoor
  --motd                Set up MOTD backdoor
  --rc-local            Set up rc.local backdoor
  --initd               Set up init.d backdoor
  --package-manager     Set up Package Manager persistence
  --bind-shell          Set up a bind shell
  --system-binary       Set up a system binary backdoor
  --udev                Cron job persistence
  --git                 Setup Git persistence
  --docker-container    Set up a malicious Docker container
  --malicious-package   Set up a malicious package
  --revert              Revert most changes made by ALPHA
  --quiet (-q)          Quiet mode (no banner)
```

![](https://i.imgur.com/waxVImv.png)

### Examples
Write me a boilerplate template here for some examples on how to establish persistence with ALPHA

```
alpha@alpha-demo:~$ sudo ./alpha.sh -q --systemd --default --ip 10.10.10.1 --port 1337
[+] Pesistence Established
```

![](https://i.imgur.com/waxVImv.png)
### Publications and Resources
Publications in which ALPHA is leveraged:

- [Linux Detection Engineering - The Basics of Linux Persistence](link)
- [Linux Detection Engineering - Beyond the Basics of Linux Persistence](link)

Feel free to check out my socials for updates on (Linux) security research.

<p align="left">
<a href="https://twitter.com/RFGroenewoud"><img src="https://img.shields.io/badge/%E2%9C%A8-Twitter%20-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="Twitter"/></a>
<a href="https://www.linkedin.com/in/ruben-groenewoud/"><img src="https://img.shields.io/badge/%E2%9C%A8-LinkedIn-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="LinkedIn"/></a>
<a href="https://www.rgrosec.com/"><img src="https://img.shields.io/badge/%E2%9C%A8-Blog-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="Blog"/></a>
<a href="https://github.com/Aegrah"><img src="https://img.shields.io/badge/%E2%9C%A8-GitHub-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="GitHub"/></a>

![](https://i.imgur.com/waxVImv.png)

## Share
By sharing [ALPHA](https://github.com/Aegrah/ALPHA), you can assist others in testing and improving their security posture and support the development of new detection capabilities in Linux security.

[![GitHub Repo stars](https://img.shields.io/badge/share%20on-reddit-red?logo=reddit)](https://reddit.com/submit?url=[https://github.com/Aegrah/ALPHA](https://github.com/Aegrah/ALPHA)&title=Aegrah's%20Linux%20Persistence%20Honed%20Assistant%20\(ALPHA\))
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-hacker%20news-orange?logo=ycombinator)](https://news.ycombinator.com/submitlink?u=https://github.com/Aegrah/ALPHA)
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-twitter-03A9F4?logo=twitter)](https://twitter.com/share?url=https://github.com/Aegrah/ALPHA&text=Aegrah's%20Linux%20Persistence%20Honed%20Assistant%20\(ALPHA\))
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-facebook-1976D2?logo=facebook)](https://www.facebook.com/sharer/sharer.php?u=https://github.com/Aegrah/ALPHA)
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-linkedin-3949AB?logo=linkedin)](https://www.linkedin.com/shareArticle?url=https://github.com/Aegrah/ALPHA&title=Aegrah's%20Linux%20Persistence%20Honed%20Assistant%20(ALPHA))

![](https://i.imgur.com/waxVImv.png)

## Disclaimer
ALPHA is intended for authorized security testing and research purposes only. Misuse of this tool for malicious activities is not condoned and is entirely at the user's own risk. By using ALPHA, you agree that you are responsible for your own actions.
