# ASPMEnabler
Linux program that automatically activates ASPM for all supported devices.\
C port of [AutoASPM](https://git.notthebe.ee/notthebee/AutoASPM).

## Download
Prebuilt binary available in [Releases](https://github.com/QuanTrieuPCYT/ASPMEnabler/releases).

## Building
```
gcc -O2 -flto -Wall -Wextra aspmenabler.c -o aspmenabler
```
The resulting binary will be named `aspmenabler`.