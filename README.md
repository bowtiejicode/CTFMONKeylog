# CTFMONKeylog

### Overview
The [original](https://github.com/bowtiejicode/OnScreenKeylog) project has the on-screen keyboard GUI open. Once the osk.exe exits, your keylogger will stop working. To prevent that, we "migrate" to another UiAccess process (ctfmon.exe) and continue our keylogging process there. The output file is written to C:\Windows\Tracing\Keylog.txt

### Usage
1. Build dllmain.cpp and rename the DLL as OnScreenKeylog.dll
2. Copy the file to your desktop
3. Open command prompt and run ```rundll32.exe OnScreenKeylog,Initialize```
4. Type anything on the keyboard and you should see the keystrokes appearing in ```C:\Windows\Tracing\Keylog.txt```

   
### Disclaimer
This project is intended solely for **educational purposes only** and in no manner supports any illegal activities. 

ctfmon.exe will restart when you switch your desktop session to another user, causing the keylogger to stop working
