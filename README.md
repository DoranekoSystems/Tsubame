# Tsubame

<img width="400" alt="img" src="https://user-images.githubusercontent.com/96031346/214802113-4b7d62b6-2ac5-4e4b-a922-f45c529b81ab.png">

cross-platform cui-based process memory analyzer.  
"Tsubame" is the Japanese word for swallow.

## Memory Scanner

```
? Please Input a command. find
? Please Input a data type. ['dword']
? Please Input a value. 1000
progress: 100%|█████████████████████████████████████████████████████████████████████████████████████████████|
HIT COUNT:3834!!

--------------------------------------------------------
? Please Input a command. filter
? Please Input a data type. ['dword']
? Please Input a value. 1010
progress: 100%|█████████████████████████████████████████████████████████████████████████████████████████████|
FILTERD:1/3834!!

-------------------------------------------------
? Please Input a command. 3
  1) find
  2) filter
  3) patch
  4) dump
  5) list
  6) view
  7) exit
```

## Realtime Memory Viewer

Multiple windows can be opened.

<img width="800" alt="img" src="https://user-images.githubusercontent.com/96031346/214028706-c327a2ea-e02e-4727-9d9b-a93a09b7d1e5.png">

# Usage

Install python library.

```
# windows
pip install -r requirements_windows.txt

# mac
pip install -r requirements_mac.txt
```

Install and start frida-server.

```
python main.py Cydia

# or

python main.py com.saurik.Cydia

# or

python main.py -p ProcessId
```

# Wiki

[Command List](https://github.com/DoranekoSystems/Tsubame/wiki/Command-List)

# License

## MemoryView

The original software is available at  
https://github.com/walterdejong/hexview.  
This project is a partial enhancement of the above great software.
