# frida-medit
simple cui-based process memory scanner.

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

--------------------------------------------------------
? Please Input a command. 3
  1) find
  2) filter
  3) patch
  4) dump
  5) list
  6) view
  7) exit
```

# Usage

Install python library.

```
pip install -r requirements.txt
```



Install and start frida-server.   

```
python main.py Cydia

# or

python main.py com.saurik.Cydia

# or

python main.py -p ProcessId
```

# Known Issues
- filter is slow

# License

## MemoryView

The original software is available at  
https://github.com/walterdejong/hexview.    
This project is a partial enhancement of the above great software.  