# Tsubame

Cross Platform TUI based process memory analyzer.  
"Tsubame" is the Japanese word for swallow.

<img width="800" alt="screenshot" src="https://github.com/DoranekoSystems/Tsubame/assets/96031346/7d576ef4-d1c0-4205-b735-0d6c486827e1">

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

# License

## MemoryView

The original software is available at  
https://github.com/walterdejong/hexview.  
This project is a partial enhancement of the above great software.
