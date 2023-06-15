# Tsubame

cross-platform Tui-based process memory analyzer.  
"Tsubame" is the Japanese word for swallow.

<img width="800" alt="img" src="https://github.com/DoranekoSystems/Tsubame/assets/96031346/96f136b9-fe62-43be-828b-62c501aa597f">

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
