# pydumpvastor

Dumps memory of the process with the selected PID. It began just to understand how to access Win APIs using python ctypes libraries.

Output file is hardcoded to ex.zip

```
python pydumpvastor.py [PID]
```
--------------------------

### Example: Dumping process with PID 9052

```
python pydumpvastor.py 9052
```

--------------------------

### .exe

To get an executable .exe version

```
pyinstaller --onefile  pydumpvastor.py
```

.exe is place in dist folder

--------------------------
### ToDo

Achive a lsass dump compatible with mimikatz or pypykatz.
Check https://github.com/ricardojoserf/NativeDump/tree/python-flavour
