# pydumpvastor

Dumps memory of the process with the selected PID. At this moments it is just a PoC of implementing Win APIs using python ctypes libraries.

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

Needs to be improved as not all memory regions are dumped
