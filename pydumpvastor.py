import ctypes
import ctypes.wintypes
from ctypes.wintypes import WORD, DWORD,LONG, LPVOID, HANDLE
from ctypes import byref
from ctypes import Structure, Union
from ctypes import *
import zipfile
import io
import argparse


#argument parsing
parser = argparse.ArgumentParser(description='Memory Process Dumpo')
parser.add_argument('pid', help='process PID')
args = parser.parse_args()

#pid
pid = int(args.pid)  

#Constants
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)


# Types definitions
SIZE_T = ctypes.c_size_t
if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong):
    DWORD_PTR = ctypes.c_ulonglong
elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong):
    DWORD_PTR = ctypes.c_ulong

#Open process
handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)


#System info
class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", ctypes.c_ushort),
        ("wReserved", ctypes.c_ushort),
        ("dwPageSize", ctypes.c_uint),
        ("lpMinimumApplicationAddress", ctypes.c_ulonglong),
        ("lpMaximumApplicationAddress", ctypes.c_ulonglong),
        ("dwActiveProcessorMask", ctypes.c_ulonglong),
        ("dwNumberOfProcessors", ctypes.c_uint),
        ("dwProcessorType", ctypes.c_uint),
        ("dwAllocationGranularity", ctypes.c_uint),
        ("wProcessorLevel", ctypes.c_ushort),
        ("wProcessorRevision", ctypes.c_ushort),
    ]

LPSYSTEM_INFO = ctypes.POINTER(SYSTEM_INFO)

Kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
Kernel32.GetSystemInfo.restype = None
Kernel32.GetSystemInfo.argtypes = (LPSYSTEM_INFO,)


sysinfo = SYSTEM_INFO()
Kernel32.GetSystemInfo(ctypes.byref(sysinfo))


#baseaddress
hModule = ctypes.c_ulonglong()  #  c_ulong for 32 bits
count = ctypes.c_ulong()
modname = ctypes.create_unicode_buffer(30)
    
# Enum Process
if ctypes.windll.psapi.EnumProcessModulesEx(handle, ctypes.byref(hModule), ctypes.sizeof(hModule), ctypes.byref(count), 3):

    print(f"Process BaseAddress: {hModule.value}")
else:
    print("Not possible to get BaseAddress.")


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = (('BaseAddress', ctypes.c_uint64),  #LPVOID for 32bits
                ('AllocationBase',    ctypes.c_uint64),  #LPVOID  for 32bits
                ('AllocationProtect', DWORD),
                ('RegionSize', ctypes.c_uint64),  #SIZE_T  for 32bits
                ('State',   DWORD),
                ('Protect', DWORD),
                ('Type',    DWORD))

mbi = MEMORY_BASIC_INFORMATION()

ctypes.windll.Kernel32.VirtualQueryEx(handle, ctypes.c_uint64(hModule.value), ctypes.byref(mbi),ctypes.sizeof(mbi)) 



#----------Dumping-------------------


# Object BytesIO for dumping
dump_data = io.BytesIO()

address=mbi.BaseAddress

buffer = (ctypes.c_char * 4096)()
bytesRead = SIZE_T()
blocks=(mbi.RegionSize/sysinfo.dwPageSize)+1
final=address+blocks*sysinfo.dwPageSize



while (address < final):

    if (ctypes.windll.kernel32.ReadProcessMemory(handle, ctypes.c_uint64(address), ctypes.byref(buffer), 4096, ctypes.byref(bytesRead))):
        print('[...]Dumping')
        dump_data.write(buffer.raw)
    else:
        ctypes.WinError(ctypes.get_last_error())

    address += sysinfo.dwPageSize
    

print('[+] Dump finished')
#print(buffer.raw)

#-----------Writing to file-----------


ctypes.windll.kernel32.CloseHandle(handle)

# Compress data
with zipfile.ZipFile('ex.zip', 'w', zipfile.ZIP_DEFLATED) as zipf:
    #zipf.setpassword(b'S3cr3t')  # Password only works for reading in zipfile library
    dump_data.seek(0)  
    zipf.writestr('dump.bin', dump_data.read())  
