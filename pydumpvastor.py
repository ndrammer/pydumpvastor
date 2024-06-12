import ctypes
import ctypes.wintypes
from ctypes.wintypes import WORD, DWORD,LONG, LPVOID, HANDLE
from ctypes import byref
from ctypes import Structure, Union
from ctypes import *
import zipfile
import io
import argparse



#------Argument parsing------
parser = argparse.ArgumentParser(description='Process Memory Dump')
parser.add_argument('pid', help='process PID')
args = parser.parse_args()

#------pid-----------
pid = int(args.pid)  

#------Constants-----
PROCESS_ALL_ACCESS = 0x1f0fff
PROCESS_VM_READ = 0x0010


#------Types definitions----
SIZE_T = ctypes.c_size_t
if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong):
    DWORD_PTR = ctypes.c_ulonglong
elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong):
    DWORD_PTR = ctypes.c_ulong

#-----Get process handle------
handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS or PROCESS_VM_READ, False, pid)


#-----System & Memory info------
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



class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = (('BaseAddress', ctypes.c_ulonglong), 
                ('AllocationBase',    ctypes.c_ulonglong),  
                ('AllocationProtect', DWORD),
                ("__alignment1", wintypes.DWORD),
                ('RegionSize', ctypes.c_ulonglong),  
                ('State',   DWORD),
                ('Protect', DWORD),
                ('Type',    DWORD),
                ("__alignment2", wintypes.DWORD))


mem_region_begin = sysinfo.lpMinimumApplicationAddress
mem_region_end = sysinfo.lpMaximumApplicationAddress
address = mem_region_begin

#-------Object BytesIO for dumping----
chunk_size = 4096
dump_data = io.BytesIO()
total_size=0


#-------Memory regions travelling and dumping-----
while address < mem_region_end:

    mbi = MEMORY_BASIC_INFORMATION()

    ctypes.windll.Kernel32.VirtualQueryEx(handle, ctypes.c_uint64(address), ctypes.byref(mbi),ctypes.sizeof(mbi)) 
    if (mbi.Protect!=(0x01) and mbi.State==0x1000):        
        print(f"BA:{hex(mbi.BaseAddress)} Size:{mbi.RegionSize/1024}")
        total_size+=mbi.RegionSize

         #----------Dumping-------------------

        for addres_s in range(mbi.BaseAddress, mbi.BaseAddress+mbi.RegionSize, chunk_size):
            buffer = (ctypes.c_char * 4096)() 
                             
            if (ctypes.windll.kernel32.ReadProcessMemory(handle, ctypes.c_ulonglong(addres_s), ctypes.byref(buffer), 4096, None)):
                dump_data.write(buffer.raw)
            else:
                ctypes.WinError(ctypes.get_last_error())

    address += mbi.RegionSize
    
print('[+] Dump finished')
print(f"Total Size (bytes): {total_size} (Kbytes): {total_size/1024} ")


#-----------Closing process handle-----------
ctypes.windll.kernel32.CloseHandle(handle)

#-----------Writing to file (zipped)-----------
with zipfile.ZipFile('ex.zip', 'w', zipfile.ZIP_DEFLATED) as zipf:
    dump_data.seek(0)  
    zipf.writestr('dump.bin', dump_data.read())  
