#!/usr/bin/env python3

import sys
# sys.path.append("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/pyrenode3/src/")

import time
from pyrenode3 import RPath
import System   # import sys
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import TranslationCPUHooksExtensions
from Antmicro.Renode.Peripherals.CPU import RegisterValue
from Antmicro.Renode.Peripherals.CPU import ICpuSupportingGdb
from Antmicro.Renode.PlatformDescription.UserInterface import PlatformDescriptionMachineExtensions
from Antmicro.Renode.Peripherals.CPU import TraceFormat


from decimal import Decimal
import random
import cProfile

import signal
import pstats
import io
import os
import threading
import ctypes
import multiprocessing
import atexit
import psutil


def cleanup():
    mach.sysbus.cpu.Dispose()
    print("Cleanup function called before exit!")

atexit.register(cleanup)  # Register cleanup function

def signal_handler(sig, frame):
    print(f"Signal handler : Received signal {sig}. Exiting ...")
    # Check child processes after
    # print("Processes after 2222 :", list_child_processes())
    # Check active threads before
    # print("Threads after calling LibAFL 22222:", list_threads())
    # return 99
    # mach.sysbus.cpu.Dispose()
    # sys.exit(0) 
    os._exit(1)

signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C (Interrupt)
signal.signal(signal.SIGTERM, signal_handler)  # Termination signal
signal.signal(signal.SIGQUIT, signal_handler)


libafl_renode_lib = ctypes.CDLL("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/target/release/liblibafl_renode.so")
input_dir = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/input_dir_i2c"
# callback_function = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
# callback_function = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p)
# callback_function = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))
callback_function = ctypes.CFUNCTYPE(ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
# callback_function = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_uint8))

libafl_renode_lib.main_fuzzing_func.argtypes = [ctypes.c_char_p, callback_function]
libafl_renode_lib.main_fuzzing_func.restype = ctypes.c_uint8

target_event = threading.Event()
exit_event = threading.Event()

exit_flag = 0 # not needed when threading based even works, but that gives problem with libafl
mach_name = "nrf"       
print("*********Emulation()********")
e = Emulation() 
print("*********Monitor()********")
m = Monitor()    # gives error if i comment it out, LoadPlatformDescription uses the machine provided by Monitor
print("*********mach add********")
mach = e.add_mach(mach_name)

# state_file= "statefile_bmp180_nrf_test_no_delay.dat"
trace_file_path = "trace_bmp180_nrf_test_no_delay"
log_file_path = "log_bmp180_nrf_test_no_delay_buggy.log"

temp_data = 60
humidity_data = 88
pressure_data = 1200

ret_val = 5
exit_addr = 0x3102  # this will change depending on target
fault_addr = 0x2ec
final_exit_addr = 0x3b78
# exit_addr = 0x3102
# restore_pc = 0x0800353a
# restore_sp = 0x20001040
# load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180@ twi0 0x77"""
load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180_modified@ twi0 0x77"""
print("*********PlatformDescriptionMachineExtensions********")
PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)

print("*********LoadElf********")
# mach.load_elf("https://dl.antmicro.com/projects/renode/BMP180_I2C.ino.arduino.mbed.nano33ble.elf-s_3127076-ba5f49cd34cd9549c2aa44f83af8e2011ecd1c22")
mach.load_elf("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/nrf_bmp180_drv1_no_delay.out")

# binary with bug
# mach.load_elf("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/nrf_bmp180_drv1_no_delay_with_bug.out")

print("*********GetSymbolAddress********")
target_addr = mach.sysbus.GetSymbolAddress("main")
# target_addr = mach.sysbus.GetSymbolAddress("Reset_Handler")
# target_addr = mach.sysbus.GetSymbolAddress("driver_bmp180_start")

print(f"Main func addr : {hex(target_addr)}")
target_func_calling_pc = target_addr


def hook_addr_target(cpu,addr):
    print("************In target hook")
    mach.Pause() 
    mach.sysbus.ram.Fuzz_Mem_Save()   # memory
    mach.sysbus.cpu.Fuzz_PrepareState() # cpu state
    target_event.set()

def hook_addr_exit(cpu,addr):
    # print(f"***** Exit addr ******* : {hex(addr)}")
    # mach.Pause()
    global ret_val
    ret_val = 0
    exit_event.set()  # Signal the exit event
    # global exit_flag
    # mach.Pause()
    # exit_flag = 1

Action1 = getattr(System, 'Action`2')
hook_action_target = Action1[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

Action2 = getattr(System, 'Action`2')
hook_action_exit = Action2[ICpuSupportingGdb, System.UInt64](hook_addr_exit)
mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)


TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")


# if os.path.exists(trace_file_path):
#     os.remove(trace_file_path)

# mach.sysbus.cpu.CreateExecutionTracing("", trace_file_path, TraceFormat.Disassembly) # ******
# m.execute("logLevel -1")
# m.execute("logFile @" + log_file_path)

# Analyzer(mach.sysbus.uart0).Show()
print("******Starting the emulator")

e.StartAll()
if target_event.wait(timeout=0.5):
    print("Target event triggered.")
    target_event.clear()
else:
    raise RuntimeError("Error: Timeout waiting for Target event.")
mach.Pause()
mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
print("Done initial setup")
data = [0xff]*2
t_count = 1

# mach.sysbus.cpu.DisableExecutionTracing()
# print("Done")
# mach.sysbus.cpu.LogFunctionNames(False)

# pr = cProfile.Profile()
# pr.enable()
# try :
i=0
def callback(data, length):
    try:
        global exit_flag, ret_val,i
        i+=1
        # print("***************Loading the saved states...")
        # print(f"---- Reg before load : SP : {hex(mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue)}, PC : {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
        # start_time = time.time()
        # mach.Pause()
        # mach.sysbus.ram.Fuzz_DeallocateAllSegments()
        mach.sysbus.ram.Fuzz_Mem_Load()
        mach.sysbus.cpu.Fuzz_LoadState()
        # Convert the raw pointer into a usable Python byte array
        # data_array = ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte * length)).contents
        # Convert to a Python list or bytes 
        # byte_data = bytes(data_array)
        byte_data = bytearray(data[i] for i in range(length))
        # mach.sysbus.cpu.Reset()
        mach.sysbus.twi0.bmp180.ReadFromFuzzer(byte_data)
        # i+=1
        # mach.sysbus.cpu.Resume()
        # mach.sysbus.cpu.CreateExecutionTracing("", f"{trace_file_path}_resumed_{i}", TraceFormat.Disassembly) # make sure trace_file is new file, else it will give error if it already exists
        mach.Resume()
        # mach.sysbus.cpu.Start()
        # Wait until the exit_event is set
        exit_event.wait(timeout=0.1)
        # exit_event.wait()
        # Reset the event for the next iteration
        exit_event.clear()
        # time.sleep(1)
        mach.Pause()
        # if i>=100:
        #     ret_val=22
        # print(f"In python res :, normal : {ret_val}")
        # time.sleep(1)
        return ret_val
        # return ctypes.c_uint8(ret_val)
        # end_time = time.time()
        # load_execution_time = end_time - start_time
        # print(f"******** Load file execution time: {load_execution_time:.10f} seconds")
        # print("Done one loop")
        # while exit_flag == 0 : # testing with this, as the event based approach is giving error with libafl, remove this when that gets fixed.
        #     # print(f"Waiting at current pc : {(mach.sysbus.cpu.PC)}")
        #     pass
    
        # if exit_flag == 1:
        #     exit_flag = 0

    except Exception as e:
        print(f"\nException occurred in callback: {e}")
        # sys.exit(1)
        os._exit(1)
        # return 99
             

           

    
# except Exception as e:
#     print(f"\n***** Exception occurred: {e}")
#     # sys.exit(1)

# finally:
#     pr.disable()
#     # Create a stream to hold the profiling results
#     s = io.StringIO()
#     sortby = pstats.SortKey.CUMULATIVE
#     ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
#     ps.print_stats()

#     # Print the profiling results
#     print(s.getvalue())
    
#     # Exit the program
#     sys.exit(0)

def list_child_processes():
    parent = psutil.Process(os.getpid())
    return [p.pid for p in parent.children(recursive=True)]

# Check child processes before
print("Processes before:", list_child_processes())
def list_threads():
    return [t.name for t in threading.enumerate()]

# Check active threads before
print("Threads before calling LibAFL:", list_threads())

assert input_dir is not None, "Error: Input directory is None"

try:
    callback_ptr = callback_function(callback)
    print("calling liabafl main_fuzzing_func------")
    libafl_renode_lib.main_fuzzing_func(ctypes.c_char_p(input_dir.encode('utf-8')),callback_ptr)
    # Check child processes after
    print("Processes after 1111:", list_child_processes())
    # Check active threads before
    print("Threads after calling LibAFL 1111:", list_threads())
except Exception as e:
    print(f"\nException occurred: {e}")
    sys.exit(1)
    # os._exit(1)

# Check child processes after
print("Processes after:", list_child_processes())
# Check active threads before
print("Threads after calling LibAFL:", list_threads())


# multiprocessing thing - renode doesn't like it
# def run_fuzzing(input_dir):
#     try:
#         callback_ptr = callback_function(callback)
#         print("Calling libafl main_fuzzing_func...")
        
#         # Call the Rust function (main_fuzzing_func)
#         libafl_renode_lib.main_fuzzing_func(ctypes.c_char_p(input_dir.encode('utf-8')), callback_ptr)
#     except Exception as e:
#         print(f"Exception occurred: {e}")
#         sys.exit(1)



# # Create a separate process for fuzzing - nope renode doesn't like
# fuzzing_process = multiprocessing.Process(target=run_fuzzing, args=(input_dir,))
# fuzzing_process.start()

# try:
#     # Wait for the fuzzing process to complete
#     fuzzing_process.join()
# except KeyboardInterrupt:
#     print("Ctrl+C detected in the main process! Performing cleanup...")
#     fuzzing_process.terminate()
#     fuzzing_process.join()
#     sys.exit(1)

# if __name__ == "__main__":
#     input_dir = "/path/to/input_dir"  # Change this to the correct input directory

#     # Create a separate process for fuzzing
#     fuzzing_process = multiprocessing.Process(target=run_fuzzing, args=(input_dir,))
#     fuzzing_process.start()

#     try:
#         # Wait for the fuzzing process to complete
#         fuzzing_process.join()
#     except KeyboardInterrupt:
#         print("Ctrl+C detected in the main process! Performing cleanup...")
#         fuzzing_process.terminate()
#         fuzzing_process.join()
#         sys.exit(1)






