#!/usr/bin/env python3

import sys
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
import psutil


target_event = threading.Event()
exit_event = threading.Event()

def signal_handler(sig, frame):
    print(f"Received signal {sig}. Exiting ...")
    # sys.exit(0)
    os._exit(1)

signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C (Interrupt)
signal.signal(signal.SIGTERM, signal_handler)  # Termination signal
signal.signal(signal.SIGQUIT, signal_handler)

print("Signal handler setup done")

libafl_renode_lib = ctypes.CDLL("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/target/release/liblibafl_renode.so")
input_dir = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/input_dir_i2c"
callback_function = ctypes.CFUNCTYPE(ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
libafl_renode_lib.main_fuzzing_func.argtypes = [ctypes.c_char_p, callback_function]
libafl_renode_lib.main_fuzzing_func.restype = ctypes.c_uint8

mach_name = "drone"
print("*********Emulation()********")
e = Emulation()
print("*********Monitor()********")
m = Monitor()    # gives error if i comment it out, LoadPlatformDescription uses the machine provided by Monitor
print("*********mach add********")
mach = e.add_mach(mach_name)

# load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180_modified@ twi0 0x77"""
mach.load_repl("platforms/cpus/stm32f103.repl")
# print("*********PlatformDescriptionMachineExtensions********")
# PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)

print("*********LoadElf********")
mach.load_elf("P2IM_Drone.elf")

print("*********GetSymbolAddress********")
main_addr = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(main_addr)}")
# target_addr = main_addr
target_addr = mach.sysbus.GetSymbolAddress("Reset_Handler")
print(f"Target func addr : {hex(target_addr)}")
target_func_calling_pc = target_addr

log_file_path = "log_drone.log" # this gets saved in renode dir
trace_file_path = "trace_drone" # this one in libafl_renode dir

ret_val = 2
exit_addr = 0x080041a0  # this will change depending on target
# exit_addr = 0x080043e4
# fault_addr = 0x2ec
# final_exit_addr = 0x3b78

def hook_addr_target(cpu,addr):
    print("************In target hook")
    mach.Pause() 
    mach.sysbus.ram.Fuzz_Mem_Save()   # memory
    mach.sysbus.cpu.Fuzz_PrepareState() # cpu state
    target_event.set()
    print("************Done target hook")

def hook_addr_exit(cpu,addr):
    # print(f"***** Exit addr ******* : {hex(addr)}")
    global ret_val
    mach.Pause()
    # mach.sysbus.cpu.DisableExecutionTracing()
    ret_val = 0
    exit_event.set()  # Signal the exit event

Action1 = getattr(System, 'Action`2')
hook_action_target = Action1[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

Action2 = getattr(System, 'Action`2')
hook_action_exit = Action2[ICpuSupportingGdb, System.UInt64](hook_addr_exit)
mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)

TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")

# m.execute("logFile @" + log_file_path)
# mach.sysbus.cpu.LogFunctionNames(True)
# mach.sysbus.cpu.CreateExecutionTracing("", f"{trace_file_path}", TraceFormat.Disassembly)
# Analyzer(mach.sysbus.usart1).Show()
print("******Starting the emulator")

e.StartAll()

if target_event.wait(timeout=2):
    print("Target event triggered.")
    target_event.clear()
else:
    raise RuntimeError("Error: Timeout waiting for Target event.")

mach.Pause()
mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
print("Done initial setup")
data = [0xff]*2
i=0
def callback(data, length):
    try:
        global ret_val,i
        # mach.sysbus.ram.Fuzz_Mem_Load()
        # mach.sysbus.cpu.Fuzz_LoadState()

        # Convert the raw pointer into a usable Python byte array
        # data_array = ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte * length)).contents
        # Convert to a Python list or bytes 
        # byte_data = bytes(data_array)
        i+=1
        byte_data = bytearray(data[i] for i in range(length))
        mach.sysbus.i2c1.ReadFromFuzzer_i2c(byte_data)
        
        # mach.sysbus.cpu.CreateExecutionTracing("", f"{trace_file_path}_resumed_{i}", TraceFormat.Disassembly) # make sure trace_file is new file, else it will give error if it already exists
        mach.Resume()
        # Wait until the exit_event is set
        # Reset the event for the next iteration
        if exit_event.wait(timeout=1):
            # print("Exit event triggered.")
            exit_event.clear()
        else:
            ret_val = 2
            # mach.sysbus.cpu.DisableExecutionTracing()
            mach.Pause()
            print("^^^^^^^^^ Error: Timeout waiting for Exit event.")
            # raise RuntimeError("Error: Timeout waiting for Target event.")
        
        # mach.Pause() // doing it inside exit hook
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
except Exception as e:
    print(f"\nException occurred: {e}")
    sys.exit(1)
