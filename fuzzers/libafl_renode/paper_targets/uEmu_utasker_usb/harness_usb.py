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
import faulthandler

# faulthandler.enable()


target_event = threading.Event()
exit_event = threading.Event()

ret_val = 0
fault_flag = 0
counter = 0

def signal_handler_exit(sig, frame):
    print(f"Received signal {sig}. Exiting ...")
    # sys.exit(0)
    os._exit(1)

signal.signal(signal.SIGINT, signal_handler_exit)  # Ctrl+C (to exit)

def signal_handler_crash(sig,frame):
    global ret_val
    ret_val=7
    exit_event.set()
    print(f"***** Signal crash : {sig} *******")
    
signal.signal(signal.SIGILL, signal_handler_crash)  
signal.signal(signal.SIGSEGV, signal_handler_crash)
signal.signal(signal.SIGBUS, signal_handler_crash)

print("Signal handler setup done")

libafl_renode_lib = ctypes.CDLL("liblibafl_renode.so")
input_dir = "input_dir"

callback_function = ctypes.CFUNCTYPE(ctypes.c_uint8)

libafl_renode_lib.main_fuzzing_func.argtypes = [ctypes.c_char_p, callback_function]
libafl_renode_lib.main_fuzzing_func.restype = ctypes.c_uint8

mach_name = "usb"
print("*********Emulation()********")
e = Emulation()
print("*********Monitor()********")
m = Monitor()    # gives error if i comment it out, LoadPlatformDescription uses the machine provided by Monitor
print("*********mach add********")
mach = e.add_mach(mach_name)

# load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180_modified@ twi0 0x77"""
mach.load_repl("platforms/cpus/stm32f429_fuzz.repl")
# print("*********PlatformDescriptionMachineExtensions********")
# PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)

print("*********LoadElf********")
mach.load_elf("uEmu.uTasker_USB.out")

print("*********GetSymbolAddress********")
main_addr = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(main_addr)}")
target_addr = mach.sysbus.GetSymbolAddress("__iar_program_start")
print(f"Target func addr : {hex(target_addr)}")
target_func_calling_pc = target_addr

fault_addr1 = mach.sysbus.GetSymbolAddress("irq_bus_fault")
print(f"irq_bus_fault addr : {hex(fault_addr1)}")

fault_addr2 = mach.sysbus.GetSymbolAddress("irq_hard_fault")
print(f"irq_hard_fault addr : {hex(fault_addr2)}")

fault_addr3 = mach.sysbus.GetSymbolAddress("irq_usage_fault")
print(f"irq_usage_fault addr : {hex(fault_addr3)}")

# fault_addr4 = mach.sysbus.GetSymbolAddress("Error_Handler")
# print(f"_Error_Handler addr : {hex(fault_addr4)}")

fault_addr4 = 0x0

exit_addr = 0x800C214   # this will change depending on target -(while-true loop)



def hook_addr_target(cpu,addr):
    print("************In target hook")
    # mach.Pause() 
    # mach.sysbus.ram.Fuzz_Mem_Save()   # memory
    # mach.sysbus.cpu.Fuzz_PrepareState() # cpu state
    target_event.set()
    print("************Done target hook")

def hook_addr_exit(cpu,addr):
    # print(f"***** Exit addr ******* : {hex(addr)}")
    global ret_val
    ret_val = 0
    mach.Pause()
    exit_event.set()

def hook_addr_faults(cpu,addr):
    global ret_val
    ret_val = 5
    mach.Pause()
    exit_event.set()
    print(f"***** Exit addr Fault ******* : {hex(addr)}")

Action1 = getattr(System, 'Action`2')
hook_action_target = Action1[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

Action2 = getattr(System, 'Action`2')
hook_action_exit = Action2[ICpuSupportingGdb, System.UInt64](hook_addr_exit)
mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)

Action3 = getattr(System, 'Action`2')
hook_action_fault = Action3[ICpuSupportingGdb, System.UInt64](hook_addr_faults)
mach.sysbus.cpu.AddHook(fault_addr1,hook_action_fault)
mach.sysbus.cpu.AddHook(fault_addr2,hook_action_fault)
mach.sysbus.cpu.AddHook(fault_addr3,hook_action_fault)
mach.sysbus.cpu.AddHook(fault_addr4,hook_action_fault)
# mach.sysbus.cpu.AddHook(fault_addr5,hook_action_fault)

# TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")
# mach.sysbus.cpu.Fuzz_SetHookAtBlockBegin()

# m.execute("logFile @" + log_file_path)
# mach.sysbus.cpu.LogFunctionNames(True)
# mach.sysbus.cpu.CreateExecutionTracing("", f"{trace_file_path}", TraceFormat.Disassembly)
# Analyzer(mach.sysbus.usart1).Show()
# mach.sysbus.cpu.PerformanceInMips = 100 # changing this changes the coverage (We get more blocks when this val is 10 compared to 100), it can also impact fuzzer perf
# mach.ConfigurePeripheralsToReset(["cpu","nvic","flash_ctrl","timer2","timer3","timer4","usart1","i2c1"])
mach.fuzz_init_settings()
mach.ConfigurePeripheralsToReset(["cpu","nvic","flash_controller","timer2", "usart3"])
mach.sysbus.cpu.EnableTimeSkip("fnDelayLoop")
print("******Starting the emulator")
i=0
e.StartAll()

if target_event.wait(timeout=1):
    print("Target event triggered.")
    target_event.clear()
else:
    raise RuntimeError("Error: Timeout waiting for Target event.")

mach.Pause()
# mach.sysbus.cpu.DisableExecutionTracing()
mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
# mach.sysbus.cpu.CountNonZeroElements_COVMAP()
# mach.sysbus.cpu.Fuzz_GetEdges(i)
# mach.sysbus.cpu.Fuzz_GetBlockCount(i)
# mach.sysbus.cpu.Fuzz_GetBlockEndCount(i)
# mach.sysbus.cpu.zeroOutCovMap()
# mach.sysbus.cpu.Fuzz_ClearSets()
# TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")
mach.sysbus.cpu.Fuzz_SetHookAtBlockBegin()
print("Done initial setup")
# mach.sysbus.cpu.Fuzz_GetBlockCount() # only when replaying
data = [0xff]*2

def callback():
        global ret_val
        # mach.FuzzReset() 
        mach.sysbus.usart3.WriteChar(0xaa)
        # mach.sysbus.usart3.ReadFromFuzzer_PY(data)
        mach.Resume()
        # mach.sysbus.usart3.WriteChar(0xaa)
        if exit_event.wait(timeout=2):
            # print("Exit event triggered.")
            mach.Pause()
            exit_event.clear()
            # mach.Pause()
            # mach.sysbus.cpu.Fuzz_GetBlockCount()
            # mach.sysbus.cpu.CountNonZeroElements_COVMAP()
            # mach.sysbus.cpu.Fuzz_GetEdgesCount()
            # mach.sysbus.cpu.Fuzz_GetEdges(i)
            # mach.sysbus.cpu.Fuzz_GetBlockCount(i)
            # mach.sysbus.cpu.Fuzz_GetBlockEndCount(i)
            # mach.sysbus.cpu.zeroOutCovMap() # testing if libafl clear it, else we will have to do it?
            # mach.sysbus.cpu.Fuzz_ClearSets()
            # exit_event.clear()
        else:
            ret_val = 2
            mach.Pause()
            print(f"^^^^^^^^^ Error: Timeout/crash waiting for Exit event. ret val : {ret_val}, PC : {mach.sysbus.cpu.PC}")
        
        if ret_val != 0 :
            mach.FuzzReset()
        # mach.Pause() 
        return ret_val


assert input_dir is not None, "Error: Input directory is None"

try:
    callback_ptr = callback_function(callback)
    print("calling liabafl main_fuzzing_func------")
    libafl_renode_lib.main_fuzzing_func(ctypes.c_char_p(input_dir.encode('utf-8')),callback_ptr)
except Exception as e:
    print(f"\nException occurred: {e}")
    sys.exit(1)

