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


target_event = threading.Event()
# exit_event = threading.Event()

def signal_handler(sig, frame):
    print(f"Received signal {sig}. Exiting gracefully...")
    #sys.exit(0) // won't work with libafl
    os._exit(1)

signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C (Interrupt)
signal.signal(signal.SIGTERM, signal_handler)  # Termination signal
signal.signal(signal.SIGQUIT, signal_handler)

print("Signal handler setup done")

libafl_renode_lib = ctypes.CDLL("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/target/release/liblibafl_renode.so")
input_dir = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/input_dir_i2c"
callback_function = ctypes.CFUNCTYPE(ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)

mach_name = "console"
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
mach.load_elf("P2IM_Soldering_Iron.elf")

print("*********GetSymbolAddress********")
target_addr = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(target_addr)}")
target_func_calling_pc = target_addr

log_file_path = "log_soldering_iron.log" # this gets saved in renode dir
trace_file_path = "trace_soldering_iron" # this one in libafl_renode dir

def hook_addr_target(cpu,addr):
    print("************In target hook")
    # mach.Pause() 
    # mach.sysbus.ram.Fuzz_Mem_Save()   # memory
    # mach.sysbus.cpu.Fuzz_PrepareState() # cpu state
    target_event.set()

Action1 = getattr(System, 'Action`2')
hook_action_target = Action1[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

# TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")

# m.execute("logFile @" + log_file_path)
# mach.sysbus.cpu.LogFunctionNames(True)
# mach.sysbus.cpu.CreateExecutionTracing("", f"{trace_file_path}", TraceFormat.Disassembly)
Analyzer(mach.sysbus.usart1).Show()
print("******Starting the emulator")

e.StartAll()

if target_event.wait(timeout=2):
    print("Target event triggered.")
    target_event.clear()
else:
    raise RuntimeError("Error: Timeout waiting for Target event.")


input()
