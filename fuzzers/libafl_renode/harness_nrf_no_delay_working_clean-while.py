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


target_event = threading.Event()
exit_event = threading.Event()

def signal_handler(sig, frame):
    print(f"Received signal {sig}. Exiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C (Interrupt)
signal.signal(signal.SIGTERM, signal_handler)  # Termination signal
signal.signal(signal.SIGQUIT, signal_handler)

print("Signal handler setup done")

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
    print(f"***** Exit addr ******* : {hex(addr)}")
    # mach.Pause()
    # mach.sysbus.cpu.Pause()
    exit_event.set()  # Signal the exit event
    # mach.Pause()

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

Analyzer(mach.sysbus.uart0).Show()
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
try :
    i=0
    while t_count:
        # print("***************Loading the saved states...")
        # print(f"---- Reg before load : SP : {hex(mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue)}, PC : {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
        start_time = time.time()
        # mach.Pause()
        # mach.sysbus.cpu.Pause()
        # mach.sysbus.ram.Fuzz_DeallocateAllSegments()
        mach.sysbus.ram.Fuzz_Mem_Load()
        mach.sysbus.cpu.Fuzz_LoadState()
        # mach.sysbus.cpu.Reset()
        mach.sysbus.twi0.bmp180.ReadFromFuzzer(data)
        # i+=1
        # mach.sysbus.cpu.Resume()
        # mach.sysbus.cpu.CreateExecutionTracing("", f"{trace_file_path}_resumed_{i}", TraceFormat.Disassembly) # make sure trace_file is new file, else it will give error if it already exists
        mach.Resume()
        # mach.sysbus.cpu.Start()
        # Wait until the exit_event is set
        exit_event.wait(timeout=0.1)
        # Reset the event for the next iteration
        exit_event.clear()
        mach.Pause()
        end_time = time.time()
        load_execution_time = end_time - start_time
        print(f"******** Load file execution time: {load_execution_time:.10f} seconds")

           

    
except Exception as e:
    print(f"\n***** Exception occurred: {e}")
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

# input()






