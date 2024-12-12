# !/usr/bin/env -S python3 -m bpython -i
import time
import timeit
from pyrenode3 import RPath
import System   # import sys
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import TranslationCPUHooksExtensions
from Antmicro.Renode.Peripherals.CPU import RegisterValue
from Antmicro.Renode.Peripherals.CPU import ICpuSupportingGdb
from Antmicro.Renode.Peripherals.CPU import ExecutionTracer
from Antmicro.Renode.Peripherals.CPU import ExecutionTracerExtensions
from Antmicro.Renode.PlatformDescription.UserInterface import PlatformDescriptionMachineExtensions
from Antmicro.Renode.Core import EmulationManager # src/Infrastructure/src/Emulator/Main/Core/EmulationManager.cs
from Antmicro.Renode.Utilities import ConfigurationManager
from Antmicro.Renode.Utilities import ReadFilePath
from Antmicro.Renode.Peripherals.CPU import TranslationCPU
from Antmicro.Renode.Peripherals.CPU import TraceFormat
from decimal import Decimal
import random
import cProfile
import sys
import signal
import pstats
import io
import os

sp_main = 0
lr_main = 0
pc_main = 0
mach_name = "nrf"
e = Emulation()
m = Monitor()    # gives error if i comment it out, LoadPlatformDescription uses the machine provided by Monitor
mach = e.add_mach(mach_name)

# state_file= "statefile_bmp180_nrf_test_no_delay.dat"
trace_file_path = "trace_bmp180_nrf_test_no_delay"
log_file_path = "log_bmp180_nrf_test_no_delay.log"

temp_data = 60
# humidity_data = 88
pressure_data = 1200

exit_flag = 0
delay_flag = 0
reach_target_flag = 0
# exit_addr = 0x00010204  # 0x000111c8 # Decision about when to exit??
exit_addr = 0x3068
# restore_pc = 0x0800353a
# restore_sp = 0x20001040
# load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180@ twi0 0x77"""
load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180_modified@ twi0 0x77"""
PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)
# mach.load_elf("https://dl.antmicro.com/projects/renode/BMP180_I2C.ino.arduino.mbed.nano33ble.elf-s_3127076-ba5f49cd34cd9549c2aa44f83af8e2011ecd1c22")
mach.load_elf("nrf_bmp180_drv1_no_delay.out")

pc_main = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(pc_main)}")
target_func_calling_pc = pc_main

def hook_addr_target(cpu,addr):
    global reach_target_flag
    # pc_target = addr
    # sp_target = mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue  
    mach.sysbus.cpu.Pause()
    # mach.Pause()
    # e.PauseAll()
    # mach.sysbus.cpu.DisableExecutionTracing()
    reach_target_flag = 1
    print("Target Hook task done")

def hook_addr_exit(cpu,addr):
    global exit_flag
    exit_flag = 1
    print(f"***** Exit addr ******* : {hex(addr)}")
Action3 = getattr(System, 'Action`2')
hook_action_target = Action3[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

# Action4 = getattr(System, 'Action`2')
# hook_action_exit = Action4[ICpuSupportingGdb, System.UInt64](hook_addr_exit)
# mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)
# ExecutionTracer.Start(mach.sysbus.cpu.internal)
# ExecutionTracerExtensions.CreateExecutionTracing(mach.sysbus.cpu.internal,trace_file_path)

if os.path.exists(trace_file_path):
    os.remove(trace_file_path)

# mach.sysbus.cpu.CreateExecutionTracing("TrackMemoryAccesses", trace_file_path, TraceFormat.Disassembly) # ******
m.execute("logLevel -1")
m.execute("logFile @" + log_file_path)
Analyzer(mach.sysbus.uart0).Show()

e.StartAll()
# m.execute("logFile @" + log_file_path)
while reach_target_flag == 0:
    pass
if reach_target_flag == 1:
    print("Target flag reached. Saving the instance now...")
    try:
        # mach.Pause()
        mach.sysbus.cpu.Pause()
        mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
        # mach.sysbus.cpu.RemoveHooksAt(exit_addr)
        # EmulationManager.Instance.Save(state_file)
        # EmulationManager.Instance.Save()
        # print(f"Save command executed")
        # print(f"Save command executed: Save @{state_file}")
        # mach.sysbus.cpu.DisableExecutionTracing()
        # m.execute("Clear")
    except Exception as e:
         print(f"Error executing save command: {e}")
    print("reached flag")

# load_path_format = ReadFilePath(state_file)
print("Done initial setup")
data = [0x44,0x44,0x32]
count = 1

# mach.sysbus.cpu.DisableExecutionTracing()
print("Done")
# mach.sysbus.cpu.LogFunctionNames(False)

# pr = cProfile.Profile()
# pr.enable()
# try :
while count:
#     # count += 1
        print("Loading the saved file")
        start_time = time.time()
        # EmulationManager.Instance.Load(load_path_format)
        # EmulationManager.Instance.Load()
        mach.sysbus.cpu.Resume()
        end_time = time.time()
        load_execution_time = end_time - start_time
        print(f"Load file execution time: {load_execution_time:.10f} seconds")
#         print("************file loaded")
#         mach = e.get_mach(mach_name)
#     # mach_new.sysbus.i2c1.ReadFromFuzzer(data)
#         mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)
#     # print(f"***Mach here : {mach_new}")
#         print(f"******PC : {mach.sysbus.cpu.PC}")
#         # Analyzer(mach.sysbus.uart0)  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#     # temp_data += 20
#     # # humidity_data += 20
#     # pressure_data += 20
#     # print(f"**** Temp :{mach_new.sysbus.twi0.bmp180.Temperature }")
#     # print(f"**** Pressure :{mach_new.sysbus.twi0.bmp180.UncompensatedPressure}")
#     # mach_new.sysbus.twi0.bmp180.Temperature = Decimal('77.0')
#     # mach_new.sysbus.twi0.bmp180.Temperature = temp_data
#     # mach_new.sysbus.twi0.bmp180.UncompensatedPressure = pressure_data
#         data[0] = random.getrandbits(8) #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#     # mach_new.sysbus.i2c1.ReadDoubleWord(0x00)
#     # print(f"start pc : {(mach_new.sysbus.cpu.PC)}")
#         print("^^^^^Resuming next run")
#         mach.sysbus.twi0.bmp180.ReadFromFuzzer(data) #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#         e.StartAll()

        while exit_flag == 0 :
            print(f"Waiting at : pc : {(mach.sysbus.cpu.PC)}")
        # pass

        if exit_flag == 1:
            exit_flag = 0
            print("**Reached exit******")
            mach.sysbus.cpu.Pause()
            # mach.Pause()

#         # input()
    
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


   




