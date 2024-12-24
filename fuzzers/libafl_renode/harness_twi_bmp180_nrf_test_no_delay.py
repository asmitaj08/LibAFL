# !/usr/bin/env -S python3 -m bpython -i

import sys
# sys.path.append("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/pyrenode3/src/")

import time
import timeit
from pyrenode3 import RPath
import System   # import sys
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import TranslationCPUHooksExtensions
from Antmicro.Renode.Peripherals.CPU import RegisterValue
from Antmicro.Renode.Peripherals.CPU import ICpuSupportingGdb
# from Antmicro.Renode.Peripherals.CPU import ExecutionTracer
# from Antmicro.Renode.Peripherals.CPU import ExecutionTracerExtensions
from Antmicro.Renode.PlatformDescription.UserInterface import PlatformDescriptionMachineExtensions
# from Antmicro.Renode.Core import EmulationManager # src/Infrastructure/src/Emulator/Main/Core/EmulationManager.cs
# from Antmicro.Renode.Utilities import ConfigurationManager
# from Antmicro.Renode.Utilities import ReadFilePath
# from Antmicro.Renode.Peripherals.CPU import TranslationCPU
from Antmicro.Renode.Peripherals.CPU import TraceFormat
# from Antmicro.Renode.Time import TimeInterval
# from Antmicro.Renode.Peripherals.Memory import MappedMemory

from decimal import Decimal
import random
import cProfile

import signal
import pstats
import io
import os


# sp_main = 0
# lr_main = 0
# pc_main = 0
mach_name = "nrf"
e = Emulation()
m = Monitor()    # gives error if i comment it out, LoadPlatformDescription uses the machine provided by Monitor
mach = e.add_mach(mach_name)

# state_file= "statefile_bmp180_nrf_test_no_delay.dat"
# trace_file_path = "trace_bmp180_nrf_test_no_delay"
# log_file_path = "log_bmp180_nrf_test_no_delay.log"
# snapshot_path = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/snapshot_bmp180_nrf_test_no_delay"

temp_data = 60
# humidity_data = 88
pressure_data = 1200

exit_flag = 0
delay_flag = 0
reach_target_flag = 0
# exit_addr = 0x296  
exit_addr = 0x3102
# restore_pc = 0x0800353a
# restore_sp = 0x20001040
# load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180@ twi0 0x77"""
load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180_modified@ twi0 0x77"""
PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)
# mach.load_elf("https://dl.antmicro.com/projects/renode/BMP180_I2C.ino.arduino.mbed.nano33ble.elf-s_3127076-ba5f49cd34cd9549c2aa44f83af8e2011ecd1c22")
mach.load_elf("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/nrf_bmp180_drv1_no_delay.out")

# pc_main = mach.sysbus.GetSymbolAddress("main")
pc_main = mach.sysbus.GetSymbolAddress("Reset_Handler")

print(f"Main func addr : {hex(pc_main)}")
target_func_calling_pc = pc_main


def hook_addr_target(cpu,addr):
    global reach_target_flag
    # pc_target = mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue
    # sp_target = mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue 
    # lr_target = mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue 
    # cpacr_target = mach.sysbus.cpu.GetRegisterUnsafe(27).RawValue 
    # mach.sysbus.cpu.Pause()
    # mach.sysbus.cpu.DisableExecutionTracing()
    print("************In target hook")
    # mach.Pause()
    # mach.sysbus.cpu.Reset()
    # e.SnapshotTracker.Save(TimeInterval.FromMilliseconds(100),snapshot_path)
    # mach.sysbus.cpu.Fuzz_PrepareState() # cpu state
    # mach.sysbus.ram.Fuzz_Mem_Save()   # memory
    reach_target_flag = 1
    # print(f"----Reg at Pause in hook : {hex(lr_target)}, {hex(sp_target)}, {hex(pc_target)}, {hex(cpacr_target)}")
    print("Target Hook task done")

def hook_addr_exit(cpu,addr):
    global exit_flag
    exit_flag = 1
    print(f"***** Exit addr ******* : {hex(addr)}")

Action1 = getattr(System, 'Action`2')
hook_action_target = Action1[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

# Action2 = getattr(System, 'Action`2')
# hook_action_exit = Action2[ICpuSupportingGdb, System.UInt64](hook_addr_exit)
# mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)

TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")

# ExecutionTracer.Start(mach.sysbus.cpu.internal)
# ExecutionTracerExtensions.CreateExecutionTracing(mach.sysbus.cpu.internal,trace_file_path)

# if os.path.exists(trace_file_path):
#     os.remove(trace_file_path)

# mach.sysbus.cpu.CreateExecutionTracing("", trace_file_path, TraceFormat.Disassembly) # ******
# m.execute("logLevel -1")
# m.execute("logFile @" + log_file_path)
Analyzer(mach.sysbus.uart0).Show()
print("******Starting the emulator")
e.StartAll()
# m.execute("logFile @" + log_file_path)
while reach_target_flag == 0: # wait until target is reached
    # print("Target not reached yet")
    pass
    
if reach_target_flag == 1:
    print("Target flag reached...")
    # try:
        
        # mach.Pause()
        # mach.sysbus.cpu.Pause()
    # mach.sysbus.cpu.DisableExecutionTracing()
    mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
    
        # e.SnapshotTracker.Save(TimeInterval.FromMilliseconds(100),snapshot_path)
        # mach.sysbus.cpu.RemoveHooksAt(exit_addr)
        # EmulationManager.Instance.Save(state_file)
        # EmulationManager.Instance.Save()
        # print(f"Save command executed")
        # print(f"-------Reg after flag set : SP : {hex(mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue)}, PC : {mach.sysbus.cpu.PC}")
        # print(f"Save command executed: Save @{state_file}")
        # mach.sysbus.cpu.DisableExecutionTracing()
        # m.execute("Clear")
        # mach.sysbus.cpu.testStatePtr()
        # mach.sysbus.cpu.testPrepareState()
       

    # except Exception as e:
    #      print(f"Error executing save command: {e}")
    # print("reached flag")

# load_path_format = ReadFilePath(state_file)
print("Done initial setup")
data = [0x44]
count = 1

# print(e.SnapshotTracker.GetLastSnapshotBeforeOrAtTimeStamp(TimeInterval.FromMilliseconds(100)))
# print(f"**** Snapshot Info : {e.SnapshotTracker.PrintSnapshotsInfo()}")

# print(f"**** Snapshot detailed info : {e.SnapshotTracker.PrintDetailedSnapshotsInfo()}")

# mach.sysbus.cpu.DisableExecutionTracing()
# print("Done")
# mach.sysbus.cpu.LogFunctionNames(False)

# pr = cProfile.Profile()
# pr.enable()
# try :
i=0
while count:
        # global exit_flag
        # exit_flag = 0
        # i+=1
#     # count += 1
        print("***************Loading the saved states...")
        # print(f"---- Reg before load : SP : {hex(mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue)}, PC : {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
        start_time = time.time()
        # EmulationManager.Instance.Load(load_path_format)
        # EmulationManager.Instance.Load()
        # mach = e.get_mach(mach_name)

        # mach.sysbus.WriteDoubleWord(0x2d8,0x00004F88)
        # mach.sysbus.WriteDoubleWord(0x2dc,0x20000000)
        # mach.sysbus.WriteDoubleWord(0x2e0,0x200000C0)
        # mach.sysbus.WriteDoubleWord(0x29c,0x00080000)
        # mach.sysbus.WriteDoubleWord(0x2a0,0x00000000)
        # mach.sysbus.WriteDoubleWord(0x2a4,0x00000000)
        # mach.sysbus.WriteDoubleWord(0x2a8,0x20040000)
        # mach.sysbus.WriteDoubleWord(0x2ac,0x200000C0)
        # mach.sysbus.WriteDoubleWord(0x2b0,0x2004076C)
        # mach.sysbus.WriteDoubleWord(0x2b4,0x00000000)
        # mach.sysbus.WriteDoubleWord(0x2b8,0x00000000)

        # mach.sysbus.ram.Fuzz_Mem_Load() # mem
        # print(f"reg read** : {hex(mach.sysbus.ReadDoubleWord(0x2d8))}")
        # mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(target_func_calling_pc, 32))
        # mach.sysbus.cpu.SetRegisterUnsafe(14, RegisterValue.Create(0x0, 32))
        # mach.sysbus.cpu.SetRegisterUnsafe(13, RegisterValue.Create(main_sp_addr, 32))
        # mach.sysbus.cpu.SetRegisterUnsafe(27, RegisterValue.Create(0x0, 32))

        # mach.sysbus.ram.Fuzz_Mem_Load() # mem , these two takes about 0.5 seconds
        # mach.sysbus.cpu.Fuzz_LoadState()
        
        # print(f"---- Reg before resume : SP : {hex(mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue)}, PC : {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
        # mach.sysbus.cpu.Resume()
        # mach.sysbus.cpu.CreateExecutionTracing("", f"{trace_file_path}_resumed_{i}", TraceFormat.Disassembly) # make sure trace_file is new file, else it will give error if it already exists
        # mach.Pause()
        # mach.sysbus.cpu.Pause()
        mach.sysbus.cpu.Reset() # with this total time is about 0.4 seconds, almost same as cpu state load, and mem load
        # mach.sysbus.cpu.Resume()
        # mach.sysbus.cpu.Fuzz_Reset() # **** this also takes almost similar i.e. 0.4 
        # mach.sysbus.cpu.Fuzz_Resume() # these are also slower , this might not worked, I did some changes
        mach.Resume() #not sure why , but this works faster than mach.sysbus.cpu.Resume() ; but either of these work fine!
        # print(f"---Reg after resume : SP : {hex(mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue)}, PC : {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
        

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
    #   mach.sysbus.twi0.bmp180.Temperature = temp_data
    #   mach.sysbus.twi0.bmp180.UncompensatedPressure = pressure_data
#         data[0] = random.getrandbits(8) #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#     # mach_new.sysbus.i2c1.ReadDoubleWord(0x00)
#     # print(f"start pc : {(mach_new.sysbus.cpu.PC)}")
#         print("^^^^^Resuming next run")
#         mach.sysbus.twi0.bmp180.ReadFromFuzzer(data) #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#         e.StartAll()
        # test = 0
        mach.sysbus.twi0.bmp180.ReadFromFuzzer(data)
        end_time = time.time()
        load_execution_time = end_time - start_time
        print(f"Load file execution time: {load_execution_time:.10f} seconds")
        # while exit_flag == 0 :
        #     # print(f"Waiting at : pc : {hex(mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue)}, {hex(mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue)},{hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
        #     # if(flag==2):
        #     #      print("Disabling--trace")
        #     #      mach.sysbus.cpu.DisableExecutionTracing()
        #     #      flag=0
        #     # test+=1
        #     # if(test==10):
        #     #     #  mach.sysbus.cpu.Pause()
        #     #      mach.Pause()
        #     #      print(f"**Test 10****** : pc : {(mach.sysbus.cpu.PC)}, {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
        #     #      break
        #     print("Waiting!")
        # pass

        # if exit_flag == 1:
        #     exit_flag = 0
        #     # mach.Pause()
        #     mach.sysbus.cpu.Reset()
        #     # mach.sysbus.cpu.DisableExecutionTracing()
        #     print("**Reached exit******")
           

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







