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
from Antmicro.Renode.Core import EmulationManager
from Antmicro.Renode.Utilities import ReadFilePath

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

faulthandler.enable()


target_event = threading.Event()
exit_event = threading.Event()

def signal_handler(sig, frame):
    # mach.sysbus.cpu.Fuzz_GetBlockCount() #use it when replaying to get blcok coverage
    # time.sleep(2)
    # mach.sysbus.cpu.Fuzz_ClearBlockSet() #use it when replaying to get blcok coverage
    # time.sleep(1)
    print(f"Received signal {sig}. Exiting ...")
    # sys.exit(0)
    os._exit(1)

signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C (Interrupt)
# signal.signal(signal.SIGTERM, signal_handler)  # Termination signal
# signal.signal(signal.SIGQUIT, signal_handler)

print("Signal handler setup done")

def file_to_byte_array(file_path):
    with open(file_path, 'rb') as file:  # 'rb' means read in binary mode
        byte_array = file.read()
    return byte_array

# libafl_renode_lib = ctypes.CDLL("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/target/release/liblibafl_renode.so")
# input_dir = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/input_dir_i2c"
# callback_function = ctypes.CFUNCTYPE(ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)

# multipart 
# Define a callback type that returns a uint8 and takes two uint8 pointers and two size_t values
# callback_function = ctypes.CFUNCTYPE(
#     ctypes.c_uint8,                             # Return type: uint8
#     ctypes.POINTER(ctypes.c_uint8),             # First data pointer: uint8*
#     ctypes.c_size_t,                            # Size of first array: size_t
#     ctypes.POINTER(ctypes.c_uint8),             # Second data pointer: uint8*
#     ctypes.c_size_t                             # Size of second array: size_t
# )

#Now passing input directly internally between libafl and renode 
# callback_function = ctypes.CFUNCTYPE(ctypes.c_uint8)

# libafl_renode_lib.main_fuzzing_func.argtypes = [ctypes.c_char_p, callback_function]
# libafl_renode_lib.main_fuzzing_func.restype = ctypes.c_uint8

mach_name = "drone_ByteIn"
print("*********Emulation()********")
e = Emulation()
print("*********Monitor()********")
m = Monitor()    # gives error if i comment it out, LoadPlatformDescription uses the machine provided by Monitor
print("*********mach add********")
mach = e.add_mach(mach_name)


# load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180_modified@ twi0 0x77"""
mach.load_repl("platforms/cpus/stm32f103_fuzz.repl")
# print("*********PlatformDescriptionMachineExtensions********")
# PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)

print("*********LoadElf********")
mach.load_elf("P2IM_Drone.elf")

# mach.sysbus.cpu.wfiAsNop = True
# mach.sysbus.cpu.wfeAndSevAsNop = True
# mach.sysbus.cpu.neverWaitForInterrupt = True

print("*********GetSymbolAddress********")
main_addr = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(main_addr)}")
# target_addr = main_addr
target_addr = mach.sysbus.GetSymbolAddress("Reset_Handler")
# target_addr = 0x08004198
print(f"Target func addr : {hex(target_addr)}")
target_func_calling_pc = target_addr

fault_addr1 = mach.sysbus.GetSymbolAddress("BusFault_Handler")
print(f"BusFault_Handler addr : {hex(fault_addr1)}")

fault_addr2 = mach.sysbus.GetSymbolAddress("UsageFault_Handler")
print(f"UsageFault_Handler addr : {hex(fault_addr2)}")

fault_addr3 = mach.sysbus.GetSymbolAddress("HardFault_Handler")
print(f"HardFault_Handler addr : {hex(fault_addr3)}")

fault_addr4 = mach.sysbus.GetSymbolAddress("_Error_Handler")
print(f"_Error_Handler addr : {hex(fault_addr4)}")

fault_addr5 = mach.sysbus.GetSymbolAddress("HAL_UART_ErrorCallback")
print(f"HAL_UART_ErrorCallback addr : {hex(fault_addr5)}")

log_file_path = "log_drone.log" # this gets saved in renode dir
trace_file_path = "trace_drone" # this one in libafl_renode dir

state_file= "statefile_new.dat"


ret_val = 2
exit_addr = 0x080041a0  # this will change depending on target
fault_flag = 0
# exit_addr = 0x080043e4
# fault_addr = 0x2ec
# final_exit_addr = 0x3b78

def hook_addr_target(cpu,addr):
    print("************In target hook")
    mach.Pause() 
    # mach.sysbus.ram.Fuzz_Mem_Save()   # memory
    # mach.sysbus.cpu.Fuzz_PrepareState() # cpu state
    # EmulationManager.Instance.Save(state_file)
    target_event.set()
    print("************Done target hook")

def hook_addr_exit(cpu,addr):
    print(f"***** Exit addr ******* : {hex(addr)}")
    global ret_val
    mach.Pause()
    # mach.sysbus.cpu.DisableExecutionTracing() 
    ret_val = 0
    exit_event.set()  # Signal the exit event

def hook_addr_faults(cpu,addr):
    global fault_flag
    mach.Pause()
    fault_flag = 1
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
mach.sysbus.cpu.AddHook(fault_addr5,hook_action_fault)


def hook_in_exhaust_exit():
    print(f"***** Exit addr fuzzer input exhaust******* ")
    global ret_val
    mach.Pause()
    # mach.sysbus.cpu.DisableExecutionTracing() 
    ret_val = 0
    exit_event.set()  # Signal the exit event
hook_action_exit_in_exhaust = System.Action(hook_in_exhaust_exit)
mach.sysbus.i2c1.SetHookAfterFuzzInputExhaust_I2C(hook_action_exit_in_exhaust)

# mach.sysbus.cpu.zeroOutCovMap()
# # TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")
# mach.sysbus.cpu.Fuzz_SetHookAtBlockBegin()
# mach.sysbus.cpu.LogCpuInterrupts(True)

# m.execute("logFile @" + log_file_path)
# mach.sysbus.cpu.LogFunctionNames(True)

# Analyzer(mach.sysbus.usart1).Show()

## MIPS val : 2 and 1 & Cov : timeout error
# 3 : Block_count:1167, edge_count : 1819, indexHash : 1685
# 4 : Block_count:1019, edge_count : 1567, indexHash : 1481
# 6 : Block_count:1019, edge_count : 1507, indexHash : 1419
# 8 : Block_count:919, edge_count : 1350, indexHash : 1291
# 10 : Block_count:898, edge_count : 1290, indexHash : 1240 
# 60 : Block_count:805, edge_count : 1093, indexHash : 1060
# 100 (this is default in renode): Block_count:710, edge_count : 960, indexHash : 935
# 120 : Block_count:712, edge_count : 964, indexHash : 939
# 140 : Block_count:613, edge_count : 801, indexHash : 782
# 1000 : Block_count:440, edge_count : 562, indexHash : 551
mach.sysbus.cpu.PerformanceInMips = 100 # changing this changes the coverage (We get more blocks when this val is 10 compared to 100), it can also impact fuzzer perf
print("******Hook settings done")
mach.fuzz_init_settings() #*****important
mach.ConfigurePeripheralsToReset(["cpu","nvic","flash_ctrl","timer2","timer3","timer4","usart1","i2c1"])
print("******Starting the emulator")

i=0
# mach.sysbus.cpu.LogCpuInterrupts(True)
# mach.sysbus.cpu.CreateExecutionTracing("", f"{trace_file_path}_{i}", TraceFormat.PC)
e.StartAll()

if target_event.wait(timeout=2):
    print("Target event triggered.")
    target_event.clear()
else:
    raise RuntimeError("Error: Timeout waiting for Target event.")

mach.Pause()
# mach.sysbus.cpu.DisableExecutionTracing()
mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
# EmulationManager.Instance.Save(state_file)
# print(f"Save command executed: Save @{state_file}")
mach.sysbus.cpu.CountNonZeroElements_COVMAP()
# mach.sysbus.cpu.Fuzz_GetEdges(i)
# mach.sysbus.cpu.Fuzz_GetBlockCount(i) # for this make sure to enable add block in renode's TranslationCPU.cs
# # mach.sysbus.cpu.Fuzz_GetBlockEndCount(i)
# mach.sysbus.cpu.zeroOutCovMap()
# mach.sysbus.cpu.Fuzz_ClearSets()
# # TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")
mach.sysbus.cpu.Fuzz_SetHookAtBlockBegin()

# load_path_format = ReadFilePath(state_file)


# mach.sysbus.LogAllPeripheralsAccess(True)
# mach.sysbus.cpu.neverWaitForInterrupt = True
print("Done initial setup")
# mach.sysbus.cpu.Fuzz_GetBlockCount() # only when replaying
data = [0xff]*200

dir_path = "queue_dir"
# filepath = "queue_dir/00997fc470afea6e"
#For replaying
# for filename in os.listdir(dir_path): #for replaying
#     if filename.startswith('.'):
#         continue
#     filepath = os.path.join(dir_path, filename)
#     print(f"filepath : {filepath}")
#     if os.path.isfile(filepath):
#         mach.sysbus.i2c1.ReadFromFuzzer_PY_i2c(bytearray(file_to_byte_array(filepath)))
#         mach.sysbus.usart1.ReadFromFuzzer_PY_uart(bytearray(file_to_byte_array(filepath)))

while i<5: # clibafl_renode_lib = ctypes.CDLL("liblibafl_renode.so")omment this when replaying
# while True:
    try:
        print("^^^^^ Loop starting")
        i+=1
        
        # global ret_val,i
        # for snapshot based fuzzer, i.e. run from any specific function, we need both Mem_Load and LoadState, 
        # Else run directly from reset handler as in othe papers using cpu.Reset() 
        # mach.sysbus.ram.Fuzz_Mem_Load() # for snapshot # As firmware always run in while loop(), reload maybe only after error or timeout occurs?? - no we need to be in same mem state 
        # mach.sysbus.cpu.Fuzz_LoadState()
        mach.FuzzReset() 
        mach.sysbus.i2c1.ReadFromFuzzer_PY(data)
        #     
        # mach.sysbus.cpu.Reset() #when load from resetHandler
        # print("^^^^^ Loop cpu.Reset Done")
        # # mach.sysbus.nvic.Reset() // added in cpu.reset in cortexM.cs
        # # print("^^^^^ Loop nvic.Reset Done")
        # # mach.sysbus.rcc.Reset()
        # mach.sysbus.flash_ctrl.Reset()
        # print("^^^^^ Loop flash_ctrl.Reset Done")
        # mach.sysbus.timer2.Reset()
        # print("^^^^^ Loop timer2.Reset Done")
        # mach.sysbus.timer3.Reset()
        # print("^^^^^ Loop timer3.Reset Done")
        # mach.sysbus.timer4.Reset()
        # print("^^^^^ Loop timer4.Reset Done")
        # mach.sysbus.cpu.LogCpuInterrupts(True)
        # print(f"^^^^^neverWaitForInterrupt : {mach.sysbus.cpu.neverWaitForInterrupt}, wfiAsNop : {mach.sysbus.cpu.wfiAsNop},wfeAndSevAsNop : {mach.sysbus.cpu.wfeAndSevAsNop}")

        # mach.sysbus.exti.Reset()
        # mach.sysbus.bitbandPeripherals.Reset()
        # mach.sysbus.usart1.Reset()
        # mach.sysbus.gpioPortA.Reset()
        # mach.sysbus.gpioPortB.Reset()
        # mach.sysbus.gpioPortC.Reset()
        # mach.sysbus.gpioPortD.Reset()
        # mach.sysbus.gpioPortE.Reset()
        # mach.sysbus.gpioPortF.Reset()
        # mach.sysbus.gpioPortG.Reset()
        # mach.sysbus.ram.Reset()
        # mach.sysbus.timer1.Reset()
        
        # mach.sysbus.cpu.LogCpuInterrupts(True)
        # mach.sysbus.cpu.Fuzz_SetHookAtBlockBegin()

        # Convert the raw pointer into a usable Python byte array
        # data_array = ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte * length)).contents
        # Convert to a Python list or bytes 
        # byte_data = bytes(data_array)
        # i+=1
        # print(f"^^^^^ data1[0] : {data1[0]}, length1 : {length1},data2[0] : {data2[0]}, length2 : {length2}")
        # byte_data_i2c = bytearray(data1[i] for i in range(length1))
        # mach.sysbus.i2c1.ReadFromFuzzer_i2c(byte_data_i2c)   #rather pass it vai share mem between renode & LibAFL
        # mach.sysbus.cpu.CreateExecutionTracing("", f"{trace_file_path}_resumed_{i}", TraceFormat.PC) # make sure trace_file is new file, else it will give error if it already exists
        mach.Resume()
        # mach.sysbus.cpu.Reset()
        # mach.Resume()
        # mach.Start()
        # Wait until the exit_event is set
        # Reset the event for the next iteration
        if exit_event.wait(timeout=5):
            # print(f"Exit event triggered.Pc : {mach.sysbus.cpu.PC}")
            # mach.sysbus.cpu.DisableExecutionTracing()
            mach.Pause()
            # mach.sysbus.cpu.DisableExecutionTracing()
            mach.sysbus.cpu.CountNonZeroElements_COVMAP()
            # mach.sysbus.cpu.Fuzz_GetEdgesCount()
            mach.sysbus.cpu.Fuzz_GetBlockCount()
            # mach.sysbus.cpu.Fuzz_GetEdges(i)
            # mach.sysbus.cpu.Fuzz_GetBlockCount(i) # for this make sure to enable add block in renode's TranslationCPU.cs
            # mach.sysbus.cpu.Fuzz_GetBlockEndCount(i)
            # mach.sysbus.cpu.zeroOutCovMap()
            # mach.sysbus.cpu.Fuzz_ClearSets()
            exit_event.clear()
        else:
            if fault_flag==0 :
                ret_val = 2 # timeout
            else :
                ret_val = 5 #fault crashes
                fault_flag = 0
            # ret_val = 2
            # mach.sysbus.cpu.DisableExecutionTracing()
            mach.Pause()
            # mach.sysbus.cpu.zeroOutCovMap()
            # mach.sysbus.cpu.Fuzz_ClearSets()
            # mach.sysbus.ram.Fuzz_Mem_Load() # As firmware always run in while loop(), reload maybe only after error or timeout occurs??
            # mach.sysbus.cpu.Fuzz_LoadState()
            print("^^^^^^^^^ Error: Timeout/Crash waiting for Exit event.")
            # mach.sysbus.ram.Fuzz_Mem_Load()
            # mach.sysbus.cpu.Fuzz_LoadState()
        
        # mach.Pause() // doing it inside exit hook
        # if i>=100:
        #     ret_val=22
        print(f"In python res :, normal : {ret_val}")
        # time.sleep(1)
        # return ret_val
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
             


# def list_child_processes():
#     parent = psutil.Process(os.getpid())
#     return [p.pid for p in parent.children(recursive=True)]

# # Check child processes before
# print("Processes before:", list_child_processes())
# def list_threads():
#     return [t.name for t in threading.enumerate()]

# # Check active threads before
# print("Threads before calling LibAFL:", list_threads())

# assert input_dir is not None, "Error: Input directory is None"

# try:
#     callback_ptr = callback_function(callback)
#     print("calling liabafl main_fuzzing_func------")
#     libafl_renode_lib.main_fuzzing_func(ctypes.c_char_p(input_dir.encode('utf-8')),callback_ptr)
# except Exception as e:
#     print(f"\nException occurred: {e}")
#     sys.exit(1)

