# !/usr/bin/env -S python3 -m bpython -i
import time
import timeit
import ctypes
from pyrenode3 import RPath
import System   # import sys
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import TranslationCPUHooksExtensions
from Antmicro.Renode.Peripherals.CPU import RegisterValue
from Antmicro.Renode.Peripherals.CPU import ICpuSupportingGdb
from Antmicro.Renode.PlatformDescription.UserInterface import PlatformDescriptionMachineExtensions
from Antmicro.Renode.Core import EmulationManager # src/Infrastructure/src/Emulator/Main/Core/EmulationManager.cs
from Antmicro.Renode.Utilities import ConfigurationManager
from Antmicro.Renode.Utilities import ReadFilePath
import cProfile
import sys
import signal

sp_main=0
lr_main=0
pc_main = 0
mach_name = "nrf"
e = Emulation()
m = Monitor() # gives error if i comment it out, LoadPlatformDescription uses the machine provided by Monitor
mach = e.add_mach(mach_name)

# state_file= "statefile_bmp180_nrf.dat"
# state_file= "statefile_bmp180_nrf_no_delay.dat"

libafl_renode_lib = ctypes.CDLL("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/target/release/liblibafl_renode.so")
input_dir = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/input_dir_i2c"
callback_function = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
# callback_function = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))

# temp_data = 60
# humidity_data = 88
# pressure_data = 1200

exit_flag = 0
reach_target_flag = 0

# exit_addr = 0x3102
exit_addr = 0x296 
# load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180@ twi0 0x77"""
load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180_modified@ twi0 0x77"""
PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)
# mach.load_elf("https://dl.antmicro.com/projects/renode/BMP180_I2C.ino.arduino.mbed.nano33ble.elf-s_3127076-ba5f49cd34cd9549c2aa44f83af8e2011ecd1c22")
# mach.load_elf("nrf_bmp180_drv1.out") 
mach.load_elf("nrf_bmp180_drv1_no_delay.out")
pc_main = mach.sysbus.GetSymbolAddress("Reset_Handler")
# pc_main = mach.sysbus.GetSymbolAddress("main")
print(f"Target func addr : {hex(pc_main)}")
target_func_calling_pc = pc_main

def hook_addr_target(cpu,addr):
    global reach_target_flag
    # mach.Pause() # Machine gets auto paused in Hook
    print("** In Target Hook ....")
    mach.sysbus.cpu.Fuzz_PrepareState() # cpu state
    mach.sysbus.ram.Fuzz_Mem_Save()   # memory
    
    # mach.sysbus.cpu.Reset()
    reach_target_flag = 1
    print("**Target Hook task done")

def hook_addr_exit(cpu,addr):
    global exit_flag
    exit_flag = 1
    # print(f"***** Exit addr ******* : {hex(addr)}")


Action1 = getattr(System, 'Action`2')
hook_action_target = Action1[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

# Action2 = getattr(System, 'Action`2')
# hook_action_exit = Action2[ICpuSupportingGdb, System.UInt64](hook_addr_exit)
# mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)

TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")
# mach.sysbus.cpu.SetHookAtBlockBegin("") # this way some issue with python script passing

# Analyzer(mach.sysbus.uart0).Show()
# print("******Starting the emulator")
e.StartAll()

while reach_target_flag == 0:
    pass
if reach_target_flag == 1:
    # reach_target_flag = 0
    print("Target flag reached...")
    mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
    print("** Removed the Hook")
    

        

print("Done initial setup")

# MAX_SIZE = 1024
data_h = [0x44]

# @profile
def callback(data) :
    try :
        global exit_flag
    # # Convert the raw pointer to a Python byte array (limit to MAX_SIZE to avoid large buffers)
    # data_in_bytes = ctypes.string_at(data, MAX_SIZE)
    #  # Find the length based on actual data (adjust to your use case if a termination condition exists)
    # actual_size = len(data_in_bytes)  
    # # Convert bytes to a ctypes array to pass to C#
    # byte_array = (ctypes.c_ubyte * actual_size).from_buffer_copy(data_in_bytes[:actual_size])

    # print("^^^^^^^^ Loading the saved file")
    # start_time = time.time()
        # EmulationManager.Instance.Load(load_path_format)
    # end_time = time.time()
    # load_execution_time = end_time - start_time
    # print(f"Execution time for the line: {load_execution_time:.10f} seconds")
    # print("^^^^^ file loaded")
        # mach.sysbus.ram.Fuzz_Mem_Load() # mem # more scope of improvement to reduce time
        # mach.sysbus.cpu.Fuzz_LoadState() # more scope of improvement to reduce time
        mach.sysbus.cpu.Reset()
        # mach.sysbus.cpu.Fuzz_Reset()  # performs almost simialr as mach.sysbus.cpu.Reset
        if len(data)==0 :
            data=[0x20]
        mach.Resume()
    # data_in_bytes = bytes(data, 'utf-8')  # Convert string to bytes
    # print(f"^^^^^ Data : {data}")CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
        # mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)
    # print(f"***Mach here : {mach_new}")
    # print(f"******PC : {mach_new.sysbus.cpu.PC}")
    # Analyzer(mach_new.sysbus.usart2).Show()
        # Analyzer(mach.sysbus.uart0)
    # print(f"start pc : {(mach_new.sysbus.cpu.PC)}")
    # print("^^^^^Resuming next run")
        mach.sysbus.twi0.bmp180.ReadFromFuzzer(data)
        # mach.Pause()
        # while exit_flag == 0 :
        #     # print(f"Waiting at current pc : {(mach.sysbus.cpu.PC)}")
        #     pass
    
        # if exit_flag == 1:
        #     exit_flag = 0
        #     # mach.Pause()
        #     mach.sysbus.cpu.Reset()

    except Exception as e:
        print(f"Exception in callback: {e}")
        return 0  # Return a default value or handle the error
        # print(f"end pc : {(mach_new.sysbus.cpu.PC)}")
    # time.sleep(1)
    # e.clear()

# profiler = cProfile.Profile()
# profiler.enable()  # Start profiling

# Define a function to handle graceful exit
def signal_handler(sig, frame):
    print("\nExiting gracefully...")
    sys.exit(0)

# Register the signal handler for keyboard interrupt
signal.signal(signal.SIGINT, signal_handler)

try:
    callback_ptr = callback_function(callback)
    print("calling liabafl main_fuzzing_func")
    libafl_renode_lib.main_fuzzing_func(ctypes.c_char_p(input_dir.encode('utf-8')),callback_ptr)
except Exception as e:
    print(f"\nException occurred: {e}")
    sys.exit(1)


