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
from Antmicro.Renode.Peripherals.I2C import BME280 # src/Infrastructure/src/Emulator/Peripherals/Peripherals/I2C/BME280.cs
from Antmicro.Renode.Core import EmulationManager # src/Infrastructure/src/Emulator/Main/Core/EmulationManager.cs
from Antmicro.Renode.Utilities import ConfigurationManager
from Antmicro.Renode.Utilities import ReadFilePath

sp_main=0
lr_main=0
pc_main = 0
mach_name = "stm"
e = Emulation()
m = Monitor()
mach = e.add_mach(mach_name)

state_file= "statefile_bme280_stm_new.dat"

libafl_renode_lib = ctypes.CDLL("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/target/release/liblibafl_renode.so")
input_dir = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/input_dir_i2c"
callback_function = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
# callback_function = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))

temp_data = 60
humidity_data = 88
pressure_data = 1200

exit_flag = 0
reach_target_flag = 0
exit_addr = 0x08003544
# restore_pc = 0x0800353a
# restore_sp = 0x20001040
load_str = """using "platforms/cpus/stm32l072.repl" bme280: I2C.BME280_modified@ i2c1 0x76"""
# load_str = """using "platforms/cpus/stm32l072.repl" bme280: I2C.BME280@ i2c1 0x76"""
# load_str = """using "platforms/cpus/stm32l072_modified.repl" bme280: I2C.BME280@ i2c1 0x76"""
PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)
# mach.load_repl("platforms/cpus/stm32l072.repl")
# mach.load_repl("platforms/cpus/stm32l072_modified.repl")
mach.load_elf("https://dl.antmicro.com/projects/renode/b_l072z_lrwan1--zephyr-bme280_test.elf-s_649120-15b7607a51b50245f4500257c871cd754cfeca5a")

pc_main = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(pc_main)}")
target_func_calling_pc = pc_main

def hook_addr_target(cpu,addr):
    global reach_target_flag
    # pc_target = addr
    # sp_target = mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue  
    mach.sysbus.cpu.Pause()
    reach_target_flag = 1
    print("**Target Hook task done")

def hook_addr_exit(cpu,addr):
    global exit_flag
    exit_flag = 1
    print(f"***** Exit addr ******* : {hex(addr)}")

Action3 = getattr(System, 'Action`2')
hook_action_target = Action3[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

Action4 = getattr(System, 'Action`2')
hook_action_exit = Action4[ICpuSupportingGdb, System.UInt64](hook_addr_exit)

TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")

Analyzer(mach.sysbus.usart2).Show()
e.StartAll()

while reach_target_flag == 0:
    pass
if reach_target_flag == 1:
    try:
        mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
        EmulationManager.Instance.Save(state_file)
        print(f"Save command executed: Save @{state_file}")
    except Exception as e:
         print(f"Error executing save command: {e}")
    print("reached flag")

load_path_format = ReadFilePath(state_file)
print("Done initial setup")

# MAX_SIZE = 1024
data_h = [0x44,0x44]
def callback(data) :
    global exit_flag,e
    # # Convert the raw pointer to a Python byte array (limit to MAX_SIZE to avoid large buffers)
    # data_in_bytes = ctypes.string_at(data, MAX_SIZE)
    #  # Find the length based on actual data (adjust to your use case if a termination condition exists)
    # actual_size = len(data_in_bytes)  
    # # Convert bytes to a ctypes array to pass to C#
    # byte_array = (ctypes.c_ubyte * actual_size).from_buffer_copy(data_in_bytes[:actual_size])

    # print("^^^^^^^^ Loading the saved file")
    # start_time = time.time()
    EmulationManager.Instance.Load(load_path_format)
    # end_time = time.time()
    # load_execution_time = end_time - start_time
    # print(f"Execution time for the line: {load_execution_time:.10f} seconds")
    # print("^^^^^ file loaded")
    mach_new = e.get_mach(mach_name)
    if len(data)==0 :
        data=[0x20]
    # data_in_bytes = bytes(data, 'utf-8')  # Convert string to bytes
    # print(f"^^^^^ Data : {data}")CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
    # mach_new.sysbus.i2c1.ReadFromFuzzer(data)
    mach_new.sysbus.cpu.AddHook(exit_addr,hook_action_exit)
    # print(f"***Mach here : {mach_new}")
    # print(f"******PC : {mach_new.sysbus.cpu.PC}")
    # if len(data)==0 :
    #     data=[0x20]
    # Analyzer(mach_new.sysbus.usart2).Show()
    Analyzer(mach_new.sysbus.usart2)
    # temp_data += 20
    # humidity_data += 20
    # pressure_data += 20
    # mach_new.sysbus.i2c1.bme280.Temperature = data[0]
    # mach_new.sysbus.i2c1.bme280.Humidity = data[0]
    # mach_new.sysbus.i2c1.bme280.Pressure = data[0]
    # mach_new.sysbus.i2c1.bme280.ReadFromFuzzer(data_h)
    mach_new.sysbus.i2c1.bme280.ReadFromFuzzer(data)
    print(f"start pc : {hex(mach_new.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
    print("^^^^^Resuming next run")
    e.StartAll()
    # print(f"starting new run: Temp : {mach.sysbus.i2c1.bme280.Temperature}, Hum : {mach.sysbus.i2c1.bme280.Humidity}, Pres : {mach.sysbus.i2c1.bme280.Pressure}")
    # print(f"Reg set to : pc : {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}, sp : {hex(mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue)}, lr : {hex(mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue)}")
    print(f"Reg set to : pc : {hex(mach_new.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
    # mach.sysbus.cpu.Resume()
    # while exit_flag == 0 :
    #     # print("wait")
    #     # print(f"Waiting at : pc : {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
    #     print(f"current pc : {hex(mach_new.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
    #     pass
    
    if exit_flag == 1:
        exit_flag = 0
        print(f"end pc : {hex(mach_new.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
    # time.sleep(1)
    # e.clear()

callback_ptr = callback_function(callback)
print("calling liabafl main_fuzzing_func")
libafl_renode_lib.main_fuzzing_func(ctypes.c_char_p(input_dir.encode('utf-8')),callback_ptr)


