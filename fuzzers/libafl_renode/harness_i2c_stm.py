# Loads libafl_renode library
# calls the fuzzing_functions, to which it sends the callback function
# sets up renode , hooks, breakpoints
# does renode related stuff within the callback function which is sent to fuzzing function

import ctypes
import subprocess
import random
import time 
from pyrenode3 import RPath
import System  
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import TranslationCPUHooksExtensions
from Antmicro.Renode.Peripherals.CPU import RegisterValue
from Antmicro.Renode.Peripherals.CPU import ICpuSupportingGdb
from Antmicro.Renode.PlatformDescription.UserInterface import PlatformDescriptionMachineExtensions

libafl_renode_lib = ctypes.CDLL("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/target/release/liblibafl_renode.so")
input_dir = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/input_dir_i2c"

# callback to be called within LibAFL
# callback_function = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_size_t)
callback_function = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
# callback_function = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p)

# ***** setup_renode, currently hardcoded for mach uart
e = Emulation()
m = Monitor()
mach = e.add_mach("stm32")
load_str = """using "platforms/cpus/stm32l072.repl" bme280: I2C.BME280@ i2c1 0x76"""
PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)
mach.load_elf("https://dl.antmicro.com/projects/renode/b_l072z_lrwan1--zephyr-bme280_test.elf-s_649120-15b7607a51b50245f4500257c871cd754cfeca5a")

print("loaded")
sp_main=0
lr_main=0
pc_main = 0
sp_target =0
lr_target = 0
pc_target =0

target_func_name = "read_temperature"
# target_func_calling_pc = 0x92ec # address from where target_func is called
# target_func_lr = 0x143e # return address of target fun , this doesn't matter actually
# reach_goal_pc = 0x1456 # address after which code resumes to teh target func with ok
# exit_addr = 0x145a
reach_target_flag = 0
reach_goal_flag = 0
exit_flag = 0
pc_main = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(pc_main)}")
target_func_calling_pc = pc_main
def hook_addr_main(cpu, addr):
    # print(f"CPU Addr Hook **** : {hex(addr)}")
    global lr_main, sp_main
    sp_main = mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue  
    # pc_val = mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue
    lr_main = mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue
    print(f"Main : SP: {hex(sp_main)}, PC: {hex(addr)}, LR: {hex(lr_main)}")

def hook_addr_goal(cpu,addr):
    global reach_goal_flag
    reach_goal_flag = 1

def hook_addr_target(cpu,addr):
    global reach_target_flag,sp_target, lr_target, pc_target
    reach_target_flag = 1
    # pc_target = addr
    # sp_target = mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue  
    mach.sysbus.cpu.Pause()
    # pc_val = mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue
    # lr_target = mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue
    # print(f"**** Target  : SP: {hex(sp_target)}, PC: {hex(pc_target)}, LR: {hex(lr_target)}")

def hook_addr_exit(cpu,addr):
    global exit_flag,pc_target, lr_target,sp_target
    exit_flag = 1
    # print("****inside exit hook*****")
    # mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(target_func_calling_pc, 32))
    # mach.sysbus.cpu.SetRegisterUnsafe(14, RegisterValue.Create(target_func_lr, 32))
    # mach.sysbus.cpu.SetRegisterUnsafe(13, RegisterValue.Create(sp_target, 32))
    # print("****updated in exit condition")
    return 0
TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")

# CpuHooksExtensions.AddHook(mach.sysbus.cpu.internal, mach.internal,main_func_addr, "")
Action1 = getattr(System, 'Action`2')
hook_action_main = Action1[ICpuSupportingGdb, System.UInt64](hook_addr_main)

Action2 = getattr(System, 'Action`2')
hook_action_goal = Action2[ICpuSupportingGdb, System.UInt64](hook_addr_goal)

Action3 = getattr(System, 'Action`2')
hook_action_target = Action3[ICpuSupportingGdb, System.UInt64](hook_addr_target)

Action4 = getattr(System, 'Action`2')
hook_action_exit = Action4[ICpuSupportingGdb, System.UInt64](hook_addr_exit)

# mach.sysbus.cpu.AddHook(pc_main,hook_action_main)
# mach.sysbus.cpu.AddHook(reach_goal_pc,hook_action_goal)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)
Analyzer(mach.sysbus.usart2)
# m.execute("using sysbus")
e.StartAll()
# while reach_target_flag == 0 :
#     print("flag 0")
#     print(f"##### PC: {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}, {hex(mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue)}")

#     pass

print(f'Flag : {reach_target_flag}')
# reach_target_flag = 0
# print(f'Updated Flag : {reach_target_flag}')
# mach.sysbus.cpu.Reset()
# mach.sysbus.cpu.Pause()
mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
print('Removed target func Hook')
# mach.sysbus.cpu.AddHook(reach_goal_pc,hook_action_goal)
# mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)
print("Done initial setup")
def callback(data):
    global reach_goal_flag, exit_flag, mach,sp_target,lr_target
    # mach.sysbus.cpu.Reset()
    mach.sysbus.cpu.Pause()
    # print(f"mach : {mach}")
    mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(target_func_calling_pc, 32))
    # mach.sysbus.cpu.SetRegisterUnsafe(14, RegisterValue.Create(target_func_lr, 32))
    # mach.sysbus.cpu.SetRegisterUnsafe(14, RegisterValue.Create(lr_target, 32))
    # mach.sysbus.cpu.SetRegisterUnsafe(13, RegisterValue.Create(sp_target, 32))
    mach.sysbus.cpu.Resume()
    # # print("******resumed******")
    print(f'*****data : {data}, size :{len(data)}')
    if len(data)==0 :
        data=["40"]
    # elif data[0]==51 or data[0]==71 :
    #     print(f"*******Q here : {data[0]}")
    m.execute(f"i2c1.bme280 Temperature {data[0]}")
    m.execute(f"i2c1.bme280 Humidity {data[0]}")
    m.execute(f"i2c1.bme280 Pressure {data[0]}")
    # print(f"***data : {hex(data[0])}")
    # m.execute(f"sysbus.usart2 WriteChar {data[0]}")
    # m.execute(f"sysbus.uart0 WriteLine {data}")
    # m.execute(f"sysbus.uart0 WriteByte {data}")
    # print("******data sent******")
    # while reach_goal_flag==0:
    #     # print(f"******{reach_goal_flag}******")
    #     pass

    # # print("********Reached goal")
    # if exit_flag == 1 :
    #     # print("****exit flag **")
    #     mach.sysbus.cpu.Pause()
    #     # return 
    # # if reach_goal_flag == 1:
    # #     mach.sysbus.cpu.Pause()
    # #     reach_goal_flag=0
    # #     return 0
    # # else :
    # #     return 3
    # #     print("break**")
    # #     exit()
    # # print("******pausing")
    # mach.sysbus.cpu.Pause()
    # m.execute("Clear")
    # print("*******Exiting")
    return 0 

callback_ptr = callback_function(callback)
print("calling liabafl main_fuzzing_func")
libafl_renode_lib.main_fuzzing_func(ctypes.c_char_p(input_dir.encode('utf-8')),callback_ptr)

