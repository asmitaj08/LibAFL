import time
import pickle
from pyrenode3 import RPath
import System   # import sys
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import ICpuSupportingGdb
from Antmicro.Renode.PlatformDescription.UserInterface import PlatformDescriptionMachineExtensions

mach_name = "stm"
reach_target_flag = 0

e = Emulation()
m = Monitor()
mach = e.add_mach(mach_name)

load_str = """using "platforms/cpus/stm32l072.repl" bme280: I2C.BME280@ i2c1 0x76"""
PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)
mach.load_elf("https://dl.antmicro.com/projects/renode/b_l072z_lrwan1--zephyr-bme280_test.elf-s_649120-15b7607a51b50245f4500257c871cd754cfeca5a")

pc_main = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(pc_main)}")
target_func_calling_pc = pc_main

def capture_state(cpu):
    # Capture general-purpose registers
    print("Inside capture **")
    registers = {}
    for i in range(16):
        registers[f"R{i}"] = cpu.GetRegisterUnsafe(i).RawValue
    
    print("Registers captured")
    # Capture special registers
    pc = cpu.GetRegisterUnsafe(15).RawValue
    sp = cpu.GetRegisterUnsafe(13).RawValue
    print(f"****PC : {hex(pc)}, SP : {hex(sp)}")
    # Capture the stack (assuming a specific stack size for simplicity)
    stack_size = 0x100  # Adjust as needed
    stack_memory = cpu.Bus.ReadBytes(sp, stack_size)
    print("*******")
    # Save the captured state to a file
    state = {
        "PC": pc,
        "SP": sp,
        "Registers": registers,
        "Stack": list(stack_memory),
    }
    print("Writing to a pickle file now")
    with open("cpu_state.pkl", "wb") as f:
        pickle.dump(state, f)

    print("State saved")

    # # Print or save the captured state
    # print(f"PC: {pc}")
    # print(f"SP: {sp}")
    # print(f"Registers: {registers}")
    # print(f"Stack (first 16 bytes): {list(stack_memory)[:16]}")

    # # Optionally, save the state to a file
    # with open("cpu_state.txt", "w") as f:
    #     f.write(f"PC: {pc}\n")
    #     f.write(f"SP: {sp}\n")
    #     f.write(f"Registers: {registers}\n")
    #     f.write(f"Stack (first 16 bytes): {list(stack_memory)[:16]}\n")

def hook_addr_target(cpu,addr):
    global reach_target_flag
    mach.sysbus.cpu.Pause()
    capture_state(cpu)
    reach_target_flag = 1

Action3 = getattr(System, 'Action`2')
hook_action_target = Action3[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

Analyzer(mach.sysbus.usart2).Show()
e.StartAll()

while reach_target_flag == 0:
    pass
if reach_target_flag == 1:
    mach.sysbus.cpu.Pause()

print("Done")
input()