import time
import pickle
from pyrenode3 import RPath
import System   # import sys
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import RegisterValue
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


def restore_state(cpu):
    # Load the state from the file
    print("inside restore_state")
    with open("cpu_state.pkl", "rb") as f:
        state = pickle.load(f)

    # Restore general-purpose registers
    for i in range(16):  # Assuming 16 general-purpose registers (R0-R15)
        register_value = RegisterValue(state["Registers"][f"R{i}"])
        cpu.SetRegisterUnsafe(i, register_value)
    
    print("loaded register")
    # Restore special registers (Program Counter and Stack Pointer)
    pc_value = RegisterValue(state["PC"])
    sp_value = RegisterValue(state["SP"])
    cpu.SetRegisterUnsafe("PC", pc_value)
    cpu.SetRegisterUnsafe("SP", sp_value)
    
    print("loaded sp, pc")
    # Restore the stack
    sp = state["SP"]
    stack_memory = state["Stack"]
    for i in range(len(stack_memory)):
        cpu.Bus.WriteByte(sp + i, stack_memory[i])

    print("State restored")


def hook_addr_target(cpu,addr):
    global reach_target_flag
    mach.sysbus.cpu.Pause()
    restore_state(cpu)
    reach_target_flag = 1

Action3 = getattr(System, 'Action`2')
hook_action_target = Action3[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

# restore_state(mach.sysbus.cpu)
Analyzer(mach.sysbus.usart2).Show()
e.StartAll()

while reach_target_flag == 0:
    pass
if reach_target_flag == 1:
    mach.sysbus.cpu.Pause()

print("Done")
input()