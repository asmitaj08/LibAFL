import time
import threading
from pyrenode3 import RPath
import System   # import sys
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import ICpuSupportingGdb
from Antmicro.Renode.Core import EmulationManager
from Antmicro.Renode.Exceptions import RecoverableException
# from Antmicro.Renode.Utilities import ConfigurationManager
from Antmicro.Renode.PlatformDescription.UserInterface import PlatformDescriptionMachineExtensions

mach_name = "stm"
reach_target_flag = 0

# ConfigurationManager.Instance.Set("general","serialization-mode", "Reflection") 

e = Emulation()
m = Monitor()
mach = e.add_mach(mach_name)
state_file= "statefile_bme280_stm.dat"

load_str = """using "platforms/cpus/stm32l072.repl" bme280: I2C.BME280@ i2c1 0x76"""
PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)
mach.load_elf("https://dl.antmicro.com/projects/renode/b_l072z_lrwan1--zephyr-bme280_test.elf-s_649120-15b7607a51b50245f4500257c871cd754cfeca5a")

pc_main = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(pc_main)}")
target_func_calling_pc = pc_main


# def save_state():
#     EmulationManager.Instance.Save(state_file)
#     print("state saved")

# def hook_addr_target(cpu, addr):
#     global reach_target_flag
#     print("Hook triggered")
#     mach.sysbus.cpu.Pause()
#     print("CPU paused")
#     save_thread = threading.Thread(target=save_state)
#     save_thread.start()
#     save_thread.join()
#     reach_target_flag = 1

def hook_addr_target(cpu,addr):
    global reach_target_flag
    # pc_target = addr
    print("In handler")
    # e.PauseAll()
    # sp_target = mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue  
    cpu.Pause()
    # EmulationManager.Instance.Save(state_file)
    # m.execute(f"Save @{state_file}")
    print("paused")
    reach_target_flag = 1




Action3 = getattr(System, 'Action`2')
hook_action_target = Action3[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

Analyzer(mach.sysbus.usart2).Show()
e.StartAll()

while reach_target_flag == 0:
    pass
if reach_target_flag == 1:
    # e.PauseAll()
    # time.sleep(1)
    try:
        mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
        EmulationManager.Instance.Save(state_file)
        # m.execute(f"Save @{state_file}")
        print(f"Save command executed: Save @{state_file}")
    except Exception as e:
         print(f"Error executing save command: {e}")
    # m.execute(f"Save @{state_file}")
    # EmulationManager.Instance.Save(state_file)
    # save_thread = threading.Thread(target=delayed_save, args=(state_file,))
    # save_thread.start()
    # save_thread.join()
    # retry_save(state_file)
    print("reached flag")
print("Done")
input()