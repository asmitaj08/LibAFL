# !/usr/bin/env -S python3 -m bpython -i
import time
import timeit
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
from decimal import Decimal
import random

sp_main = 0
lr_main = 0
pc_main = 0
mach_name = "nrf"
e = Emulation()
m = Monitor()
mach = e.add_mach(mach_name)

state_file= "statefile_bmp180_nrf_test.dat"
state_file_delay= "statefile_bmp180_nrf_test_delay.dat"


temp_data = 60
# humidity_data = 88
pressure_data = 1200

exit_flag = 0
delay_flag = 0
reach_target_flag = 0
# exit_addr = 0x00010204  # 0x000111c8 # Decision about when to exit??
exit_addr = 0x3102
delay_addr = 0x4ec0
# restore_pc = 0x0800353a
# restore_sp = 0x20001040
# load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180@ twi0 0x77"""
load_str = """using "platforms/cpus/nrf52840.repl" bmp180: Sensors.BMP180_modified@ twi0 0x77"""
PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)
# mach.load_elf("https://dl.antmicro.com/projects/renode/BMP180_I2C.ino.arduino.mbed.nano33ble.elf-s_3127076-ba5f49cd34cd9549c2aa44f83af8e2011ecd1c22")
mach.load_elf("nrf_bmp180_drv1.out")

pc_main = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(pc_main)}")
target_func_calling_pc = pc_main

def hook_addr_target(cpu,addr):
    global reach_target_flag
    # pc_target = addr
    # sp_target = mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue  
    # mach.sysbus.cpu.Pause()
    mach.Pause()
    reach_target_flag = 1
    print("Target Hook task done")

def hook_addr_exit(cpu,addr):
    global exit_flag
    exit_flag = 1
    print(f"***** Exit addr ******* : {hex(addr)}")

def hook_addr_delay(cpu,addr):
    global delay_flag
    delay_flag = 1
    # global mach
    print(f"***** delay addr *******: {delay_flag} : {hex(addr)}")
    # mach.sysbus.cpu.Pause()
    mach.Pause()
    # print("~~~~~~~~~~~~~~~~~~~~")
    # mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create((delay_addr+4), 32))
    mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create((0x3316), 32)) #0x3312 is lr
    # mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create((mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue-1), 32)) #for lr
    # mach.sysbus.cpu.SetRegisterUnsafe(0, RegisterValue.Create(0, 32))
    # m.execute(f"cpu PC {0x3312}")
    # print(f"Reg set to : pc : {(mach.sysbus.cpu.PC)}")
    # print(f"Reg0 set to 0: R0 : {mach.sysbus.cpu.GetRegisterUnsafe(0).RawValue}")
    # mach.sysbus.cpu.Resume()
    mach.Start()
    # print(f"Resume PC1 : pc : {(mach.sysbus.cpu.PC)}")
    # print(f"~~~~~~~~CPU Resumed~~~~~~~~~~~~ : pc : {(mach.sysbus.cpu.PC)}")
    # print(f"Resume PC2 : pc : {(mach.sysbus.cpu.PC)}")
    # mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
    # mach.sysbus.cpu.RemoveHooksAt(exit_addr)
    # EmulationManager.Instance.Save(state_file_delay)
    # print(f"** For delay Save command executed: Save @{state_file_delay}")


Action3 = getattr(System, 'Action`2')
hook_action_target = Action3[ICpuSupportingGdb, System.UInt64](hook_addr_target)
mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)

Action4 = getattr(System, 'Action`2')
hook_action_exit = Action4[ICpuSupportingGdb, System.UInt64](hook_addr_exit)
# mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)

Action5 = getattr(System, 'Action`2')
hook_action_delay = Action5[ICpuSupportingGdb, System.UInt64](hook_addr_delay)

Analyzer(mach.sysbus.uart0).Show()
e.StartAll()

while reach_target_flag == 0:
    pass
if reach_target_flag == 1:
    print("Target flag reached. Saving the instance now...")
    try:
        mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
        # mach.sysbus.cpu.RemoveHooksAt(exit_addr)
        EmulationManager.Instance.Save(state_file)
        print(f"Save command executed: Save @{state_file}")
    except Exception as e:
         print(f"Error executing save command: {e}")
    print("reached flag")

load_path_format = ReadFilePath(state_file)
print("Done initial setup")
data = [0x44,0x44,0x32]
count = 1
while count:
    # count += 1
    print("Loading the saved file")
    # start_time = time.time()
    EmulationManager.Instance.Load(load_path_format)
    # end_time = time.time()
    # load_execution_time = end_time - start_time
    # print(f"Execution time for the line: {load_execution_time:.10f} seconds")
    print("************file loaded")
    mach = e.get_mach(mach_name)
    # mach_new.sysbus.i2c1.ReadFromFuzzer(data)
    mach.sysbus.cpu.AddHook(exit_addr,hook_action_exit)
    mach.sysbus.cpu.AddHook(delay_addr,hook_action_delay)
    # print(f"***Mach here : {mach_new}")
    print(f"******PC : {mach.sysbus.cpu.PC}")
    Analyzer(mach.sysbus.uart0)  #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # temp_data += 20
    # # humidity_data += 20
    # pressure_data += 20
    # print(f"**** Temp :{mach_new.sysbus.twi0.bmp180.Temperature }")
    # print(f"**** Pressure :{mach_new.sysbus.twi0.bmp180.UncompensatedPressure}")
    # mach_new.sysbus.twi0.bmp180.Temperature = Decimal('77.0')
    # mach_new.sysbus.twi0.bmp180.Temperature = temp_data
    # mach_new.sysbus.twi0.bmp180.UncompensatedPressure = pressure_data
    # data[0] = random.getrandbits(8) #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # mach_new.sysbus.i2c1.ReadDoubleWord(0x00)
    # print(f"start pc : {(mach_new.sysbus.cpu.PC)}")
    # print("^^^^^Resuming next run")
    # mach.sysbus.twi0.bmp180.ReadFromFuzzer(data) #^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    e.StartAll()
    # print(f"Reg set to : pc : {(mach_new.sysbus.cpu.PC)}")
    # print(f"**** Temp^^ :{mach_new.sysbus.twi0.bmp180.Temperature }")
    # print(f"**** Pressure^^ :{mach_new.sysbus.twi0.bmp180.UncompensatedPressure}")
    # print(f"starting new run: Temp : {mach.sysbus.i2c1.bme280.Temperature}, Hum : {mach.sysbus.i2c1.bme280.Humidity}, Pres : {mach.sysbus.i2c1.bme280.Pressure}")
    # print(f"Reg set to : pc : {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}, sp : {hex(mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue)}, lr : {hex(mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue)}")
    # mach.sysbus.cpu.Resume()

    # if delay_flag == 1:
    #     print("~~~~~~~~~~~~~~~~~~~~")
    #     mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create((mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue - 1), 32))
    #     mach.sysbus.cpu.SetRegisterUnsafe(0, RegisterValue.Create(0, 32))
    #     print(f"Reg set to : pc : {(mach.sysbus.cpu.PC)}")
    #     print(f"Reg0 set to 0: R0 : {mach.sysbus.cpu.GetRegisterUnsafe(0).RawValue}")
    #     mach.sysbus.cpu.Resume()
    #     print("~~~~~~~~CPU Resumed~~~~~~~~~~~~")
    #       mach.sysbus.cpu.Resume()
    #       print("~~~~~~~~CPU Resumed~~~~~~~~~~~~")
    #     print("***************@@@@@@@@@@@@@@@@@@@@@@***************************************")
    #     # mach.sysbus.cpu.Pause()
    #     print(f"Reg set to @@ : pc : {(mach.sysbus.cpu.PC)} : sp : {mach.sysbus.cpu.SP} : lr : {mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue}")
    #     mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue, 32))
    #     print(f"Reg set to : pc : {(mach.sysbus.cpu.PC)}")
    #     print("$$$$$$$$$$$$$$$$$$$@@@@@@@@@@@@@@@@@@@@@$$$$$$$$$$$$$$$$$$$$$$$$")
    #     delay_flag=0
    #     mach.sysbus.cpu.Resume()
        # mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(delay_addr+4, 32))
        # print(f"Reg set to : pc : {(mach.sysbus.cpu.PC)}")

    while exit_flag == 0 :
        # if delay_flag == 1:
        #     print("~~~~~~~~~~~~~~~~~~~~")
        #     mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create((mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue - 1), 32))
        #     mach.sysbus.cpu.SetRegisterUnsafe(0, RegisterValue.Create(0, 32))
        #     print(f"Reg set to : pc : {(mach.sysbus.cpu.PC)}")
        #     print(f"Reg0 set to 0: R0 : {mach.sysbus.cpu.GetRegisterUnsafe(0).RawValue}")
        #     mach.sysbus.cpu.Resume()
        #     print("~~~~~~~~CPU Resumed in while exit part~~~~~~~~~~~~")        
        # print("wait")
        # if delay_flag == 1:
        #     print("******************************************************")
        #     mach.sysbus.cpu.Resume()
        #     print("~~~~~~~~CPU Resumed in while exit_flag part~~~~~~~~~~~~")
        #     # mach.sysbus.cpu.Pause()
        #     print(f"Reg set to @@ : pc : {(mach.sysbus.cpu.PC)} : sp : {mach.sysbus.cpu.SP} : lr : {mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue}")
        #     mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue, 32))
        #     print(f"Reg set to : pc : {(mach.sysbus.cpu.PC)}")
        #     print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
        #     delay_flag=0
        #     mach.sysbus.cpu.Resume()
        #     # mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(delay_addr+4, 32))
        #     # print(f"Reg set to : pc : {(mach.sysbus.cpu.PC)}")
        print(f"Waiting at : pc : {(mach.sysbus.cpu.PC)}")
        # pass

    if exit_flag == 1:
        exit_flag = 0
        print("**Reached exit******")

    # input()
   




