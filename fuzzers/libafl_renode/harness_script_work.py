# Loads libafl_renode library
# calls the fuzzing_functions, to which it sends the callback function
# sets up renode , hooks, breakpoints
# does renode related stuff within the callback function which is sent to fuzzing function

import ctypes
import subprocess
import random
import time 
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import TranslationCPUHooksExtensions



SCRIPTID = random.random().hex()
print(f"script id: {SCRIPTID}")
# with open("log.txt", 'a') as logfile:
#     print(f"script id: {SCRIPTID}", file=logfile, flush=True)

libafl_renode_lib = ctypes.CDLL("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/target/release/liblibafl_renode.so")
input_dir = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/input_dir"

# just testing dll import from libafl
test_res = libafl_renode_lib.external_current_millis2()
print(test_res)

#callback to be called within LibAFL
callback_function = ctypes.CFUNCTYPE(None, ctypes.c_char_p)

# ***** setup_renode, currently hardcoded for nrf52840 uart
state_file= "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/statefile.dat"
e = Emulation()
m = Monitor()
nrf52840 = e.add_mach("nrf52840")
nrf52840.load_repl("platforms/cpus/nrf52840.repl")
nrf52840.load_elf("https://dl.antmicro.com/projects/renode/renode-nrf52840-zephyr_shell_module.elf-gf8d05cf-s_1310072-c00fbffd6b65c6238877c4fe52e8228c2a38bf1f")
# nrf52840.load_elf("/media/asmita/224870c0-ff7f-4009-9ea0-79854d3c355a/nrfSDK/DeviceDownload/nRF5_SDK_17.1.0_ddde560/examples/peripheral/uart/pca10056/blank/armgcc/_build/nrf52840_xxaa.out")
TranslationCPUHooksExtensions.SetHookAtBlockBegin(nrf52840.sysbus.cpu.internal, nrf52840.internal, " ")
Analyzer(nrf52840.sysbus.uart0).Show()
e.StartAll()
# pc_val_i = m.execute("sysbus.cpu PC") #just hangs 
# # m.execute("Clear")

# print(pc_val_i)
m.execute(f"Save @{state_file}")
m.execute("Clear")
print("Saved initial renode stat file")
# m.execute(f"logFile @log")


def callback(data):
    # e.StartAll()
    # m.execute(f"sysbus.uart0 WriteChar {data}")
    # m.execute("Clear")
    # print("Inside harness callback")
    print(f"data: {type(data)} {data} size: {len(data)}")
    m.execute(f"Load @{state_file}")
    # print("***CCCC1****")
    nrf52840 = e.get_mach("nrf52840")
    # print("***CCCC2****")
    Analyzer(nrf52840.sysbus.uart0) # works but slow
    # print("***CCCC3****")
    e.StartAll()
    # print("***CCCC4****")
    # m.execute(f"sysbus.uart0 WriteChar 0x44")
    for i in range(len(data)):
        m.execute(f"sysbus.uart0 WriteByte {data[i]}")
    # print("***CCCC5****")
    # m.execute("sysbus.cpu PC")
    # print(val1)
    # print("***CCCC6****")
    # print(val1)
    # if m.execute("sysbus.cpu PC") == ('0x5156\r\r\n', '') :
    #     return 5
    m.execute("Clear")
    # return 0
    # with open("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/log.txt", 'a') as logfile:
    #     print(f"3rd print in callback", file=logfile, flush=True)

callback_ptr = callback_function(callback)
print("calling liabafl main_fuzzing_func")
libafl_renode_lib.main_fuzzing_func(ctypes.c_char_p(input_dir.encode('utf-8')),callback_ptr)
