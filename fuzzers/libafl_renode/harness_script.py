# Loads libafl_renode library
# calls the fuzzing_functions, to which it sends the callback function
# sets up renode , hooks, breakspoints
# does renode related stuff within the callback function which is sent to fuzzing function

import ctypes
import subprocess
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import TranslationCPUHooksExtensions


libafl_renode_lib = ctypes.CDLL("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/target/release/liblibafl_renode.so")
input_dir = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/in-dir/test"

# just tetsing dll import from libafl
test_res = libafl_renode_lib.external_current_millis2()
print(test_res)

#callback to be called within LibAFL
callback_function = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_size_t)

# renode setup
# renode_path = "/home/asmita/fuzzing_bare-metal/renode_modify/renode/renode"
# resc_path = "/home/asmita/fuzzing_bare-metal/renode_modify/renode/scripts/single-node/nrf52840.resc"

# # renode_command = [renode_path, f"-e i @{resc_path};cpu SetHookAtBlockBegin \"print '***HookFn'\";s"]
# renode_command = [renode_path, f"-e i @{resc_path};s;sysbus.uart0 WriteChar 0x44"] # 0x44 will be replaced by data sent by LibAFL
# print(f"Renode command : {renode_command}")

#testing
# subprocess.run(renode_command)
# print("Executed renode")
# define callback which executes renode
# state_file = "/home/asmita/fuzzing_bare-metal/libafl_modify/fuzzers/libafl_renode/statefile.dat"
# renode_command = [renode_path, f"-e i @{resc_path};s;Save @{state_file};quit"]
# subprocess.run(renode_command)

# renode_command = [renode_path, f"-e i @{resc_path};Load @{state_file};mach set 0; showAnalyzer sysbus.uart0; sysbus.uart0 WriteChar {0x44}"]
# subprocess.run(renode_command)

# ***** setup_renode, currently hardcoded for nrf52840 uart
e = Emulation()
m = Monitor()
nrf52840 = e.add_mach("nrf52840")
nrf52840.load_repl("platforms/cpus/nrf52840.repl")
nrf52840.load_elf("https://dl.antmicro.com/projects/renode/renode-nrf52840-zephyr_shell_module.elf-gf8d05cf-s_1310072-c00fbffd6b65c6238877c4fe52e8228c2a38bf1f")

TranslationCPUHooksExtensions.SetHookAtBlockBegin(nrf52840.sysbus.cpu.internal, nrf52840.internal, " ")
Analyzer(nrf52840.sysbus.uart0).Show()
# e.StartAll()
def callback(data, size):
    # print("Callback called")
    # data = data.strip('\n')
    # Convert raw bytes to Python string for printing
    # data_str = ctypes.string_at(data, size).decode('utf-8')
    # print("Callback data:", data)
    # renode_command = [renode_path, f"--disable-xwt --console --hide-analyzers -e i @{resc_path};s;sysbus.uart0 WriteChar {0x44};quit"]
    # subprocess.run(renode_command)
    # print("Executed renode")
    e.StartAll()
    m.execute(f"sysbus.uart0 WriteChar {data}")
    # m.execute(f"sysbus.uart0 WriteChar {0x44}")



callback_ptr = callback_function(callback)
print("calling liabafl main_fuzzing_func")
libafl_renode_lib.main_fuzzing_func(ctypes.c_char_p(input_dir.encode('utf-8')),callback_ptr)