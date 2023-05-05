import angr
import sys

main_addr = 0x4011A9
find_addr = 0x401363
avoid_addr = 0x40134D


def twos_complement(hexstr, bits):
    value = int(hexstr, 16)
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


class my_scanf(angr.SimProcedure):
    def run(self, format, buffer):
        simfd = self.state.posix.get_fd(sys.stdin.fileno())
        data, ret_size = simfd.read_data(0x4)
        self.state.memory.store(buffer, data)
        return ret_size


proj = angr.Project("./src/prog", load_options={"auto_load_libs": False})
proj.hook_symbol("__isoc99_scanf", my_scanf(), replace=True)

state = proj.factory.blank_state(addr=main_addr)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=find_addr, avoid=avoid_addr)
if simgr.found:
    ans = simgr.found[0].posix.dumps(sys.stdin.fileno())
    print(ans)

    for i in range(0, len(ans), 0x4):
        x = twos_complement((ans[i : i + 0x4][::-1]).hex(), 32)
        print(x)
else:
    print("Failed")
