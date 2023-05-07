import angr
import sys

main_addr = 0x4011A9
find_addr = 0x40134F
avoid_addr = 0x40133C


class my_scanf(angr.SimProcedure):
    def run(self, format, buffer):
        simfd = self.state.posix.get_fd(sys.stdin.fileno())
        data, ret_size = simfd.read_data(4)
        self.state.memory.store(buffer, data)
        return ret_size


proj = angr.Project("./src/prog", load_options={"auto_load_libs": False})
proj.hook_symbol(
    "printf", angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True
)
proj.hook_symbol(
    "puts", angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True
)
proj.hook_symbol("__isoc99_scanf", my_scanf(), replace=True)

state = proj.factory.blank_state(addr=main_addr)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=find_addr, avoid=avoid_addr)
if simgr.found:
    ans = simgr.found[0].posix.dumps(sys.stdin.fileno())
    print(ans)

    with open("solve_input", "w") as f:
        for i in range(0, 15):
            x = int.from_bytes(ans[i * 4 : i * 4 + 4], byteorder="little", signed=True)
            f.write(f"{x}\n")
            print(x)
else:
    print("Failed")
