import globals
import utils
import claripy
import angr
import ipdb

def wrmsr_hook(state):
    # Check if we can control the parameters of wrmsr.
    if utils.tainted_buffer(utils.get_reg(state, 'a')) and utils.tainted_buffer(utils.get_reg(state, 'c')) and utils.tainted_buffer(utils.get_reg(state, 'd')):
        # Check whether the regsiter is constrained.
        tmp_state = state.copy()
        
        reg_c = utils.get_reg(tmp_state, 'c')
        tmp_state.solver.add(claripy.Or(reg_c == 0x00000174, reg_c == 0x00000175, reg_c == 0x00000176, reg_c == 0xC0000081, reg_c == 0xC0000082, reg_c == 0xC0000083))

        if tmp_state.satisfiable():
            utils.print_vuln('arbitrary wrmsr', '', state, {'Register': str(utils.get_reg(state, 'c')), 'Value': (str(utils.get_reg(state, 'd')), str(utils.get_reg(state, 'a')))}, {})


def out_hook(state):
    # Check if we can control the parameters of out.
    if utils.tainted_buffer(utils.get_reg(state, 'a')) and utils.tainted_buffer(utils.get_reg(state, 'd')):
        # Check whether the port is constrained (can be 0xcf9 or not).
        tmp_state = state.copy()
        tmp_state.solver.add(utils.get_reg(tmp_state, 'd') == 0xcf9)
        tmp_state.solver.add(utils.get_reg(tmp_state, 'a') == 0xe)
        if tmp_state.satisfiable():
            utils.print_vuln('arbitrary out', '', state, {'Port': str(utils.get_reg(state, 'd')), 'Data': str(utils.get_reg(state, 'a'))}, {})


def rep_movsb_hook(state):
    dst = utils.get_reg(state, 'di')
    src = utils.get_reg(state, 'si')
    count = state.solver.min(utils.get_reg(state, 'c'))
    if count <= 0:
        count = 1
    elif count > 0x1000:
        count = 0x1000
    
    utils.print_debug(f'rep_movsb_hook: {dst}, {src}, {count}')
    val = state.memory.load(src, count)
    state.memory.store(dst, val, count)
    
def rep_movsw_hook(state):
    dst = utils.get_reg(state, 'di')
    src = utils.get_reg(state, 'si')
    count = state.solver.min(utils.get_reg(state, 'c'))
    if count <= 0:
        count = 1
    elif count > 0x1000:
        count = 0x1000

    for i in range(count):
        val = state.memory.load(src + i*2, 2, endness=state.arch.memory_endness)
        state.memory.store(dst + i*2, val, 2, endness=state.arch.memory_endness)
    state.add_constraints(count == 0)

def rep_movsd_hook(state):
    dst = utils.get_reg(state, 'di')
    src = utils.get_reg(state, 'si')
    count = state.solver.min(utils.get_reg(state, 'c'))
    if count <= 0:
        count = 1
    elif count > 0x1000:
        count = 0x1000

    for i in range(count):
        val = state.memory.load(src + i*4, 4, endness=state.arch.memory_endness)
        state.memory.store(dst + i*4, val, 4, endness=state.arch.memory_endness)
    state.add_constraints(count == 0)


def rep_stosb_hook(state):
    cx = state.solver.min(utils.get_reg(state, 'c'))
    if cx > 0x1000:
        cx = 0x1000
    di = utils.get_reg(state, 'di')
    value = utils.get_reg(state, 'a')

    while cx > 0:
        state.memory.store(di, value)
        di += 1
        cx -= 1

    utils.set_reg(state, 'c', 0)
    utils.set_reg(state, 'di', di)

def rep_stosw_hook(state):
    cx = state.solver.min(utils.get_reg(state, 'c'))
    if cx > 0x1000:
        cx = 0x1000
    di = utils.get_reg(state, 'di')
    value = utils.get_reg(state, 'a')

    while cx > 0:
        state.memory.store(di, value, 2, endness=state.arch.memory_endness)
        di += 2
        cx -= 1

    utils.set_reg(state, 'c', 0)
    utils.set_reg(state, 'di', di)

def rep_stosd_hook(state):
    cx = state.solver.min(utils.get_reg(state, 'c'))
    if cx > 0x1000:
        cx = 0x1000
    di = utils.get_reg(state, 'di')
    value = utils.get_reg(state, 'a')

    while cx > 0:
        state.memory.store(di, value, 4, endness=state.arch.memory_endness)
        di += 4
        cx -= 1

    utils.set_reg(state, 'c', 0)
    utils.set_reg(state, 'di', di)

def rep_stosq_hook(state):
    cx = state.solver.min(utils.get_reg(state, 'c'))
    if cx > 0x1000:
        cx = 0x1000
    di = utils.get_reg(state, 'di')
    value = utils.get_reg(state, 'a')

    while cx > 0:
        state.memory.store(di, value, 8, endness=state.arch.memory_endness)
        di += 8
        cx -= 1

    utils.set_reg(state, 'c', 0)
    utils.set_reg(state, 'di', di)


def int_hook(state):
    state.kill()
    return

def rdpmc_hook(state):
    return

def outs_hook(state):
    return

def lock_hook(state):
    return

def ins_hook(state):
    return

def lfence_hook(state):
    return

def sidt_hook(state):
    return

def lidt_hook(state):
    return

def pushfw_hook(state):
    flags = utils.get_reg(state, 'flags')
    sp = utils.get_reg(state, 'sp')
    sp -= state.arch.bytes
    utils.set_reg(state, 'sp', sp)
    state.memory.store(sp, flags, state.arch.bytes, endness=state.arch.memory_endness)
    return

def popfw_hook(state):
    sp = utils.get_reg(state, 'sp')
    flags = state.memory.load(sp, state.arch.bytes, endness=state.arch.memory_endness)
    sp += state.arch.bytes
    utils.set_reg(state, 'sp', sp)
    utils.set_reg(state, 'flags', flags)
    return

def indirect_jmp_hook(state):
    # Evaluate the indirect jmp address.
    mnemonic = globals.proj.factory.block(state.addr).capstone.insns[0].mnemonic
    op = globals.proj.factory.block(state.addr).capstone.insns[0].op_str
    
    # Handle both x64 and x86 register names
    valid_regs = ['rax', 'rbx', 'rcx', 'rdx', 'eax', 'ebx', 'ecx', 'edx']
    
    if op in valid_regs:
        jmp_addrs = []
        if op in ['rax', 'eax']:
            jmp_addrs = state.solver.eval_upto(utils.get_reg(state, 'a'), 0x20)
        elif op in ['rbx', 'ebx']:
            jmp_addrs = state.solver.eval_upto(utils.get_reg(state, 'b'), 0x20)
        elif op in ['rcx', 'ecx']:
            jmp_addrs = state.solver.eval_upto(utils.get_reg(state, 'c'), 0x20)
        elif op in ['rdx', 'edx']:
            jmp_addrs = state.solver.eval_upto(utils.get_reg(state, 'd'), 0x20)

        utils.print_debug(f'indirect jmp\n\tstate: {state}\n\taddr: {hex(state.addr)}\n\tinstruction\n\t\t{globals.proj.factory.block(state.addr).capstone.insns}\n\t\t{globals.proj.factory.block(state.addr).capstone.insns[0].mnemonic} {globals.proj.factory.block(state.addr).capstone.insns[0].op_str}\n\tjmp_addrs: {[hex(i) for i in jmp_addrs]}\n')
        if len(jmp_addrs) > 1:
            # Iterate all possible jmp addresses and insert them into the deferred stash.
            for i in range(1, len(jmp_addrs)):
                tmp_state = state.copy()
                
                if op in ['rax', 'eax']:
                    tmp_state.add_constraints(utils.get_reg(tmp_state, 'a') == jmp_addrs[i])
                elif op in ['rbx', 'ebx']:
                    tmp_state.add_constraints(utils.get_reg(tmp_state, 'b') == jmp_addrs[i])
                elif op in ['rcx', 'ecx']:
                    tmp_state.add_constraints(utils.get_reg(tmp_state, 'c') == jmp_addrs[i])
                elif op in ['rdx', 'edx']:
                    tmp_state.add_constraints(utils.get_reg(tmp_state, 'd') == jmp_addrs[i])

                globals.simgr.deferred.append(tmp_state)

            if op in ['rax', 'eax']:
                state.add_constraints(utils.get_reg(state, 'a') == jmp_addrs[0])
            elif op in ['rbx', 'ebx']:
                state.add_constraints(utils.get_reg(state, 'b') == jmp_addrs[0])
            elif op in ['rcx', 'ecx']:
                state.add_constraints(utils.get_reg(state, 'c') == jmp_addrs[0])
            elif op in ['rdx', 'edx']:
                state.add_constraints(utils.get_reg(state, 'd') == jmp_addrs[0])
        elif len(jmp_addrs) == 1:
            # The jmp address is constrained.
            addr = state.addr
            globals.proj.unhook(addr)
            globals.simgr.step()
            globals.proj.hook(addr, indirect_jmp_hook, 0)
        else:
            # Kill the state if there is no candidate jmp address.
            tmp_state = state.copy()
            utils.set_reg(tmp_state, 'ip', globals.proj.factory.block(state.addr).capstone.insns[0].size + utils.get_reg(tmp_state, 'ip'))
            globals.simgr.deferred.append(tmp_state)

            tmp_state = state.copy()
            utils.set_reg(tmp_state, 'ip', globals.DO_NOTHING)
            globals.simgr.deferred.append(tmp_state)

            state.kill()
    else:
        # Maybe some situations are not considered.
        ipdb.set_trace()

    return
