import lief
from capstone import *

# Constant stuff
discardable_functions = ["_init","printf","read","free"]
arm32_to_amd64_gp = {"r0":"edi","r1":"esi","r2":"edx","r3":"ecx","r4":"eax","r5":"ebx","r6":"r8d","r7":"r9d","r7":"r10d","r8":"r11d","r9":"r12d","r10":"r13d","r11":"r14d","r12":"r14d","lr":"r15","sp":"rsp"}
arith_ops = ["sub","add"]
armcc_to_amd_cc={"eq":"e","ne":"ne","ge":"ge","lt":"lt","gt":"gt","le":"le"}
reloc_tbl_addr = dict()
reloc_tbl_v = dict()

def top(op):
    if op in arm32_to_amd64_gp.keys():
        return arm32_to_amd64_gp[op]
    return op[1:]

def resolve_addr(addr):
    if addr in reloc_tbl_addr.keys():
        return reloc_tbl_addr[addr].name
    if addr in reloc_tbl_v.keys():
        return reloc_tbl_v[addr].name
    return f"br_{addr}"

def ai_to_xi(ai):
    xi = []
    if ai.mnemonic=="cmp":
        ops = [x.strip() for x in ai.op_str.split(",")]
        xi.append(f"cmp {top(ops[0])}, {top(ops[1])}")
        return xi
    if ai.mnemonic=="push":
        ops = [x.strip() for x in ai.op_str[1:-1].split(",")]
        for op in ops:
            xi.append(f"push\t{arm32_to_amd64_gp[op]}")
        return xi
    if ai.mnemonic=="pop":
        ops = reversed([x.strip() for x in ai.op_str[1:-1].split(",")])
        for op in ops:
            if op=="pc":
                xi.append("ret")
                continue
            xi.append(f"pop\t{arm32_to_amd64_gp[op]}")
        return xi
    if ai.mnemonic=="eor":
        ops = [x.strip() for x in ai.op_str.split(",")]
        xi.append(f"mov\t{top(ops[0])}, {top(ops[1])}")
        xi.append(f"xor\t{top(ops[0])}, {top(ops[2])}")
        return xi
    if ai.mnemonic[:3] in arith_ops and len(ai.mnemonic)<=4:
        ops = [x.strip() for x in ai.op_str.split(",")]
        if ai.mnemonic[3:]=="s":
            if ai.mnemonic[:3]=="sub":
                xi.append(f"neg\t{top(ops[2])}")
            xi.append(f"cmp\t{top(ops[1])},{top(ops[2])}")
            if ai.mnemonic[:3]=="sub":
                xi.append(f"neg\t{top(ops[2])}")
        xi.append(f"mov\t{top(ops[0])}, {top(ops[1])}")
        xi.append(f"{ai.mnemonic}\t{top(ops[0])}, {top(ops[2])}")
        return xi
    if ai.mnemonic=="b":
        addr = ai.op_str.strip()
        xi.append(f"jmp\t{resolve_addr(addr[1:])}")
        return xi
    if ai.mnemonic[0]=="b"  and ai.mnemonic[1:] in armcc_to_amd_cc.keys():
        addr = ai.op_str.strip()
        xi.append(f"j{armcc_to_amd_cc[ai.mnemonic[1:]]}\t{resolve_addr(addr[1:])}")
        return xi
    if ai.mnemonic=="bl":
        addr = ai.op_str.strip()
        xi.append(f"call\t{resolve_addr(addr[1:])}")
        return xi
    if ai.mnemonic=="mov":
        ops = [x.strip() for x in ai.op_str.split(",")]
        xi.append(f"mov {top(ops[0])}, {top(ops[1])}")
        return xi
    return [f"UNIMPLEMENTED: {ai.mnemonic}\t{ai.op_str}"]

# Elf to be translated
arm_elf_path = "./simple_stack_arm"

# Preprocessing
binary = lief.parse(arm_elf_path)
ext_fun_names = set()
funs = []
for fn in binary.functions:
    if fn.size==0:
        ext_fun_names.add(fn.name)
        continue
    if fn.name.startswith("_"):
        continue
    funs.append(fn)

for reloc in binary.relocations:
    reloc_tbl_addr[hex(reloc.address)] = reloc.symbol
    reloc_tbl_v[hex(reloc.symbol.value)] = reloc.symbol
# Generator
externs = "\textern printf,putchar,malloc,fprintf,exit,open\n"
data_sec = "\tSECTION .data\n"
text_sec = "\tSECTION .text\n"

# BranchDsts: String, includes the '#0x'
branch_dsts = []
fns = dict()

# First pass to find branch destinations
for fn in funs:
    md = Cs(CS_ARCH_ARM,CS_MODE_ARM)
    cont = binary.get_content_from_virtual_address(virtual_address=fn.address,size=fn.size)
    code = [bytes([x]) for x in cont]
    code = b"".join(code)
    for i,ins in enumerate(md.disasm(code,fn.address)):
        if ins.address>fn.address+fn.size:
            break
        if ins.mnemonic.startswith("b"):
            dst = ins.op_str
            if dst in reloc_tbl_v.keys() or dst in reloc_tbl_addr.keys():
                continue
            branch_dsts.append(ins.op_str.strip()[1:])
        # print(f"{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}")

for fn in funs:
    fns[fn.name] = ""
    md = Cs(CS_ARCH_ARM,CS_MODE_ARM)
    cont = binary.get_content_from_virtual_address(virtual_address=fn.address,size=fn.size)
    code = [bytes([x]) for x in cont]
    code = b"".join(code)
    for i,ins in enumerate(md.disasm(code,fn.address)):
        if ins.address>fn.address+fn.size:
            break
        if hex(ins.address) in branch_dsts:
            fns[fn.name] += f"br_{hex(ins.address)}:\n"
        if ins.mnemonic.startswith("b"):
            pass
            # branch_dsts.append(ins.op_str.strip())
            # print("RET")
            # print(ai_to_xi(ins))
        fns[fn.name] += "\t"+"\n\t".join(ai_to_xi(ins))+"\n"
        # print(f"{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}")

for k,v in fns.items():
    text_sec += f"{k}:\n{v}\n"

output = f"{externs}\n{data_sec}\n{text_sec}\n"
with open("atx.s","w+") as f:
    f.write(output)


class ArmI:
    def __init__(self,armi):
        self.mnem = armi.mnemonic
        self.opstr = armi.op_str

    def emit(self):
        pass

class AArith(ArmI):
    def __init__(self,armi):
        super().__init__(self,armi)
