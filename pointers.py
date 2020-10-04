from __future__ import annotations
import gdb
import re
from dataclasses import dataclass
from functools import lru_cache
from itertools import takewhile

class ExaminePointers(gdb.Command):
    def __init__(self):
        super(ExaminePointers, self).__init__("pointers", gdb.COMMAND_DATA)

    # Constants
    SHOW_ALL_POINTERS = "show"
    FIND_POINTERS_TO = "to"
    FIND_MULTILEVEL_POINTERS = "to2"
    HELP1 = f"[{SHOW_ALL_POINTERS} [<start_pc> <end_pc>]]"
    HELP2 = f"[({FIND_POINTERS_TO} | {FIND_MULTILEVEL_POINTERS}) <address> [<start_pc> <end_pc>]]"
    PTR_REGEX = r"(^|[^\$-:])(0x[0-9a-f]+)([,\s]|$)"
    NO_SYMBOL_MATCH = "No symbol matches"
    NOT_FOUND = "not-found"
    HEX_PREFIX = "0x"
    # TODO: Find pointer size for architecture and OS - gdb.inferiors()[0].architecture().name()
    PTR_SIZE = 6
    ENDIANNESS = "little"

    # Structures
    @dataclass
    class AddressInfo:
        addr: str
        symbol: str
        section: str   
        objfile: str
        def __str__(self):
            if self.section is ExaminePointers.NOT_FOUND:
                return self.addr
            elif self.symbol is ExaminePointers.NOT_FOUND:
                return f"{self.addr} in section {self.section} of {self.objfile}"
            elif _ := self._is_ptr2():
                next_ptr = ExaminePointers._get_address_info(_)
                return f"{self.addr} <{self.symbol}> -> {next_ptr.__str__()}" 
            else:
                return f"{self.addr} <{self.symbol}>" 
        def _ptr_to(self, length: int):
            try:
                inferior = gdb.inferiors()[0]
                mem = inferior.read_memory(self.addr_num(), length)
                return mem.tobytes()
            except gdb.MemoryError:
                return False
        def _is_ptr2(self):
            try:
                inferior = gdb.inferiors()[0]
                ptr2 = inferior.read_memory(
                        int.from_bytes(self._ptr_to(ExaminePointers.PTR_SIZE), byteorder=ExaminePointers.ENDIANNESS),
                        ExaminePointers.PTR_SIZE)
                return hex(int.from_bytes(ptr2, byteorder=ExaminePointers.ENDIANNESS))
            except gdb.MemoryError:
                return False
        def addr_num(self) -> int:
            return int(self.addr, 16)
            

    # Lambda functions
    hex2dec = lambda d: int(d, 16) if isinstance(d, str) else d 

    def invoke(self, arg, from_tty):
        def resolve_addr_args(args, addr_args_start: int) -> tuple:
            if (args.__len__() == addr_args_start+2):
                start_pc, end_pc = self._eval(args[addr_args_start]), self._eval(args[addr_args_start+1])
            else:
                start_pc, end_pc = self._get_current_mmap()
            return start_pc, end_pc

        if not arg: self._help(); return
        if not from_tty: return

        # All inputs must be evaluated before used 
        args = gdb.string_to_argv(arg) 
        if (args[0] == self.SHOW_ALL_POINTERS):
            start_pc, end_pc = resolve_addr_args(args, 1)
            pointer_list = self._find_pointers(start_pc, end_pc)
            self._print_pointers(start_pc, end_pc, pointer_list)
        elif (args[0] == self.FIND_POINTERS_TO):
            start_pc, end_pc = resolve_addr_args(args, 2)
            pointer_list = self._find_pointers(start_pc, end_pc)
            slen = len(self._eval(args[1]))
            for ptr in pointer_list:
                if ptr.ptr_to(slen) != self._eval(args[1]): continue
                print(ptr)
                #print(ptr.ptr_to(slen))
        else:
            self._help(); return
    
    #####################
    # Utility functions #
    #####################
    
    # Evaluate expressions like $rip and convert number base
    def _eval(self, term) -> str:
        term = gdb.execute(f"print /ax {term}", to_string=True)
        return term.split()[-1]

    def _change_endianness(mem: memoryview) -> memoryview:
        blist = bytearray(mem.tobytes())
        blist.reverse()
        return memoryview(blist)

    def _help(self) -> None:
        print(f"pointers {self.HELP1} \n\t {self.HELP2}")
        return

    @lru_cache()
    def _find_pointers(self, start_pc: str, end_pc: str, follow_ptr=True) -> list:    
        mem_addr = list()
        pointers = list()
        frame = gdb.selected_frame()
        arch = frame.architecture()
        disas = arch.disassemble(ExaminePointers.hex2dec(start_pc), ExaminePointers.hex2dec(end_pc))
        for instr in disas:
            m = re.findall(self.PTR_REGEX, instr["asm"])
            if m: mem_addr.extend(m) 
        return [self._get_address_info(addr[1]) for addr in set(mem_addr)]
    
    def _print_pointers(self, start_pc: str, end_pc: str, pointer_list) -> None:
        print("{} pointer found on {}-{}:".format(pointer_list.__len__(), start_pc, end_pc))
        for ptr in pointer_list: print(ptr)

    ####################
    # Memory functions #
    ####################

    def _get_current_mmap(self) -> tuple:
        mappings = gdb.execute("info proc mappings", to_string=True)
        pc = gdb.selected_frame().pc()
        start_addr, end_addr = None, None
        for space in mappings.splitlines():
            if not space: continue
            fields = space.split()
            if not fields[0].startswith(self.HEX_PREFIX): continue
            start_addr = ExaminePointers.hex2dec(fields[0])
            end_addr = ExaminePointers.hex2dec(fields[1])
            if (start_addr < pc) and (pc < end_addr): break
        if not start_addr: Exception("Address not found on memory mapping")
        return (start_addr, end_addr)

    # Construct AddressInfo object using addr and symbol information
    @staticmethod
    def _get_address_info(addr: str) -> ExaminePointers.AddressInfo:
        sym_info = gdb.execute(f"info symbol {addr}", to_string=True)
        if sym_info.startswith(ExaminePointers.NO_SYMBOL_MATCH): 
            return ExaminePointers.AddressInfo(addr, ExaminePointers.NOT_FOUND, 
                    ExaminePointers.NOT_FOUND, ExaminePointers.NOT_FOUND)
        sym_info = sym_info.split()
        if sym_info[0].startswith(ExaminePointers.HEX_PREFIX):
            symbol = ExaminePointers.NOT_FOUND
        else:
            symbol = " ".join(list(takewhile(lambda token: token != "in", sym_info)))
        objfile = sym_info[-1]
        section = sym_info[-3]
        return ExaminePointers.AddressInfo(addr, symbol, section, objfile)

ExaminePointers()
