from __future__ import annotations
import gdb
import pprint
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
    HELP1 = "[{} [<start_pc> <end_pc>]]".format(SHOW_ALL_POINTERS)
    HELP2 = "[{} <address> [<start_pc> <end_pc>]]".format(FIND_POINTERS_TO)
    PTR_REGEX = r"(^|[^\$-])(0x[0-9a-f]+)([,\s]|$)"
    NO_SYMBOL_MATCH = "No symbol matches"
    NOT_FOUND = "not-found"

    # Structures
    @dataclass
    class AddressInfo:
        addr: str
        symbol: str
        section: str   
        objfile: str
        def __str__(self):
            if self.section == ExaminePointers.NOT_FOUND:
                return self.addr
            elif self.symbol == ExaminePointers.NOT_FOUND:
                return "{} in section {} of {}".format(self.addr, self.section, self.objfile)
            else:
                return "{} <{}>".format(self.addr, self.symbol) 
        def ptr_to(self) -> str:
            try:
                ptr2_result = gdb.execute("print **{}".format(self.addr), to_string=True)
            except gdb.MemoryError:
                ptr2_result = False
            if ptr2_result:
                print(ptr2_result)
            return ptr2_result
        def addr_int(self) -> int:
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
            for ptr in pointer_list:
                if ptr.ptr_to() != self._eval(args[1]): continue
                print(ptr)
        else:
            self._help(); return
    
    #####################
    # Utility functions #
    #####################
    
    # Evaluate expressions like "$rip" and convert number base
    def _eval(self, term) -> str:
        term = gdb.execute("print /ax {}".format(term), to_string=True)
        return term.split()[-1]

    def _help(self) -> None:
        print("pointers {} \n\t {}".format(self.HELP1, self.HELP2))
        return

    @lru_cache()
    def _find_pointers(self, start_pc: str, end_pc: str, follow_ptr=True) -> list:    
        pointers = list() 
        frame = gdb.selected_frame()
        arch = frame.architecture()
        disas = arch.disassemble(ExaminePointers.hex2dec(start_pc), ExaminePointers.hex2dec(end_pc))
        for instr in disas:
            m = re.findall(self.PTR_REGEX, instr["asm"])
            if m: [pointers.append(self._get_address_info(addr[1])) for addr in m]
        return pointers
    
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
            if not fields[0].startswith("0x"): continue
            start_addr = ExaminePointers.hex2dec(fields[0])
            end_addr = ExaminePointers.hex2dec(fields[1])
            if (start_addr < pc) and (pc < end_addr): break
        if not start_addr: Exception("Address not found on memory mapping")
        return (start_addr, end_addr)

    # Construct AddressInfo object using addr and symbol information 
    def _get_address_info(self, addr: int) -> AddressInfo:
        sym_info = gdb.execute("info symbol {}".format(addr), to_string=True)
        if sym_info.startswith(self.NO_SYMBOL_MATCH): 
            return self.AddressInfo(addr, self.NOT_FOUND, self.NOT_FOUND, self.NOT_FOUND)
        sym_info = sym_info.split()
        if sym_info[0].startswith("0x"):
            symbol = self.NOT_FOUND
        else:
            symbol = " ".join(list(takewhile(lambda token: token != "in", sym_info)))
        objfile = sym_info[-1]
        section = sym_info[-3]
        return self.AddressInfo(addr, symbol, section, objfile)

ExaminePointers()
