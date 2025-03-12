
# evm loader

import idaapi
from idc import *
import re
import ida_bytes

def accept_file(li, filename):
    if filename.endswith('.evm') or filename.endswith('.bytecode'):
        return {'format': "EVM", 'options': 1|0x8000}
    return 0

def load_file(li, neflags, format):
    
    # Select the PC processor module
    idaapi.set_processor_type("EVM", SETPROC_LOADER_NON_FATAL)
    
    # TODO: detect and emulate contract creation code
    li.seek(0)
    buf = li.read(li.size())
    if not buf:
        return 0

    if re.fullmatch(b"0[xX][0-9a-fA-F]+", buf):
        print("Evm loader detected hex.")
        print("Replacing original buffer with hex decoded version")
        bs = buf[2:].strip().decode()
        buf = bytes.fromhex(bs) if len(bs)%2 == 0 else bytes.fromhex(f"0{bs}")

    # Load all shellcode into different segments
    start = 0x0
    seg = idaapi.segment_t()
    size = len(buf)
    end  = start + size
    # Create the segment
    seg.start_ea = start
    seg.end_ea   = end
    seg.bitness = 1 # 32-bit

    idaapi.add_segm_ex(seg, "evm", "CODE", 0)

    # TODO: make segments for stack, memory, storage

    # Copy the bytes
    idaapi.mem2base(buf, start, end)


    # check for swarm hash and make it data instead of code
    swarm_hash_address = buf.find(b'ebzzr0')
    if swarm_hash_address != -1:
        print("Evm loader Swarm hash detected, making it data")
        #for i in range(swarm_hash_address-1, swarm_hash_address+42):
        #    MakeByte(i) ## TODO
        if not idaapi.create_byte(swarm_hash_address-1, 43, True):
            print("[ERR] Evm loader failed to make swarm hash data")
        ida_bytes.set_cmt(swarm_hash_address-1, "swarm hash", True)
    # add entry point
    idaapi.add_entry(start, start, "start", 1) 

    # add comment to beginning of disassembly
    #idaapi.describe(start, True, "EVM bytecode disassembly")

    # Mark for analysis
    AutoMark(start, AU_CODE)

    #setup_enums()
    return 1
