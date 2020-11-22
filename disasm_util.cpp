#include <iostream>
#include <stdint.h>
#include <string.h>

#include <capstone/capstone.h>

#include "../inc/loader.h"
#include "disasm_util.h"

static csh dis;

static int init_capstone(Binary const& bin)
{
    cs_mode mode;
    if (bin.arch() == Binary::Arch::X86) {
        switch(bin.bits()) {
            case 32:
                mode = CS_MODE_32;
                break;
            case 64:
                mode = CS_MODE_64;
                break;
            default:
                ::fprintf(stderr, "Unsupported bit width for x86: %u bits\n", bin.bits());
                return -1;
        }
    } else {
        ::fputs("Unsupported architecture", stderr);
        return -1;
    }

    if (cs_open(CS_ARCH_X86, mode, &dis) != CS_ERR_OK) {
        ::fputs("Failed to open Capstone", stderr);
        return -1;
    }

    return 0;
}

int disasm_one(Section const& sec, uint64_t addr, char* mnemonic, char* op_str)
{
    static bool capstone_inited = false;
    if (!capstone_inited) {
        if (init_capstone(sec.binary()) < 0) {
            return -1;
        }
        capstone_inited = true;
    }

    if (!sec.contains(addr)) {
        ::fprintf(stderr, "Section %s does not contain address 0x%lx\n", sec.name().c_str(), addr);
        return -1;
    }

    cs_insn* insn = cs_malloc(dis);
    if (!insn) {
        ::fputs("Out of memory", stderr);
        return -1;
    }

    uint64_t off      = addr - sec.vma();
    uint8_t const* pc = sec.bytes() + off;
    size_t n          = sec.size() - off;
    if (!cs_disasm_iter(dis, &pc, &n, &addr, insn)) {
        ::fprintf(stderr, "Disassembly error: %s\n", cs_strerror(cs_errno(dis)));
        return -1;
    }

    if (mnemonic) {
        strcpy(mnemonic, insn->mnemonic);
    }
    if (op_str) {
        strcpy(op_str, insn->op_str);
    }

    int len = insn->size;

    cs_free(insn, 1);

    return len;
}

