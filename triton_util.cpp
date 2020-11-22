#include <stdio.h>
#include <stdint.h>

#include <string>
#include <map>

#include <triton/api.hpp>

#include "triton_util.h"
#include "../inc/binary.h"

int set_triton_arch(Binary const& bin, triton::API& api, triton::arch::register_e& ip)
{
    if (bin.arch() != Binary::Arch::X86) {
        ::fputs("Unsupported architecture", stderr);
        return -1;
    }

    if (bin.bits() == 32) {
        api.setArchitecture(triton::arch::ARCH_X86);
        ip = triton::arch::ID_REG_X86_EIP;
    }
    else if (bin.bits() == 64) {
        api.setArchitecture(triton::arch::ARCH_X86_64);
        ip = triton::arch::ID_REG_X86_RIP;
    }
    else {
        ::fprintf(stderr, "Unsupported bit width for x86: %u bits\n", bin.bits());
        return -1;
    }

    return 0;
}

triton::arch::register_e get_triton_regnum(char* regname)
{
         if(!strcmp(regname, "al"))  return triton::arch::ID_REG_X86_AL;
    else if(!strcmp(regname, "ah"))  return triton::arch::ID_REG_X86_AH;
    else if(!strcmp(regname, "ax"))  return triton::arch::ID_REG_X86_AX;
    else if(!strcmp(regname, "eax")) return triton::arch::ID_REG_X86_EAX;
    else if(!strcmp(regname, "rax")) return triton::arch::ID_REG_X86_RAX;
    else if(!strcmp(regname, "bl"))  return triton::arch::ID_REG_X86_BL;
    else if(!strcmp(regname, "bh"))  return triton::arch::ID_REG_X86_BH;
    else if(!strcmp(regname, "bx"))  return triton::arch::ID_REG_X86_BX;
    else if(!strcmp(regname, "ebx")) return triton::arch::ID_REG_X86_EBX;
    else if(!strcmp(regname, "rbx")) return triton::arch::ID_REG_X86_RBX;
    else if(!strcmp(regname, "cl"))  return triton::arch::ID_REG_X86_CL;
    else if(!strcmp(regname, "ch"))  return triton::arch::ID_REG_X86_CH;
    else if(!strcmp(regname, "cx"))  return triton::arch::ID_REG_X86_CX;
    else if(!strcmp(regname, "ecx")) return triton::arch::ID_REG_X86_ECX;
    else if(!strcmp(regname, "rcx")) return triton::arch::ID_REG_X86_RCX;
    else if(!strcmp(regname, "dl"))  return triton::arch::ID_REG_X86_DL;
    else if(!strcmp(regname, "dh"))  return triton::arch::ID_REG_X86_DH;
    else if(!strcmp(regname, "dx"))  return triton::arch::ID_REG_X86_DX;
    else if(!strcmp(regname, "edx")) return triton::arch::ID_REG_X86_EDX;
    else if(!strcmp(regname, "rdx")) return triton::arch::ID_REG_X86_RDX;
    else if(!strcmp(regname, "dil")) return triton::arch::ID_REG_X86_DIL;
    else if(!strcmp(regname, "di"))  return triton::arch::ID_REG_X86_DI;
    else if(!strcmp(regname, "edi")) return triton::arch::ID_REG_X86_EDI;
    else if(!strcmp(regname, "rdi")) return triton::arch::ID_REG_X86_RDI;
    else if(!strcmp(regname, "sil")) return triton::arch::ID_REG_X86_SIL;
    else if(!strcmp(regname, "si"))  return triton::arch::ID_REG_X86_SI;
    else if(!strcmp(regname, "esi")) return triton::arch::ID_REG_X86_ESI;
    else if(!strcmp(regname, "rsi")) return triton::arch::ID_REG_X86_RSI;
    else if(!strcmp(regname, "bpl")) return triton::arch::ID_REG_X86_BPL;
    else if(!strcmp(regname, "bp"))  return triton::arch::ID_REG_X86_BP;
    else if(!strcmp(regname, "ebp")) return triton::arch::ID_REG_X86_EBP;
    else if(!strcmp(regname, "rbp")) return triton::arch::ID_REG_X86_RBP;
    else if(!strcmp(regname, "spl")) return triton::arch::ID_REG_X86_SPL;
    else if(!strcmp(regname, "sp"))  return triton::arch::ID_REG_X86_SP;
    else if(!strcmp(regname, "esp")) return triton::arch::ID_REG_X86_ESP;
    else if(!strcmp(regname, "rsp")) return triton::arch::ID_REG_X86_RSP;
    else if(!strcmp(regname, "ip"))  return triton::arch::ID_REG_X86_IP;
    else if(!strcmp(regname, "eip")) return triton::arch::ID_REG_X86_EIP;
    else if(!strcmp(regname, "rip")) return triton::arch::ID_REG_X86_RIP;

    return triton::arch::ID_REG_INVALID;
}

int parse_sym_config(char const* fname,
                     std::map<triton::arch::register_e, uint64_t>& regs,
                     std::map<uint64_t, uint8_t>& mem,
                     std::vector<triton::arch::register_e>* symregs,
                     std::vector<uint64_t>* symmem)
{
    FILE* f = fopen(fname, "r");
    if (!f) {
      ::fprintf(stderr, "Failed to open file \"%s\"\n", fname);
      return -1;
    }

    char buf[4096];
    while (fgets(buf, sizeof(buf), f)) {
        char* s = nullptr;
        if ((s = strchr(buf, '#')))  s[0] = '\0';
        if ((s = strchr(buf, '\n'))) s[0] = '\0';
        if (!(s = strchr(buf, '='))) continue;

        char* key = buf;
        char* val = s+1;
        s[0] = '\0';

        if (key[0] == '%') {
            /* key is a register name and val is an unsigned long */
            key++;
            triton::arch::register_e triton_reg = get_triton_regnum(key);
            if (triton_reg == triton::arch::ID_REG_INVALID) {
                ::fprintf(stderr, "Unrecognized register name \"%s\"\n", key);
                return -1;
            }
            if (val[0] != '$') {
                uint64_t regval = strtoul(val, nullptr, 0);
                regs[triton_reg] = regval;
            } else if (symregs) {
                symregs->push_back(triton_reg);
            }
      } else if (key[0] == '@') {
            /* key is a memory address and val is a uint8_t */
            key++;
            uint64_t addr = strtoul(key, nullptr, 0);
            if (val[0] != '$') {
                uint8_t memval = strtoul(val, nullptr, 0);
                mem[addr] = memval;
            } else if (symmem) {
                symmem->push_back(addr);
            }
        }
    }

    fclose(f);
    return 0;
}

