#include <cassert>
#include <iostream>
#include <map>
#include <string>
#include <unordered_map>

#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>

#include "../inc/loader.h"
#include "disasm_util.h"
#include "triton_util.h"

void print_slice(triton::API& api, Section const& section, uint64_t addr, triton::arch::register_e reg, std::string const& regName)
{
    auto regExpr = api.getSymbolicRegisters()[reg];
    std::unordered_map<triton::usize, triton::engines::symbolic::SharedSymbolicExpression> slice = api.sliceExpressions(regExpr);

    for (auto const& [key, value] : slice) {
        ::printf("%s\n", value->getComment().c_str());
    }

    char mnemonic[32], operands[128];
    disasm_one(section, addr, mnemonic, operands);
    std::string target = mnemonic;
    target += ' ';
    target += operands;
    ::printf("(slice for %s @ 0x%lx: %s)\n", regName.c_str(), addr, target.c_str());
}

int main(int argc, char* argv[])
{
    if (argc < 6) {
        ::fprintf(stderr, "Usage: %s <binary> <sym-config> <entry> <slice-addr> <reg>\n", argv[0]);
        return 1;
    }

    std::string fname(argv[1]);
    Binary bin;
    bin.init(argv[1], Binary::Type::Auto, false);
    if (!bin.is_valid()) {
        return 1;
    }

    triton::API api;
    triton::arch::register_e ip;
    if (set_triton_arch(bin, api, ip) < 0) {
        return 1;
    }

    api.setMode(triton::modes::ALIGNED_MEMORY, true);

    std::map<triton::arch::register_e, uint64_t> regs;
    std::map<uint64_t, uint8_t> mem;
    if (parse_sym_config(argv[2], regs, mem) < 0) {
        return 1;
    }

    for (auto const& [key, value] : regs) {
        auto r = api.getRegister(key);
        api.setConcreteRegisterValue(r, value);
    }

    for (auto const& [key, value] : mem) {
        api.setConcreteMemoryValue(key, value);
    }

    uint64_t pc = strtoul(argv[3], nullptr, 0);
    uint64_t slice_addr = strtoul(argv[4], nullptr, 0);
    std::optional<Section> text = bin.get_text_section();
    assert(text.has_value());

    while (text.value().contains(pc)) {
        char mnemonic[32], operands[128];
        int len = disasm_one(text.value(), pc, mnemonic, operands);
        if (len <= 0) {
            return 1;
        }

        triton::arch::Instruction insn;
        insn.setOpcode(text.value().bytes() + (pc - text.value().vma()), len);
        insn.setAddress(pc);

        api.processing(insn);

        for (auto const& se : insn.symbolicExpressions) {
            std::string comment = mnemonic;
            comment += ' ';
            comment += operands;
            se->setComment(comment);
        }

        if (pc == slice_addr) {
            print_slice(api, text.value(), slice_addr, get_triton_regnum(argv[5]), argv[5]);
            break;
        }

        pc = static_cast<uint64_t>(api.getConcreteRegisterValue(api.getRegister(ip)));
    }

    return 0;
}

