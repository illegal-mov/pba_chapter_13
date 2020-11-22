#include <cassert>
#include <map>
#include <triton/ast.hpp>
#include <vector>

#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>

#include "../inc/loader.h"
#include "disasm_util.h"
#include "triton_util.h"

void find_new_input(triton::API& api, Section const& section, uint64_t branchAddr)
{
    triton::ast::SharedAstContext const& ast = api.getAstContext();
    triton::ast::SharedAbstractNode constraintList = ast->equal(ast->bvtrue(), ast->bvtrue());

    ::printf("evaluating branch 0x%lx\n", branchAddr);

    std::vector<triton::engines::symbolic::PathConstraint> const& pathConstraints = api.getPathConstraints();
    for (auto const& pc : pathConstraints) {
        if (pc.isMultipleBranches()) {
            for (auto const& branchConstraint : pc.getBranchConstraints()) {
                auto [wasBranchTaken, srcAddr, dstAddr, constraint] = branchConstraint;

                if (srcAddr != branchAddr) {
                    // this is not our target branch, so keep the existing "true" constraint
                    if (wasBranchTaken) {
                        constraintList = ast->land(constraintList, constraint);
                    }
                }
                else {
                    // this is our target branch, compute new input
                    ::printf("    0x%lx -> 0x%lx (", srcAddr, dstAddr);
                    if (!wasBranchTaken) {
                        ::printf("not ");
                    }
                    ::puts("taken)");
                    if (!wasBranchTaken) {
                        ::printf("    computing new input for 0x%lx -> 0x%lx\n", srcAddr, dstAddr);
                        constraintList = ast->land(constraintList, constraint);
                        for (auto const& [symVar, value] : api.getModel(constraintList)) {
                            ::printf("    SymVar %lu (%s) = 0x%lx\n", symVar, api.getSymbolicVariable(symVar)->getComment().c_str(), static_cast<uint64_t>(value.getValue()));
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char* argv[])
{
    if (argc < 5) {
        ::fprintf(stderr, "Usage: %s <binary> <sym-config> <entry> <branch-addr>\n", argv[0]);
        return 1;
    }

    std::string fname(argv[1]);
    Binary bin;
    bin.init(argv[1], Binary::Type::Auto, false);
    if (!bin.is_valid()) {
        std::cout << "invalid binary\n";
        return 1;
    }

    triton::API api;
    triton::arch::register_e ip;
    if (set_triton_arch(bin, api, ip) < 0) {
        std::cout << "set triton arch failed\n";
        return 1;
    }

    api.setMode(triton::modes::ALIGNED_MEMORY, true);

    std::map<triton::arch::register_e, uint64_t> regs;
    std::map<uint64_t, uint8_t> mem;
    std::vector<triton::arch::register_e> symRegs;
    std::vector<uint64_t> symMem;
    if (parse_sym_config(argv[2], regs, mem, &symRegs, &symMem) < 0) {
        std::cout << "parse failed\n";
        return 1;
    }

    for (auto const& [regId, concreteValue] : regs) {
        auto r = api.getRegister(regId);
        api.setConcreteRegisterValue(r, concreteValue);
    }

    for (auto const& [memAddr, value] : mem) {
        api.setConcreteMemoryValue(memAddr, value);
    }

    for (auto const& regId : symRegs) {
        triton::arch::Register r = api.getRegister(regId);
        api.symbolizeRegister(r)->setComment(r.getName());
    }

    for (auto const& memAddr : symMem) {
        api.symbolizeMemory(triton::arch::MemoryAccess(memAddr, 1))->setComment(std::to_string(memAddr));
    }

    uint64_t pc = strtoul(argv[3], nullptr, 0);
    uint64_t branchAddr = strtoul(argv[4], nullptr, 0);
    std::optional<Section> text = bin.get_text_section();
    assert(text.has_value());

    std::cout << "beginning loop\n";
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

        if (pc == branchAddr) {
            find_new_input(api, text.value(), branchAddr);
            break;
        }

        pc = static_cast<uint64_t>(api.getConcreteRegisterValue(api.getRegister(ip)));
    }

    return 0;
}

