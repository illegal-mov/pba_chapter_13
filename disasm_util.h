#ifndef DISASM_UTIL_H
#define DISASM_UTIL_H

#include <stdint.h>

class Section;

int disasm_one(Section const& sec, uint64_t addr, char* mnemonic, char* op_str);

#endif /* DISASM_UTIL_H */
