#ifndef TRITON_UTIL_H
#define TRITON_UTIL_H

#include <map>
#include <stdint.h>

#include <triton/api.hpp>

class Binary;

int set_triton_arch(Binary const& bin, triton::API& api, triton::arch::register_e& ip);

triton::arch::register_e get_triton_regnum(char* regname);

int parse_sym_config(
  const char* fname,
  std::map<triton::arch::register_e, uint64_t>& regs,
  std::map<uint64_t, uint8_t>& mem,
  std::vector<triton::arch::register_e>* symregs = nullptr,
  std::vector<uint64_t>* symmem = nullptr
);

#endif /* TRITON_UTIL_H */
