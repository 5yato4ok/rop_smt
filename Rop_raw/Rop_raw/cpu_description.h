#pragma once
#include "unicorn\unicorn.h"
#include <string>
#include <map>
#include <vector>


//TODO: do two different classes for x86 and x86-64
//make all constant
namespace cpu {
class CPU_description {
public:
  CPU_description(uc_mode mode, uc_arch arch);
  int bits;
  uc_x86_reg instruction_pointer;
  uc_x86_reg stack_pointer;
  int64_t address_mask;
  int64_t page_mask;
  int64_t page_size;
  std::string return_instructions;
  int alignment;
  const uc_mode mode_;
  const uc_arch arch_;
  std::map<uc_x86_reg, std::string> common_regs_;
  bool is_initialized() const { return initialized_; }
private:
  bool initialized_ = false;
};
}