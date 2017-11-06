#pragma once
#include "unicorn\unicorn.h"
#include <string>
#include <vector>


//TODO: do two different classes for x86 and x86-64
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
  std::vector<uc_x86_reg> common_regs; //change to std::array
  std::string return_instructions;
  int alignment;
  const uc_mode mode_;
  const uc_arch arch_;
  const uc_x86_reg str_to_reg(const std::string& str_registr);
  bool is_initialized() const { return initialized_; }
private:
  bool initialized_ = false;
};
}