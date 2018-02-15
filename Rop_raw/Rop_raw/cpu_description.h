#pragma once
#include "unicorn\unicorn.h"
#include <string>
#include <map>
#include <vector>


//TODO: do two different classes for x86 and x86-64
//make all constant
namespace cpu_info {
class CPU_description {
 public:
  CPU_description(uc_mode mode, uc_arch arch);
  CPU_description(const CPU_description& copy_value);
  int bits;
  //change to container with unique key and value
  std::map<uc_x86_reg, std::string> instruction_pointer; 
  std::map<uc_x86_reg, std::string> stack_pointer;
  int64_t address_mask;
  int64_t page_mask;
  int64_t page_size;
  std::string return_instructions;
  int alignment;
  uc_mode mode_;
  uc_arch arch_;
  std::map<uc_x86_reg, std::string> common_regs_;
  bool is_initialized() const { return initialized_; }
private:
  bool initialized_ = false;
};
}