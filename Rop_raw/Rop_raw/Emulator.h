#pragma once
#include "unicorn\unicorn.h"
#include "executable_format.hpp"
#include "cpu_description.h"


namespace ropperdis {
class Emulator {
public:
  Emulator(const uc_mode mode_, const uc_arch arch_);
  Emulator(const cpu_info::CPU_description& cpu_description);
  ~Emulator();
  uc_engine *uc;
  
  bool Init_unicorn();
  uc_err Map_addres(const uint64_t adress, const uint64_t length);
  uc_err Map_code(const uint64_t address, std::string const& code);
  uc_err Setup_stack(const uint64_t adress, const uint64_t size,std::string const& data = "");
  uc_err Setup_regist(const uc_x86_reg reg, const uint64_t value);
  uint64_t Get_reg_value(const uc_x86_reg reg);
  uc_err Run(const uint64_t adress, const uint64_t size);
  const bool Is_initialized() const { return initialized; }
  const bool Code_mapped() const { return code_mapped; }
  const cpu_info::CPU_description& get_description() const { return description_; };
private:
  uint64_t page;
  const cpu_info::CPU_description description_;
  bool initialized = false;
  bool code_mapped = false;
};

}// namespace unicorny