#pragma once
#include "unicorn\unicorn.h"
#include "executable_format.hpp"
#include "cpu_description.h"


namespace unicorny {
  class Emulator {
  public:
    Emulator();
    uc_engine *uc;
    bool init_unicorn(uc_mode mode_, uc_arch arch_);
    uc_err map_addres(uint64_t adress, uint64_t length);
    uc_err map_code(uint64_t address, std::string& code);
    //setup_stack(adress, size, data = none);
    //run(adress, size);
  private:
    uc_mode mode_;
    uc_arch arch_;
    const std::string ip = instruction_pointer;
    const std::string sp = stack_pointer;
    bool initialized_ = false;
  };

}// namespace unicorny