#pragma once
#include "unicorn\unicorn.h"
#include "executable_format.hpp"
#include "cpu_description.h"


namespace unicorny {
  class Emulator {
  public:
    Emulator(uc_mode mode_, uc_arch arch_);
    ~Emulator();
    uc_engine *uc;
    bool init_unicorn();
    uc_err map_addres(uint64_t adress, uint64_t length);
    uc_err map_code(uint64_t address, std::string& code);
    //setup_stack(adress, size, data = none);
    uc_err run(uint64_t adress, uint64_t size);
  private:
    uint64_t page;
    CPU_description description;
    //const std::string ip = instruction_pointer;
    //const std::string sp = stack_pointer;
    bool initialized_ = false;
    bool code_mapped_ = false;
  };

}// namespace unicorny