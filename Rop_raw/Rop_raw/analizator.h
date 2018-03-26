#pragma once
#include <stdint.h>
#include "Emulator.h"
#include "utils.h"

namespace sequence_helper {

enum class category :int32_t{ STORE, ADJUST, CALL,SYSCALL,LOAD,UNKNOWN };
using GadgetDescription = std::map<uc_x86_reg, std::vector<std::string>>;

class AnalizeMngr {
 public:
  AnalizeMngr(const cpu_info::CPU_description& description);
  bool Is_initialized() { return is_initialized_; }
  GadgetDescription GetAnalizedState(std::string& code, uintptr_t ptr, uintptr_t* stack_move);
  
 private:
  int get_stack_move(GadgetDescription& regs_condition, uintptr_t stack_move);
  ropperdis::Emulator emu;
  bool is_initialized_ = false;
};

}//namespace sequence_helper
