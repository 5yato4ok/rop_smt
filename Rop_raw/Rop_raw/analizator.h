#pragma once
#include <stdint.h>
#include "Emulator.h"
#include "utils.h"
#include <z3++.h>

namespace sequence_helper {

enum class category :int32_t{ STORE, ADJUST, CALL,SYSCALL,LOAD,UNKNOWN };
using GadgetDescription = std::map<uc_x86_reg, std::vector<std::string>>;
using SMTGadgetDescription = std::map<std::string, z3::expr_vector>;
class AnalizeMngr {
 public:
  AnalizeMngr(const cpu_info::CPU_description& description);
  bool Is_initialized() { return is_initialized_; }
  GadgetDescription GetAnalizedState(std::string& code, uintptr_t ptr, uintptr_t* stack_move);
  SMTGadgetDescription GetMappedState(SMTGadgetDescription input_state, GadgetDescription& reg_descr, //TODO: change
    z3::context& z3_context, uintptr_t mov, int code_ptr);
 private:
  int get_stack_move(GadgetDescription& regs_condition, uintptr_t stack_move,ropperdis::Emulator& emu_);
  const cpu_info::CPU_description& cpu_description;
  bool is_initialized_ = false;
};

}//namespace sequence_helper
