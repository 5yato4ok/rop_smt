#pragma once
#include <stdint.h>
#include "gadget.hpp"
#include "Emulator.h"
#include "utils.h"
#include <z3++.h>
#include <set>
#include <map>
namespace sequence_helper {

enum class category :int32_t{ STORE, ADJUST, CALL,SYSCALL,LOAD,UNKNOWN };

using GadgetDescription = std::map<uc_x86_reg, std::vector<std::string>>;
using SMTGadgetDescription = std::map<std::string, z3::expr_vector>;
class AnalizeMngr {
 public:
  AnalizeMngr(const cpu_info::CPU_description& description);
  bool Is_initialized() { return is_initialized_; }
  bool AnaliseGadgets(std::multiset<Gadget*, Gadget::Sort>gadgets_set);
  SMTGadgetDescription MapGadgets(SMTGadgetDescription input_state, z3::context& z3_context, Gadget& gadget);
 private:
  SMTGadgetDescription get_mapped_state(SMTGadgetDescription input_state,Gadget& gadget,GadgetDescription primary_descr, z3::context& z3_context);
  GadgetDescription get_analized_state(Gadget gadget);
  std::map<Gadget,GadgetDescription> gadgets_descr;
  std::map<Gadget, int> gadget_stack_mov;
  int get_stack_move(GadgetDescription& regs_condition, uintptr_t stack_move,ropperdis::Emulator& emu_);
  const cpu_info::CPU_description& cpu_description;
  bool is_initialized_ = false;
};

}//namespace sequence_helper
