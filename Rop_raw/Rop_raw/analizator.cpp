#include "analizator.h"
namespace sequence_helper {
AnalizeMngr::AnalizeMngr(const cpu_info::CPU_description& cpu_description) :
  emu(cpu_description), is_initialized_(emu.Init_unicorn()) {
}

GadgetDescription AnalizeMngr::GetAnalizedState(std::string& code, uintptr_t ptr,uintptr_t* stack_move) {
  uc_err result = emu.Map_code(ptr, code);
  GadgetDescription regs_condition;
  auto arch_description = emu.get_description();
  uint64_t stack = utils::get_random_page(arch_description);
  std::string stack_data = utils::random_str(arch_description.page_size);
  result = emu.Setup_stack(stack, arch_description.page_size, stack_data);
  std::map<uint32_t, uc_x86_reg> init_regs;
  for (auto const& current_reg : arch_description.common_regs_) {
    std::string random_data;
    if (current_reg.first == arch_description.instruction_pointer.begin()->first ||
      current_reg.first == arch_description.stack_pointer.begin()->first) {
      random_data = "";
      continue;
    }
    random_data = utils::random_str(arch_description.bits >> 3);
    uint64_t hex_value = std::stoll(utils::convert_string2ascii(random_data), 0, 16);
    result = emu.Setup_regist(current_reg.first, hex_value);
    init_regs[hex_value] = current_reg.first;
  }
  result = emu.Run(ptr, code.size());

  for (auto const& current_reg : arch_description.common_regs_) {
    regs_condition[current_reg.first] = { "junk", "" };
    uint32_t val_emu = emu.Get_reg_value(current_reg.first);
    if (init_regs.find(val_emu) != init_regs.end()) {
      regs_condition[current_reg.first] = { "mov", arch_description.common_regs_.at(uc_x86_reg(init_regs[val_emu])) };
      continue;
    }

    int32_t offset = utils::gen_find(utils::convert_ascii2string(utils::covert_int2hex(val_emu), 16), stack_data);
    if (offset != -1) {
      regs_condition[current_reg.first] = { "stack", std::to_string(offset) };
    }
  }
  *stack_move = get_stack_move(regs_condition,stack);
  return regs_condition;
};
int AnalizeMngr::get_stack_move(GadgetDescription& regs_condition,uintptr_t stack_value) {
  //set this to separate func
  int mov = 0;
  if (regs_condition[emu.get_description().stack_pointer.begin()->first][0] == "junk") {
    mov = emu.Get_reg_value(emu.get_description().stack_pointer.begin()->first) - stack_value;
    regs_condition[emu.get_description().stack_pointer.begin()->first] = { "add", std::to_string(mov) };
  }
  return mov;
}
} //sequnece_helper
