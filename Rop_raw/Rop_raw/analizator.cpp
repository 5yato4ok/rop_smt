#include "analizator.h"
namespace sequence_helper {
AnalizeMngr::AnalizeMngr(const cpu_info::CPU_description& cpu_description_) :
cpu_description(cpu_description_), is_initialized_(cpu_description.is_initialized()) {
}

GadgetDescription AnalizeMngr::GetAnalizedState(std::string& code, uintptr_t ptr,uintptr_t* stack_move) {
  ropperdis::Emulator emu(cpu_description);
  GadgetDescription regs_condition;
  if (!emu.Init_unicorn())
    return regs_condition;
  uc_err result = emu.Map_code(ptr, code);
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
  *stack_move = get_stack_move(regs_condition,stack,emu);
  return regs_condition;
};
int AnalizeMngr::get_stack_move(GadgetDescription& regs_condition, uintptr_t stack_value, ropperdis::Emulator& emu_) {
  int mov = 0;
  if (regs_condition[cpu_description.stack_pointer.begin()->first][0] == "junk") {
    mov = emu_.Get_reg_value(cpu_description.stack_pointer.begin()->first) - stack_value;
    regs_condition[cpu_description.stack_pointer.begin()->first] = { "add", std::to_string(mov) };
  }
  return mov;
}

SMTGadgetDescription AnalizeMngr::GetMappedState(SMTGadgetDescription input_state, 
  GadgetDescription& regs_condition, z3::context& z3_context,uintptr_t mov, int code_ptr) {
  auto out_state = input_state;
  auto ptr_ip_input = input_state.find(cpu_description.instruction_pointer.begin()->second);

  //TEST: get_first_offset() or maybe here get_first_absolute_address(void)
  //We can compare bitvector only by extracting its value.

  auto is_ip_equal_address = ptr_ip_input->second[0].extract(
    utils::get_bit_vector_size(ptr_ip_input->second[0], z3_context) - 1, 0) == code_ptr;
  auto ptr_constr_out = out_state.find("constraints");
  ptr_constr_out->second.push_back(is_ip_equal_address);
  for (auto & reg : regs_condition) {
    auto ptr_reg_out = out_state.find(cpu_description.common_regs_.at(reg.first));
    if (reg.second[0] == "mov") {
      ptr_reg_out->second = input_state.at(cpu_description.common_regs_.at(reg.first));
    } else if (reg.second[0] == "stack") {
      ptr_reg_out->second = utils::z3_read_bits(input_state.at("stack"), z3_context,
        std::stoi(reg.second[1]) * 8, cpu_description.bits);
    } else if (reg.second[0] == "add") {
      auto tmp_expr = input_state.at(cpu_description.common_regs_.at(reg.first))[0];
      z3::expr_vector tmp_vector(z3_context);
      tmp_vector.push_back(tmp_expr + std::stoi(reg.second[1]));
      ptr_reg_out->second = tmp_vector;
    } else if (reg.second[0] == "junk") {
      z3::expr_vector tmp_vector(z3_context);
      tmp_vector.push_back(z3_context.int_val(utils::random_int(0, 2 * cpu_description.bits)));
      ptr_reg_out->second = tmp_vector;
    }
  }
  if (mov >= 0) {
    auto ptr_stack_out = out_state.find("stack");
    ptr_stack_out->second = utils::z3_read_bits(input_state.at("stack"), z3_context, mov * 8);
  }
  return out_state;
}
} //sequnece_helper
