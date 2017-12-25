#include "sequence_builder.h"

namespace sequence_helper {

Sequence_builder::Sequence_builder(std::fstream& input, uint32_t m_depth, uint32_t smt_levels):
levels(smt_levels),rop_mngr(input,m_depth){
  if (init()) {
    initialized_ = true;
  }
}

bool Sequence_builder::init() {
  return true;
}


std::map<std::string, z3::expr_vector> Sequence_builder::start_map(std::map<std::string, z3::expr_vector> input_state) {
  std::map<std::string, z3::expr_vector> result;
  result = input_state;
  //TODO: if change iterator will it change the value?
  auto ptr_ip = result.find(rop_mngr.get_arch_info().instruction_pointer.begin()->second);
  auto ptr_stack = z3_state.find("stack");
  ptr_ip->second = utils::z3_read_bits(ptr_stack->second, z3_context, 0, rop_mngr.get_arch_info().bits);
  auto ptr_sp = result.find(rop_mngr.get_arch_info().stack_pointer.begin()->second);
  ptr_sp->second[0] = ptr_sp->second[0] + (rop_mngr.get_arch_info().bits >> 3);
  ptr_stack->second = utils::z3_read_bits(ptr_stack->second, z3_context, rop_mngr.get_arch_info().bits);
  return result;
};

std::map<std::string, z3::expr_vector> Sequence_builder::build_round(std::map<std::string, z3::expr_vector> input_state) {
  std::map<std::string, z3::expr_vector> fini = utils::z3_new_state(z3_context, rop_mngr.get_arch_info());
  auto ptr_constraints = z3_state.find("constraints");
  fini.insert({ "constraints", std::forward<z3::expr_vector &>(ptr_constraints->second) });
  z3::expr_vector empty_vector(z3_context);
  //TODO: fix this empty vector
  ptr_constraints->second = empty_vector;
  //for 
  return fini;
}

std::map<std::string, z3::expr_vector> Sequence_builder::smt_map(std::map<std::string, z3::expr_vector> input_state) {
  std::map<std::string, z3::expr_vector> result;
  result = input_state;
  z3::expr_vector gadgets_v(z3_context);
  for (int i = 0; i < levels; i++) {
    auto ptr_ip = result.find(rop_mngr.get_arch_info().instruction_pointer.begin()->second);
    gadgets_v.push_back(ptr_ip->second[0]);
    result = build_round(result);
  }
  result.insert({ "gadgets", std::forward<z3::expr_vector &>(gadgets_v) });
  return result;
};

void Sequence_builder::map() {
  //TODO: fix multiple maps.are the needed
  z3_state = utils::z3_new_state(z3_context, rop_mngr.get_arch_info());
  z3_state = start_map(z3_state);
  z3_state = smt_map(z3_state); // in wich calls build round. in wich calls map for real gadget

  //checking
  auto ptr_ip = z3_state.find("constraints");
  size_t tmp = ptr_ip->second.size();
  bool check = ptr_ip->second[0].is_bv();

}

std::map<std::string, z3::expr_vector> Sequence_builder::gadget_map(std::map<std::string, z3::expr_vector> input_state) {
  std::map<std::string, z3::expr_vector> result;
  //if (!is_analized)
  //  return result;
  //z3_state = utils::z3_new_state(z3_context, emu.get_description());
  //z3_state["constraints"].push_back(z3_state[emu.get_description().instruction_pointer.begin()->second] == address);
  int smth = 2;
  return result;
}

}
