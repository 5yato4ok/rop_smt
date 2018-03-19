#include "sequence_builder.h"
#include <assert.h>
//TODO: write description for each function. 
namespace sequence_helper {

Sequence_builder::Sequence_builder(std::fstream& input, uint32_t m_depth, uint32_t smt_levels):
levels(smt_levels),rop_mngr(input,m_depth) {
  if (init()) {
    initialized_ = true;
  }
}

bool Sequence_builder::init() {
  set_of_gadgets = rop_mngr.get_rop_result();
  for (auto const& gadget : set_of_gadgets) {
    if (!gadget->analize()) {
      return false;
    }
  }
  return set_of_gadgets.size()!=0;
}


std::map<std::string, z3::expr_vector> Sequence_builder::start_map(std::map<std::string, z3::expr_vector> input_state) {
  std::map<std::string, z3::expr_vector> result;
  result = input_state;
  auto ptr_ip = result.find(rop_mngr.get_arch_info().instruction_pointer.begin()->second);
  auto ptr_stack = input_state.find("stack");
  ptr_ip->second = utils::z3_read_bits(ptr_stack->second, z3_context, 0, rop_mngr.get_arch_info().bits);
  auto ptr_sp = result.find(rop_mngr.get_arch_info().stack_pointer.begin()->second);
  ptr_sp->second[0] = ptr_sp->second[0] + (rop_mngr.get_arch_info().bits >> 3);
  ptr_stack->second = utils::z3_read_bits(ptr_stack->second, z3_context, rop_mngr.get_arch_info().bits);
  return result;
};

//compare values in two states return container with this comparing
z3::expr_vector Sequence_builder::equal_states(std::map<std::string, z3::expr_vector> a, std::map<std::string, z3::expr_vector> b) {
  z3::expr_vector regs_and_stack(z3_context);
  for (auto& reg : rop_mngr.get_arch_info().common_regs_) {
    z3::expr comparing(z3_context);
    if (a.at(reg.second)[0].is_bv() && b.at(reg.second)[0].is_bv()) {
      if (utils::get_bit_vector_size(a.at(reg.second)[0], z3_context) !=
        utils::get_bit_vector_size(b.at(reg.second)[0], z3_context)) {
        std::cout << "Bit_vector error.Different size comparing.\n";
        std::cout << "Error in reg:" << reg.second << std::endl;
        return regs_and_stack;
      }
      comparing = a.at(reg.second)[0] == b.at(reg.second)[0];
    } else if (a.at(reg.second)[0].is_int() && b.at(reg.second)[0].is_bv()) {
      //we need to compare values. It can be only bv_const or int_val. So extracting it
      auto value_a = a.at(reg.second)[0].get_numeral_int(); //Why intput cant be int64???
      auto value_b = b.at(reg.second)[0].extract(utils::get_bit_vector_size(b.at(reg.second)[0], z3_context) - 1, 0);
      comparing = value_a == value_b;
    } else if (a.at(reg.second)[0].is_bv() && b.at(reg.second)[0].is_int()) {
      auto value_a = a.at(reg.second)[0].extract(utils::get_bit_vector_size(a.at(reg.second)[0], z3_context) - 1, 0);
      auto value_b = b.at(reg.second)[0].get_numeral_int();
      comparing = value_a == value_b;
    }
    regs_and_stack.push_back(comparing);
  }
  z3::expr extr_a = a.at("stack")[0].extract(utils::get_bit_vector_size(b.at("stack")[0], z3_context)-1,0);
  z3::expr cmp = extr_a == b.at("stack")[0];
  regs_and_stack.push_back(cmp);
  //TODO:test on correct values
  return regs_and_stack;
}


std::map<std::string, z3::expr_vector> Sequence_builder::build_round(std::map<std::string, z3::expr_vector> input_state) {
  std::map<std::string, z3::expr_vector> fini = utils::z3_new_state(z3_context, rop_mngr.get_arch_info());
  std::map<std::string, z3::expr_vector> outs;
  auto ptr_constraints = input_state.find("constraints");
  fini.insert({ "constraints", std::forward<z3::expr_vector >(ptr_constraints->second) });
  z3::expr_vector empty_vector(z3_context);
  //TODO: fix this empty vector
  ptr_constraints->second = empty_vector;
  for (auto const & current_gadget : set_of_gadgets) {
    outs = current_gadget->map(input_state, z3_context);
    auto eq_states = equal_states(fini, outs);

    for (int i = 0; i < outs.at("constraints").size(); i++) {
      eq_states.push_back(outs.at("constraints")[i]);
    }

    auto ip = rop_mngr.get_arch_info().instruction_pointer.begin()->second;
    //TEST:get_offset or smth like that
    int size_eip = utils::get_bit_vector_size(input_state.at(ip)[0], z3_context);
    auto is_equal_ip = input_state.at(ip)[0].extract(
      utils::get_bit_vector_size(input_state.at(ip)[0], z3_context) - 1, 0) == TEST_VALUE;
    //Make a one expr from vector by anding it?
    auto and_constraints = z3::mk_and(eq_states);
    auto implies_constraints = z3::implies(is_equal_ip, and_constraints);
    auto fini_constraints = fini.find("constraints");
    fini_constraints->second.push_back(implies_constraints);
    int value = fini_constraints->second.size(); //test
  }
  auto fini_constraints = fini.find("constraints");
  for (auto const & current_gadget : set_of_gadgets) {
    auto ip = rop_mngr.get_arch_info().instruction_pointer.begin()->second;
    auto is_equal_ip = input_state.at(ip)[0].extract(
      utils::get_bit_vector_size(input_state.at(ip)[0], z3_context) - 1, 0) == TEST_VALUE;
    z3::expr_vector is_ip_vector(z3_context);
    is_ip_vector.push_back(is_equal_ip);
    auto fini_constraints = fini.find("constraints");
    auto or_constraints = z3::mk_or(is_ip_vector);
    fini_constraints->second.push_back(or_constraints);
  }
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

std::map<std::string, z3::expr_vector> Sequence_builder::map(std::map<std::string, z3::expr_vector> z3_state) {
  //TODO: add some checking
  //TODO: fix multiple maps.are the needed
  //auto z3_state = utils::z3_new_state(z3_context, rop_mngr.get_arch_info());
  z3_state = start_map(z3_state);
  z3_state = smt_map(z3_state); // in wich calls build round. in wich calls map for real gadget


  //checking
  auto ptr_ip = z3_state.find("constraints");
  size_t tmp = ptr_ip->second.size();
  bool check = ptr_ip->second[0].is_bv();
  return z3_state;
}

std::map<std::string, z3::expr_vector> Sequence_builder::map_x86_call(std::map<std::string, z3::expr_vector> z3_state, 
  uintptr_t call_address, std::vector<uintptr_t>args) {
  auto out_state = z3_state;
  auto ptr_ip_input = z3_state.find(rop_mngr.get_arch_info().instruction_pointer.begin()->second);
  auto is_ip_equal_address = ptr_ip_input->second[0].extract(
    utils::get_bit_vector_size(ptr_ip_input->second[0], z3_context) - 1, 0) == (int)call_address;
  auto ptr_constr_out = out_state.find("constraints");
  ptr_constr_out->second.push_back(is_ip_equal_address);
  
  int mov = 4;
  auto ptr_stack_out = out_state.find("stack");
  ptr_stack_out->second = utils::z3_read_bits(z3_state.at("stack"), z3_context, mov * 8);
  auto ptr_ip_out = out_state.find(rop_mngr.get_arch_info().instruction_pointer.begin()->second);
  ptr_ip_out->second = utils::z3_read_bits(z3_state.at("stack"), z3_context,0, rop_mngr.get_arch_info().bits);
  int i = 0;
  for (auto&arg : args) {
    int bits = rop_mngr.get_arch_info().bits;
    z3::expr arg_stack = utils::z3_read_bits(z3_state.at("stack"),z3_context, i * bits, bits)[0];
    auto is_arg_stack_equal_address = arg_stack.extract(
      utils::get_bit_vector_size(arg_stack, z3_context) - 1, 0) == (int)arg;
    ptr_constr_out->second.push_back(is_arg_stack_equal_address);
  }
  return out_state;
}

void Sequence_builder::x86_call(uintptr_t call_address, std::vector<uintptr_t>args) {
  //TODO: add for amd64 call
  input_state_ = utils::z3_new_state(z3_context, rop_mngr.get_arch_info());
  out_state_ = map(input_state_);
  out_state_ = map_x86_call(out_state_, call_address, args);
  model();
}

z3::model Sequence_builder::model() {
  //Make somehow
  z3::solver solver(z3_context);
  for (auto & reg : rop_mngr.get_arch_info().common_regs_) {
    if (reg.second == rop_mngr.get_arch_info().instruction_pointer.begin()->second) {
      continue;
    }
    z3::expr exp(z3_context);
    if (out_state_.at(reg.second)[0].is_bv()) {
      exp = out_state_.at(reg.second)[0].extract(utils::get_bit_vector_size(
        out_state_.at(reg.second)[0], z3_context) - 1, 0) == 0;
    } else {
      exp = out_state_.at(reg.second)[0] == 0;
    }
    solver.add(exp);
  }
  //z3_expr has no begin, so we have to use this cicle
  for (int i = 0; i < out_state_.at("constraints").size();i++) {
    z3::expr exp = out_state_.at("constraints")[i]; //all expr must be bool
    if (exp.is_bool()) {
      solver.add(exp);//error here
    }
  }
  if (solver.check() == z3::sat) {
    std::cout << "Its working!";
  } else {
    //TODO:add valid gadgets and constraints
    std::cout << "Well, it's not working...";
    ::ExitProcess(0);
  }
  return solver.get_model();
}


void Sequence_builder::use() {
  //TODO: rewrite from python
  //if not model : model = self.model()
  //  ins, outs, m = model
  //  stack_size = outs[self.arch.sp] - ins[self.arch.sp]
  //  stack_size = int(str(m.eval(stack_size)))
  //  return z3_model_read_bytes(m, ins["stack"], 0, stack_size)
}

}//namespace sequence_helper

