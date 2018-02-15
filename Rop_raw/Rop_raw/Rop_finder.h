#pragma once

#include "beaengine.h"
#include "safeint.hpp"
#include "executable_format.hpp"
#include "gadget.hpp"
#include <z3++.h>
#include <cstdint>
#include <fstream>
#include <set>

namespace findrop_helper{

class Rop_finder {
 public:
  Rop_finder(std::fstream& input, uint32_t m_depth = 3);
  std::multiset<Gadget*, Gadget::Sort> get_rop_result() { return found_gadgets; };
  
  //TODO smth like that
  //std::multiset<Gadget*>generate_chain(uint32_t levels,input_condition_code)
  //std::set_condition
  const cpu_info::CPU_description& get_arch_info();
  bool Initialized() const { return initialized_; }
 private:
   std::vector<Section*> executable_sections;
   std::multiset<Gadget*, Gadget::Sort> find_rop();
   std::multiset<Gadget*> find_gadget_in_memory(const unsigned char* data, unsigned long long size, 
     unsigned long long vaddr, uint32_t m_depth = 3);
  std::multiset<Gadget*>find_all_gadget_from_ret(const unsigned char* data, unsigned long long vaddr, 
    const DISASM& ending_instr_disasm, unsigned int len_ending_instr);
  void init_disasm_struct(DISASM& d);
  bool is_valid_ending_instruction_nasm(DISASM& ending_instr_d);
  bool is_valid_ending_instruction_att(DISASM& ending_instr_d);
  bool is_valid_ending_instruction(DISASM& ending_instr_d);
  bool is_valid_instruction(DISASM& ending_instr_d);
  uint32_t m_depth;
  
  ExecutableFormat  exe_info;
  cpu_info::CPU_description cpu_info; // for now only x86 architecture
  
  bool init(std::fstream& input_file);
  bool initialized_ = false;
  std::multiset<Gadget*, Gadget::Sort> found_gadgets;
  //z3::solver z3_smt;
};

}//namespace findrop_helper
