#include "Rop_finder.h"
#include <set>
#include <fstream>
#include <cstdint>

namespace sequence_helper {

class Sequence_builder {
 public:
  //SMT_gadget();
  Sequence_builder(std::fstream& input, uint32_t m_depth = 3, uint32_t smt_levels_ = 1); //plus some context
  bool Is_initialized() { return initialized_; };
  std::multiset<Gadget*, Gadget::Sort> get_gadget_listing() { return rop_mngr.get_rop_result(); };
  void use();
  z3::model model();
  void x86_call(uintptr_t call_address, std::vector<uintptr_t>args = {}); //TODO

 private:
  
   SMTGadgetDescription map(SMTGadgetDescription z3_state); //TODO
   SMTGadgetDescription map_x86_call(SMTGadgetDescription z3_state,
    uintptr_t call_address, std::vector<uintptr_t>args);
   SMTGadgetDescription input_state_;
   SMTGadgetDescription out_state_;
  int levels;
  z3::context z3_context;
  findrop_helper::Rop_finder rop_mngr;
  //std::map<std::string, z3::expr_vector> z3_state;
  z3::expr_vector equal_states(SMTGadgetDescription a, SMTGadgetDescription b);
  SMTGadgetDescription start_map(SMTGadgetDescription input_state);
  SMTGadgetDescription smt_map(SMTGadgetDescription input_state);
  SMTGadgetDescription build_round(SMTGadgetDescription input_state);
  std::multiset<Gadget*, Gadget::Sort> set_of_gadgets;
  bool initialized_ = false;
  bool init();

};

}//namespace sequence builder

