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
  void model();
  std::map<std::string, z3::expr_vector> map(); //TODO
  void use(); //TODO

 private:

  int levels;
  z3::context z3_context;
  findrop_helper::Rop_finder rop_mngr;
  //std::map<std::string, z3::expr_vector> z3_state;
  z3::expr_vector equal_states(std::map<std::string, z3::expr_vector> a, std::map<std::string, z3::expr_vector> b);
  std::map<std::string, z3::expr_vector> start_map(std::map<std::string, z3::expr_vector> input_state);
  std::map<std::string, z3::expr_vector> smt_map(std::map<std::string, z3::expr_vector> input_state);
  std::map<std::string, z3::expr_vector> build_round(std::map<std::string, z3::expr_vector> input_state);
  std::multiset<Gadget*, Gadget::Sort> set_of_gadgets;
  bool initialized_ = false;
  bool init();

};

}//namespace sequence builder

