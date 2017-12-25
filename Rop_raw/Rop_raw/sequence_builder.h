#include "Rop_finder.h"
#include <set>
#include <fstream>
#include <cstdint>

namespace sequence_helper {

class Sequence_builder {
public:
  //SMT_gadget();
  Sequence_builder(std::fstream& input, uint32_t m_depth = 3, uint32_t smt_levels_ = 1); //plus some context
  bool is_initialized() { return initialized_; };
  void map();
private:
  int levels;
  z3::context z3_context;
  findrop_helper::Rop_finder rop_mngr;
  std::map<std::string, z3::expr_vector> z3_state;
  std::map<std::string, z3::expr_vector> start_map(std::map<std::string, z3::expr_vector> input_state);
  std::map<std::string, z3::expr_vector> smt_map(std::map<std::string, z3::expr_vector> input_state);
  std::map<std::string, z3::expr_vector> gadget_map(std::map<std::string, z3::expr_vector> input_state);
  std::map<std::string, z3::expr_vector> build_round(std::map<std::string, z3::expr_vector> input_state);
  std::multiset<Gadget*, Gadget::Sort> set_of_gadgets;
  bool initialized_ = false;
  bool init();

};

}
