#include "Rop_finder.h"
#include <set>
#include <fstream>
#include <cstdint>

namespace sequence_helper {

class Sequence_builder {
public:
  //SMT_gadget();
  Sequence_builder(std::fstream& input, uint32_t m_depth = 3); //plus some context
  bool is_initialized() { return initialized_; };
    
private:
  std::multiset<Gadget*, Gadget::Sort> set_of_gadgets;
  bool initialized_ = false;
  bool init();

};

}
