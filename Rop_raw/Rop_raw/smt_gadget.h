#include "gadget.hpp"
#include <set>

namespace gadget {

  class SMT_gadget {
  public:
    SMT_gadget();
    //SMT_gadget(std::multiset<Gadget*>);
    //change to constrcutor
    bool is_initialized() { return is_initialized_; };
    
  private:
    std::multiset<Gadget*> set_of_gadgets;
    bool is_initialized_ = false;
    

  };

}
