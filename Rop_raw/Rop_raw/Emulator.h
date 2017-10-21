#pragma once
//#include "unicorn\unicorn.h"
#include "executable_format.hpp"

namespace unicorny {
  class Emulator {
  public:
    Emulator();
    uc_engine *uc;
    bool init_unicorn(uc_mode mode_, uc_arch arch_);

  private:
    uc_mode mode_;
    uc_arch arch_;
    //arch);
    //arch = arch;//structure with architectur and mode
    //uc = unicorn.uc(ar);
    ////get_item?
    ////setitem?
    //map_addres(adress, length);
    //map_code(adress, code);
    //setup_stack(adress, size, data = none);
    //run(adress, size);
  };

}// namespace unicorny