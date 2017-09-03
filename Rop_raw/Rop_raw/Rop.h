#pragma once
#include "beaengine.h"
#include <executable_format.hpp>
#include <fstream>

#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL

namespace ropperdis {
  struct Rop_Info {

  };

  class Ropperdis {
  public:
    Ropperdis(std::fstream& input);
    Rop_Info& find_rop();
  private:
    ExecutableFormat* exec_info;
    std::fstream& input_file;

  };
}