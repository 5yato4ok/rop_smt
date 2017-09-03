#pragma once
#include "beaengine.h"
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
    std::fstream& input_file;

  };
}