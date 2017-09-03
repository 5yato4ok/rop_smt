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
  bool initialized() { return initialized_; }
 private:
  PortableExecutableLayout* exec_info;
  bool init();
  bool initialized_ = false;
  std::fstream& input_file;

};
}//namespace ropperdis
