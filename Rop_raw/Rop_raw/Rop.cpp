#include "Rop.h"

namespace ropperdis {
Rop_Info & Ropperdis::find_rop() {
  // TODO: insert return statement here
  Rop_Info test;
  return test;
}
Ropperdis::Ropperdis(std::fstream& input) :input_file(input) {
  unsigned int magic_dword = 0;
  input.read((char*)&magic_dword, sizeof(magic_dword));
  if (init()) {
    initialized_ = true;
  }
};

bool Ropperdis::init() {
  ExecutableFormat tmp;
  if (tmp.extract_information_from_binary(input_file) == ExecutableFormat::CPU_UNKNOWN) {
    printf("ERROR while extracting info");
    return false;
  }
  exec_info = tmp.m_pPELayout;
  return true;
}
}