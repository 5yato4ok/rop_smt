#include "Rop.h"

namespace ropperdis {
Rop_Info & Ropperdis::find_rop() {
  // TODO: insert return statement here
  Rop_Info test;
  std::vector<Section*> executable_sections = exe_info.get_executables_section(input_file);
  if (executable_sections.size() == 0)
    std::cout << "It seems your binary haven't executable sections." << std::endl;
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
  if (exe_info.extract_information_from_binary(input_file) == ExecutableFormat::CPU_UNKNOWN) {
    printf("ERROR while extracting info");
    return false;
  }
  //exec_info = tmp.m_pPELayout;
  return true;
}
}