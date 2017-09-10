#include "Rop.h"

int main() {
  //get string with hex file
  //disasemble
  //get info (beaengine)
  //somehow make rop gadgets. watch python script
  //

  std::fstream file("x86.exe");
  ropperdis::Ropperdis mngr(file);
  std::vector<int> result_gadgets;
  if (mngr.initialized()) {
    mngr.find_rop();
  }

  return 0;
}

