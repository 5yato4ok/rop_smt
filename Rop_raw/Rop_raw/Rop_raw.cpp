#include "Rop.h"

int main() {
  //get string with hex file
  //disasemble
  //get info (beaengine)
  //somehow make rop gadgets. watch python script
  //

  std::fstream file("x86.exe");
  ropperdis::Ropperdis test(file);
  return 0;
}

