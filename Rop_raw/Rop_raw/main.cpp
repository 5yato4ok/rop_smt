#include "Rop.h"
#include <fstream>
int main() {
  //get string with hex file
  //disasemble
  //get info (beaengine)
  //somehow make rop gadgets. watch python script
  //

  std::fstream file("x86.exe");
  ropperdis::Ropperdis mngr(file);
  std::multiset<Gadget*, Gadget::Sort> result;
  if (mngr.initialized()) {
    result = mngr.find_rop();
  }
  std::multiset<Gadget*, Gadget::Sort>::iterator it = result.begin();
  Gadget* test = *it;
  test->analize();
  file.close();
  return 0;
}

