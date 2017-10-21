#include "Rop.h"
#include <fstream>

#pragma warning (disable : 4996 ) //function may be unsafe
#pragma warning (disable : 4005) //macro redefinition

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

