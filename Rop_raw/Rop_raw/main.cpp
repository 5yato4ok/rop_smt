#include "Rop.h"
#include <fstream>

#pragma warning (disable : 4996 ) //function may be unsafe
#pragma warning (disable : 4005) //macro redefinition
#pragma warning (disable:4099) //pdb file wasnot found

//libz3.dll must in the same folder as result exe
int main() {
  std::fstream file("x86.exe");
  ropperdis::Ropperdis mngr(file);
  std::multiset<Gadget*, Gadget::Sort> result;
  if (mngr.Initialized()) {
    result = mngr.find_rop();
  }
  std::multiset<Gadget*, Gadget::Sort>::iterator it = result.begin();
  Gadget* test = *it;
  test->analize();
  file.close();
  return 0;
}

