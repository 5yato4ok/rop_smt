#include "Rop_finder.h"
#include "sequence_builder.h"
#include <fstream>

#pragma warning (disable : 4996 ) //function may be unsafe
#pragma warning (disable : 4005) //macro redefinition
#pragma warning (disable:4099) //pdb file wasnot found

//libz3.dll must in the same folder as result exe
int main() {
  std::fstream file("x86.exe");
  //findrop_helper::Rop_finder mngr(file, 3);
  std::multiset<Gadget*, Gadget::Sort> result;
  //if (mngr.Initialized()) {
  //  result = mngr.get_rop_resuslt();
  //}
  sequence_helper::Sequence_builder smt_mngr(file, 3);
  if (smt_mngr.Is_initialized()) {
    result = smt_mngr.get_gadget_listing();
  }
  //int counter = 0;
  //for (auto gadget : result) {
  //  counter += 1;
  //  std::cout << "Gadget #"<<counter<<std::endl;
  //  gadget->print_condition();
  //}
  //TODO: Test what happens if run on same gadget analizing two times
  //std::multiset<Gadget*, Gadget::Sort>::iterator it = result.begin();
  //Gadget* test = *it;
  //test->analize();
  //smt_mngr.model();
  smt_mngr.x86_call(0x1000, { 1 });
  file.close();
  return 0;
}

