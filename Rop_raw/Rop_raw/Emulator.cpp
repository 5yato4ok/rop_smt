#include "Emulator.h"

//Emulator::Emulator(uc_mode mode, uc_arch arch) {
//  uc_err err;
//  
//  //err = uc_open(arch, mode, &uc);
//  err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);//
//}
namespace unicorny {
Emulator::Emulator() {};
bool Emulator::init_unicorn(uc_mode mode_, uc_arch arch_) {
  uc_err err;
  err = uc_open(arch_, mode_, &uc);
  //err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
  return false;
}
}