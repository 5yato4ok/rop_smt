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
  if (err != UC_ERR_OK){
    return false;
  }
  initialized_ = true;
}
uc_err Emulator::map_addres(uint64_t address, uint64_t length) {
  uint64_t page = address & page_mask;
  uint64_t size = 0;
  while ((page + size) <= address + length){
    size += page_size;
  }
  uc_err result;
  if (initialized_) {
    result = uc_mem_map(uc, page, size, UC_PROT_ALL);
  }
  return result;
}

uc_err Emulator::map_code(uint64_t address, std::string& code) {
  uc_err result;
  return result;
}
}