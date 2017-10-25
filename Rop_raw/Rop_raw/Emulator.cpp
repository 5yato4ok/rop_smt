#include "Emulator.h"

//Emulator::Emulator(uc_mode mode, uc_arch arch) {
//  uc_err err;
//  
//  //err = uc_open(arch, mode, &uc);
//  err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);//
//}
namespace ropperdis {
  Emulator::Emulator(uc_mode mode_, uc_arch arch_):
    description(mode_,arch_)
  {};
bool Emulator::init_unicorn() {
  uc_err err;
  err = uc_open(description.arch_, description.mode_, &uc);
  if (err != UC_ERR_OK && !description.is_initialized()){
    return false;
  }
  initialized_ = true;
  return true;
}
uc_err Emulator::map_addres(uint64_t address, uint64_t length) {
  page = address & description.page_mask;
  uint64_t size = 0;
  while ((page + size) <= address + length){
    size += description.page_size;
  }
  if (initialized_) {
    return uc_mem_map(uc, page, size, UC_PROT_ALL);
  }
  return UC_ERR_MAP;
}

uc_err Emulator::map_code(uint64_t address, std::string& code) {
  uc_err result = UC_ERR_WRITE_PROT;
  if (map_addres(address, code.length()) == UC_ERR_OK) {
    result = uc_mem_write(uc, page, code.c_str(), code.length());
    if (result == UC_ERR_OK)
      code_mapped_ = true;
  }
  return result;
}

Emulator::~Emulator() {
  uc_close(uc);
}

uc_err Emulator::run(uint64_t adress, uint64_t size) {
  if (initialized_ && code_mapped_){
    return uc_emu_start(uc, adress, adress + size,0,0);
  }
  return UC_ERR_EXCEPTION;
}
}