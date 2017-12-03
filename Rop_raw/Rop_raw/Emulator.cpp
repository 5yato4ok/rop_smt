#include "Emulator.h"

//Emulator::Emulator(uc_mode mode, uc_arch arch) {
//  uc_err err;
//  
//  //err = uc_open(arch, mode, &uc);
//  err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);//
//}
namespace ropperdis {
Emulator::Emulator(const uc_mode mode_, const uc_arch arch_):
  description_(mode_,arch_)
{};

bool Emulator::Init_unicorn() {
  uc_err err;
  err = uc_open(description_.arch_, description_.mode_, &uc);
  if (err != UC_ERR_OK && !description_.is_initialized()){
    return false;
  }
  initialized = true;
  return true;
}

uc_err Emulator::Map_addres(const uint64_t address, const uint64_t length) {
  page = address & description_.page_mask;
  uint64_t size = 0;
  while ((page + size) <= address + length){
    size += description_.page_size;
  }
  if (Is_initialized()) {
    return uc_mem_map(uc, page, size, UC_PROT_ALL);
  }
  return UC_ERR_MAP;
}

uc_err Emulator::Map_code(const uint64_t address, std::string const& code) {
  uc_err result = UC_ERR_WRITE_PROT;
  if (Map_addres(address, code.size()) == UC_ERR_OK) {
    result = uc_mem_write(uc, page, code.c_str(), code.length());
    if (result == UC_ERR_OK)
      code_mapped = true;
  }
  return result;
}

uc_err Emulator::Setup_regist(const uc_x86_reg reg, const uint64_t value) {
  return uc_reg_write(uc, reg, &value);
}

uint64_t Emulator::Get_reg_value(const uc_x86_reg reg) {
  uint64_t value;
  uc_err read_result = uc_reg_read(uc, reg, &value);
  if (read_result == UC_ERR_OK) {
    return value;
  }
  return read_result;
}

uc_err Emulator::Setup_stack(const uint64_t address, const uint64_t size, std::string const& data) {
  if (!Is_initialized()) {
    return UC_ERR_MAP;
  } 
  uc_err result = uc_mem_map(uc, address, size, UC_PROT_ALL);
  if (result == UC_ERR_OK) {
    if (!data.empty()) {
      result = uc_mem_write(uc, address, data.c_str(), data.size());
    }
    result = Setup_regist(description_.stack_pointer.begin()->first, address);
  }
  return result;
}

uc_err Emulator::Run(const uint64_t adress, const uint64_t size) {
  if (Is_initialized() && Code_mapped()){
    return uc_emu_start(uc, adress, adress + size,0,0);
  }
  return UC_ERR_EXCEPTION;
}

Emulator::~Emulator() {
  uc_close(uc);
}
}