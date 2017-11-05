#include "cpu_description.h"

namespace cpu {
CPU_description::CPU_description(uc_mode mode, uc_arch arch) :
  mode_(mode), arch_(arch) {
  switch (arch) {
  case UC_ARCH_X86:
    switch (mode) {
    case UC_MODE_32:
      bits = 32;
      instruction_pointer = UC_X86_REG_EIP;
      stack_pointer = UC_X86_REG_ESP;
      common_regs = { UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP,
        UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EIP };
      address_mask = 0xffffffff;
      page_mask = 0xfffff000;
      page_size = 0x1000;
      return_instructions = "\xc3";
      alignment = 1;
      break;
    case UC_MODE_64:
      bits = 64;
      instruction_pointer = UC_X86_REG_RIP;
      stack_pointer = UC_X86_REG_RSP;
      common_regs = { UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP, 
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RIP};
      address_mask = 0x0000007fffffffff;
      page_mask = 0x0000007ffffff000;
      page_size = 0x1000;
      return_instructions = "\xc3";
      alignment = 1;
      break;
    default:
      initialized_ = false;
    }
  default:
    initialized_ = false;
  }
};

uc_x86_reg str_to_reg(const std::string& str_registr) {
  if (str_registr == "rax") {
    return UC_X86_REG_RAX;
  } else if (str_registr == "rbx") {
    return UC_X86_REG_RBX;
  } else if (str_registr == "rcx") {
    return UC_X86_REG_RCX;
  } else if (str_registr == "rdx") {
    return UC_X86_REG_RDX;
  } else if (str_registr == "rsp") {
    return UC_X86_REG_RSP;
  } else if (str_registr == "rsi") {
    return UC_X86_REG_RSI;
  } else if (str_registr == "rdi") {
    return UC_X86_REG_RBX;
  } else if (str_registr == "rip") {
    return UC_X86_REG_RBX;
  } else if (str_registr == "rbp") {
    return UC_X86_REG_RBP;
  } else if (str_registr == "eax") {
    return UC_X86_REG_EAX;
  } else if (str_registr == "ebx") {
    return UC_X86_REG_EBX;
  } else if (str_registr == "ecx") {
    return UC_X86_REG_ECX;
  } else if (str_registr == "edx") {
    return UC_X86_REG_EDX;
  } else if (str_registr == "esp") {
    return UC_X86_REG_ESP;
  } else if (str_registr == "esi") {
    return UC_X86_REG_ESI;
  } else if (str_registr == "edi") {
    return UC_X86_REG_EBX;
  } else if (str_registr == "eip") {
    return UC_X86_REG_EBX;
  } else if (str_registr == "ebp") {
    return UC_X86_REG_EBP;
  } else {
    return UC_X86_REG_ZMM9;
  }
}

} //namespace cpu
