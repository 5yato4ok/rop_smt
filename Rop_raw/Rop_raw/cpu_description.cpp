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
} //namespace cpu
