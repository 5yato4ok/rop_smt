#include "cpu_description.h"

namespace cpu {
CPU_description::CPU_description(uc_mode mode, uc_arch arch) :
  mode_(mode), arch_(arch) {
  switch (arch) {
  case UC_ARCH_X86:
    switch (mode) {
    case UC_MODE_32:
      bits = 32;
      instruction_pointer.insert(std::pair<uc_x86_reg, std::string>(UC_X86_REG_EIP, "eip"));
      stack_pointer.insert(std::pair<uc_x86_reg, std::string>(UC_X86_REG_ESP, "esp"));
      common_regs_ = decltype(common_regs_){{ UC_X86_REG_EAX, "eax" }, { UC_X86_REG_ECX, "ecx" }, { UC_X86_REG_EDX, "edx" },
      { UC_X86_REG_EBX, "ebx" }, { UC_X86_REG_ESP, "esp" }, { UC_X86_REG_EBP, "ebp" },
      { UC_X86_REG_ESI, "esi" }, { UC_X86_REG_EDI, "edi" }, { UC_X86_REG_EIP, "eip" } };
      address_mask = 0xffffffff;
      page_mask = 0xfffff000;
      page_size = 0x1000;
      return_instructions = "\xc3";
      alignment = 1;
      initialized_ = true;
      break;
    case UC_MODE_64:
      bits = 64;
      instruction_pointer.insert(std::pair<uc_x86_reg, std::string>(UC_X86_REG_RIP, "rip"));
      stack_pointer.insert(std::pair<uc_x86_reg, std::string>(UC_X86_REG_RSP, "rsp"));
      common_regs_ = decltype(common_regs_){ { UC_X86_REG_RAX, "rax" }, { UC_X86_REG_RCX, "rcx" }, { UC_X86_REG_RDX, "rdx" },
      { UC_X86_REG_RBX, "rbx" }, { UC_X86_REG_RSP, "rsp" }, { UC_X86_REG_RBP, "rbp" },
      { UC_X86_REG_RSI, "rsi" }, { UC_X86_REG_RDI, "rdi" }, { UC_X86_REG_RIP, "rip" } };
      address_mask = 0x0000007fffffffff;
      page_mask = 0x0000007ffffff000;
      page_size = 0x1000;
      return_instructions = "\xc3";
      alignment = 1;
      initialized_ = true;
      break;
    default:
      initialized_ = false;
    }
  default:
    initialized_ = false;
  }
};
} //namespace cpu
