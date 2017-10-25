#include "cpu_description.h"

CPU_description::CPU_description(uc_mode mode, uc_arch arch):
mode_(mode), arch_(arch) {
  switch (arch) {
    case UC_ARCH_X86:
      switch (mode) {
        case UC_MODE_32:
          bits = 32;
          instruction_pointer = "eip";
          stack_pointer = "esp";
          address_mask = 0xffffffff;
          page_mask = 0xfffff000;
          page_size = 0x1000;
          return_instructions = "\xc3";
          alignment = 1;
        case UC_MODE_64:
          bits = 64;
          instruction_pointer ="rip";
          stack_pointer = "rsp";
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