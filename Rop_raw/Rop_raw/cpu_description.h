//#define AMD64_BITS 64
//#define X86_BITS 32

//#define instruction_pointer "rip"
//#define stack_pointer "rsp"

//#define address_mask 0x0000007fffffffff
//#define page_mask 0x0000007ffffff000
//#define page_size 0x1000

//#define return_instructions "\xc3"
//#define alignment 1
#include "unicorn\unicorn.h"
#include <string>

//TODO: add description for x86
class CPU_description {
 public:
  CPU_description(uc_mode mode, uc_arch arch);
  int bits;
  std::string instruction_pointer;
  std::string stack_pointer;
  int64_t address_mask;
  int64_t page_mask;
  int64_t page_size;
  std::string return_instructions;
  int alignment;
  const uc_mode mode_;
  const uc_arch arch_;
  bool is_initialized() { return initialized_; }
 private:
   bool initialized_ = false;
};
