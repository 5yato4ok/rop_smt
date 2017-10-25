#include "unicorn\unicorn.h"
#include <string>

namespace ropperdis {
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
}