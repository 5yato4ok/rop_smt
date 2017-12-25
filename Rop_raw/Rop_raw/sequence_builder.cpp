#include "sequence_builder.h"

namespace sequence_helper {

Sequence_builder::Sequence_builder(std::fstream& input, uint32_t m_depth) {
  if (init()) {
    initialized_ = true;
  }
}

bool Sequence_builder::init() {
  return true;
}

}
