#include "utils.h"

namespace utils {
const std::string alphabet = "abcdefghijklmnopqrstuvwxyz";

std::string random_str(const uint32_t count, const std::string alph) {
  std::ostringstream oss;
  for (int i = 0; i < count; i++) {
    oss << alphabet[random_int(0, alph.size() - 1)];
  }
  return oss.str();
}

uint64_t random_int(uint64_t start, uint64_t end) {
  std::random_device rd;
  std::mt19937 mt(rd());
  std::uniform_int_distribution<uint64_t> dist(start, end);
  return dist(mt);
}

uint64_t get_random_page(const cpu::CPU_description arch) {
  return random_int(0, pow(2, arch.bits - 1)) & arch.page_mask;
};

}