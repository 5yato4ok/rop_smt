#include "utils.h"

namespace utils {
const std::string alphabet = "abcdefghijklmnopqrstuvwxyz";

int32_t gen_find(const std::string& subseq, const std::string& generator) {
  int32_t pos = 0;
  int32_t size = subseq.length();
  int32_t size2 = generator.length();
  pos = (size2 - size)/sizeof(byte);
  return pos;
}
//def gen_find(subseq, generator) :
//subseq = list(subseq)
//pos = 0
//saved = []
//
//  for c in generator :
//  saved.append(c)
//  if len(saved) > len(subseq) :
//    saved.pop(0)
//    pos += 1
//  if saved == subseq :
//    return pos
//    return -1

std::string random_str(const uint32_t count, const std::string alph) {
  std::ostringstream oss;
  for (int i = 0; i < count; i++) {
    oss << alphabet[random_int(0, alph.size() - 1)];
  }
  return oss.str();
}

uint64_t random_int(const uint64_t start, const uint64_t end) {
  std::random_device rd;
  std::mt19937 mt(rd());
  std::uniform_int_distribution<uint64_t> dist(start, end);
  return dist(mt);
}

uint64_t get_random_page(const cpu::CPU_description arch) {
  return random_int(0, pow(2, arch.bits - 1)) & arch.page_mask;
};

}