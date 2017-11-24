#include "utils.h"

namespace utils {
const std::string alphabet = "abcdefghijklmnopqrstuvwxyz";

std::string convert_ascii2string(std::string& ascii_code,const int radix) {
  std::string newString;
  for (int i = 0; i < ascii_code.length(); i += 2) {
    std::string byte = ascii_code.substr(i, 2);
    char chr = (char)(int)strtol(byte.c_str(), nullptr, radix);
    newString.push_back(chr);
  }
  std::reverse(newString.begin(), newString.end());
  return newString;
}

std::string covert_int2hex(const uint64_t value) {
  std::stringstream result_str;
  result_str << std::hex << value;
  return result_str.str();
}

std::string convert_string2ascii(std::string& string) {
  std::stringstream result_str;
  result_str << std::setw(2) << std::setfill('0') << std::hex << std::uppercase;
  std::copy(string.begin(), string.end(), std::ostream_iterator<unsigned int>(result_str, ""));
  return result_str.str();
}

//TODO: How get number of byte to clean stack?
int32_t gen_find(const std::string& subseq, const std::string& generator) {
  int32_t pos = 0;
  std::string saved;
  for (int i = 0; i < generator.size(); i++) {
    saved += generator[i];
    if (saved.length()>subseq.length()) {
      saved.erase(0, 1);
      pos += 1;
    }
    if (saved == subseq) {
      return pos;
    }
  }
  return -1;
}

std::string random_str(const uint32_t count, const std::string alph) {
  std::ostringstream oss;
  for (int i = 0; i < count; i++) {
    oss << alphabet[random_int(0, alph.size() - 1)];
    //oss << "A";
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