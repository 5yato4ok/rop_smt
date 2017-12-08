#include "utils.h"

namespace utils {
const std::string alphabet = "abcdefghijklmnopqrstuvwxyz";
int g_index = 0;

std::string convert_ascii2string(const std::string& ascii_code,const int radix) {
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

std::string convert_string2ascii(const std::string& string) {
  std::stringstream result_str;
  result_str << std::setw(2) << std::setfill('0') << std::hex << std::uppercase;
  std::copy(string.begin(), string.end(), std::ostream_iterator<unsigned int>(result_str, ""));
  return result_str.str();
}

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

uint64_t get_random_page(const cpu::CPU_description& arch) {
  return random_int(0, pow(2, arch.bits - 1)) & arch.page_mask;
};

std::string unique_name(std::string name) {
  return (name + "_" +std::to_string(g_index++));
}
//TODO: change saving method. 
std::map<std::string, z3::expr_vector> z3_new_state(z3::context& context, const cpu::CPU_description& arch) {
  z3::expr_vector stack_description_v(context);  
  stack_description_v.push_back(context.bv_const(unique_name("stack").c_str(), arch.page_size * 8));
  z3::expr_vector constraint_description_v(context);
  constraint_description_v.push_back(context.bv_const("trash", 100)); //TODO: is here ptr to smth?
  std::map<std::string, z3::expr_vector> state = { { "stack", stack_description_v },
  { "constartaints",{ constraint_description_v } } };
  int size = stack_description_v.size();
  for (auto const& current_reg : arch.common_regs_) {
    z3::expr_vector reg_description_v(context);
    reg_description_v.push_back(context.bv_const(unique_name(current_reg.second).c_str(), arch.bits));
    state.insert(std::pair<std::string, z3::expr_vector>(current_reg.second, reg_description_v));
  };
  return state;
}

z3::expr_vector z3_read_bits(z3::expr_vector& bv, z3::context& context, const int offset,int size) {
  if (size == -1) {
    //size = bv.size() - offset;
  };
  z3::expr_vector result(context);
  z3::expr test = bv[0];
  z3::expr smth = test.extract(size,(offset + size - 1));
  result.push_back(bv[0].extract(size,(offset + size - 1)));
  return result;
}

}