#pragma once
#include "cpu_description.h"
#include <sstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <z3.h>
#include <vector>
#include <map>
#include <list>
#include <random>

namespace utils {
extern const std::string alphabet;
uint64_t get_random_page(const cpu::CPU_description arch);
std::string random_str(const uint32_t count, const std::string alph = alphabet);
uint64_t random_int(const uint64_t start, const uint64_t end);
std::string covert_int2hex(const uint64_t value);
std::string convert_string2ascii(std::string& string);
std::string convert_ascii2string(std::string& ascii_code,const int radix);
int32_t gen_find(const std::string& subseq, const std::string& generator);

//std::map<z3bit_vec,std::vector<std::string>> z3_new_state(ropperdis::CPU_description& arch);
}
