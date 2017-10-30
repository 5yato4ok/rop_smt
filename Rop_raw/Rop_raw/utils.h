#include "cpu_description.h"
#include "z3\inc\z3.h"
#include <vector>
#include <map>
#include <string>

std::map<z3bit_vec,std::vector<std::string>> z3_new_state(ropperdis::CPU_description& arch);