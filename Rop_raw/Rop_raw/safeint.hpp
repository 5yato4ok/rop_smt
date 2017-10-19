#ifndef SAFE_INT
#define SAFE_INT

#define SafeAddU32(a, b) SafeInt::Add<unsigned int>(a, b)
#define SafeAddU64(a, b) SafeInt::Add<unsigned long long>(a, b)

/*
    The purpose of this class is to avoid integer overflow ; if one is detected, an exception is raised
*/
struct SafeInt {
  template<class T>
  static inline T Add(const T a, const T b) {
    T result = a + b;
    if(result < a)
        printf("Integer overflow detected.");

    return result;
  }
};

#endif
