/// Keep in my: this program is only coompiled under win32
///

#pragma once

#define JUNK_ASM 1

#if JUNK_ASM == 1
#define ASM_JUNK //
#else
#define ASM_JUNK 
#endif

#define ASM_JUNK_1 __asm      \
{                         \
   __asm pop eax        \
   __asm nop   \
   __asm push eax       \
}


#define ASM_JUNK_2 __asm {    \
__asm        push eax    \
__asm        push   0x61    \
__asm        mov eax, esp    \
__asm        push eax    \
__asm    \
__asm        pop eax    \
__asm        pop eax    \
__asm        pop eax    \
}
