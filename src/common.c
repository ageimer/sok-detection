#include "common.h"

char __attribute__((optimize(0)))
NOP(const void* addr, size_t size) {
    return 0;
}

void printhex(unsigned char* buf, int len) {
    for(int i = 0; i < len; i++)
        printf("%X ",*(buf+i));
}

// Pin notification functions.
// These functions (and their names) must not be optimized away by the compiler, so Pin can find and instrument them.
// The return values reduce the probability that the compiler uses these function in other places as no-ops (Visual C++ did do this in some experiments).
#pragma optimize("", off)
int PinNotifyTestcaseStart(int t) { return t + 42; }
int PinNotifyTestcaseEnd() { return 42; }
int PinNotifyStackPointer(uint64_t spMin, uint64_t spMax) { return (int)(spMin + spMax + 42); }
int PinNotifyAllocation(uint64_t address, uint64_t size) { return (int)(address + 23 * size); }
#pragma optimize("", on)

// Reads the stack pointer base value and transmits it to Pin.
void ReadAndSendStackPointer()
{
    // There does not seem to be a reliable way to get the stack size, so we use an estimation
    // Compiling with -fno-split-stack may be desired, to avoid surprises during analysis

    // Take the current stack pointer as base value
    uintptr_t stackBase;
    asm("mov %%rsp, %0" : "=r"(stackBase));

    // Get full stack size
    struct rlimit stackLimit;
    if(getrlimit(RLIMIT_STACK, &stackLimit) != 0)
    {
        char errBuffer[128];
        strerror_r(errno, errBuffer, sizeof(errBuffer));
        fprintf(stderr, "Error reading stack limit: [%d] %s\n", errno, errBuffer);
    }

    uint64_t stackMin = (uint64_t)stackBase - (uint64_t)stackLimit.rlim_cur;
    uint64_t stackMax = ((uint64_t)stackBase + 0x10000) & ~0xFFFFull; // Round to next higher multiple of 64 kB (should be safe on x86 systems)
    PinNotifyStackPointer(stackMin, stackMax);
}

// function used to annotate secrets in Abacus, see https://github.com/s3team/Abacus/
int __attribute__((optimize(0)))
abacus_make_symbolic(uint32_t argc, void **buffers, uint32_t *buflengths) {
  return 1;
}

int thrash_cache() {
    uint8_t buf[512*1024];
    int ret = buf[0];
    for (int i = 0; i < 512*1024; i+=64) {
        buf[i] = 42;
    }

    return ret^buf[0];
}
