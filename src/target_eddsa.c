#include <stdint.h>
#include <stdio.h>
#define ED25519
#include "common.h"

extern void RunTarget(uint8_t* input);

extern void InitTarget(uint8_t* input);

extern void Target(FILE* input, int testcaseId, int* targetInit)
{
    uint8_t d[DLEN+QLEN] = {0};
    uint8_t* data = (uint8_t*)d;
    
    if (input != NULL) {
        size_t total = fread(data, 1, DLEN, input); data+=DLEN;
        total += fread(data, 1, QLEN, input);
        if (total != DLEN+QLEN) return;
    }

    // If the target was not yet initialized, call the init function for the first test case
    if(!(*targetInit)) {
        InitTarget(d);
        fseek(input, 0, SEEK_SET);
        *targetInit = 1;
    }
            
    PinNotifyTestcaseStart(testcaseId);
    RunTarget(d);
    PinNotifyTestcaseEnd();

}
