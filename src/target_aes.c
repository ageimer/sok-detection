#include <stdint.h>
#include <stdio.h>
#define KEY16
#include "common.h"

extern void RunTarget(uint8_t* input);

extern void InitTarget(uint8_t* input);

extern void Target(FILE* input, int testcaseId, int* targetInit)
{
    uint8_t sk[16];
    
    if (input != NULL) {
        if(fread(sk, 1, KEYLEN, input) != KEYLEN)
            return;
    }

    // If the target was not yet initialized, call the init function for the first test case
    if(!(*targetInit)) {
        InitTarget(sk);
        fseek(input, 0, SEEK_SET);
        *targetInit = 1;
    }
            
    PinNotifyTestcaseStart(testcaseId);
    RunTarget(sk);
    PinNotifyTestcaseEnd();

}
