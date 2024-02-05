#include <stdint.h>
#include <stdio.h>
#include "common.h"

extern void RunTarget(uint8_t* input);

extern void InitTarget(uint8_t* input);

extern void Target(FILE* input, int testcaseId, int* targetInit)
{
    uint8_t bn[128];
    
    if (input != NULL) {
        if(fread(bn, 1, 128, input) != 128)
            return;
    }

    // If the target was not yet initialized, call the init function for the first test case
    if(!(*targetInit)) {
        InitTarget(bn);
        fseek(input, 0, SEEK_SET);
        *targetInit = 1;
    }
            
    PinNotifyTestcaseStart(testcaseId);
    RunTarget(bn);
    PinNotifyTestcaseEnd();

}
