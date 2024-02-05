#include <stdint.h>
#include <stdio.h>
#include "common.h"

extern void RunTarget(uint8_t* input);

extern void InitTarget(uint8_t* input);

extern void Target(FILE* input, int testcaseId, int* targetInit)
{
    uint8_t d[1] = {0};
    
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
