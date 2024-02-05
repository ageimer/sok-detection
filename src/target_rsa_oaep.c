#include <stdint.h>
#include <stdio.h>
#define RSA1024
#define OAEP
#include "common.h"

extern void RunTarget(uint8_t* input);

extern void InitTarget(uint8_t* input);

extern void Target(FILE* input, int testcaseId, int* targetInit)
{
    uint8_t d[NLEN+DLEN+PLEN+QLEN+DPLEN+DQLEN+QINVLEN+NLEN] = {0};
    uint8_t* data = (uint8_t*)d;
    
    if (input != NULL) {
        size_t total = fread(data, 1, NLEN, input); data+=NLEN;
        total += fread(data, 1, DLEN, input); data += DLEN;
        total += fread(data, 1, PLEN, input); data += PLEN;
        total += fread(data, 1, QLEN, input); data += QLEN;
        total += fread(data, 1, DPLEN, input); data += DPLEN;
        total += fread(data, 1, DQLEN, input); data += DQLEN;
        total += fread(data, 1, QINVLEN, input); data += QINVLEN;
        total += fread(data, 1, NLEN, input);
        if (total != NLEN+DLEN+PLEN+QLEN+DPLEN+DQLEN+QINVLEN+NLEN) return;
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
