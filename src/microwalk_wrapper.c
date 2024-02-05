#ifdef _GNU_SOURCE
    #undef _GNU_SOURCE
#endif

#include "common.h"

// adapted from Microwalk C template:
// https://github.com/microwalk-project/Microwalk/blob/master/templates/c/microwalk/main.c

// Main trace target function. The following actions are performed:
//     The current action is read from stdin.
//     A line with "t" followed by a numeric ID, and another line with a file path determining a new testcase, that is subsequently loaded and fed into the target function, while calling PinNotifyNextFile() beforehand.
//     A line with "e 0" terminates the program.
void MicrowalkWrapper()
{
    // First transmit stack pointer information
    ReadAndSendStackPointer();
	
	PinNotifyAllocation((uint64_t)&errno, 8);

    // Run until exit is requested
    char inputBuffer[512];
    char errBuffer[128];
	int targetInitialized = 0;
    while(1)
    {
        // Read command and testcase ID (0 for exit command)
        char command;
        int testcaseId;
        char* str = fgets(inputBuffer, sizeof(inputBuffer), stdin);
        sscanf(inputBuffer, "%c %d", &command, &testcaseId);

        // Exit or process given testcase
        if(command == 'e')
            break;
        if(command == 't')
        {
            // Read testcase file name
            char* str = fgets(inputBuffer, sizeof(inputBuffer), stdin);
            int inputFileNameLength = strlen(inputBuffer);
            if(inputFileNameLength > 0 && inputBuffer[inputFileNameLength - 1] == '\n')
                inputBuffer[inputFileNameLength - 1] = '\0';

            // Load testcase file and run target function
            FILE* inputFile = fopen(inputBuffer, "rb");
            if(!inputFile)
            {
                strerror_r(errno, errBuffer, sizeof(errBuffer));
                fprintf(stderr, "Error opening input file '%s': [%d] %s\n", inputBuffer, errno, errBuffer);
                continue;
            }

            // calls the target function's wrapper which will read the input file then call the target
			Target(inputFile, testcaseId, &targetInitialized);
			            
            fclose(inputFile);
        }
    }
}

// Wrapper entry point.
int main(int argc, const char** argv) {
    const char* env_test_mode = getenv("TEST_MODE");

    if (env_test_mode == NULL)
        exit(EXIT_FAILURE);
    
    if (!strcmp(env_test_mode, "COMMON")) {
        // call the target without passing a file pointer
        // todo
    } else if (!strcmp(env_test_mode, "DUDECT")) {
        // todo
        
    } else if (!strcmp(env_test_mode, "MICROWALK")) {
        MicrowalkWrapper();
    } else {
        exit(EXIT_FAILURE);
    }
    
    return 0;
}
