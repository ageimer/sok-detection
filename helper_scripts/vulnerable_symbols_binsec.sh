#!/usr/bin/env bash

# ===== Description
#
# For each result file in RESULT_DIR, lists all vulnerabilities, address and
# corresponding function symbol
#


# ===== Parameters
RESULT_DIR="../benchmarks-results"  # Directory containing result files
BUILD_DIR="../build/"                # Directory containing executables
BINSEC_VERSION=2                 # Version of binsec used


if [ ${BINSEC_VERSION} -eq 1 ]
then
    TOOL=binsec-rel
    TOOLSUFFIX=binsec
else
    TOOL=binsec-rel2
    TOOLSUFFIX=binsec-rel2
fi

TARGETS=$(find "${RESULT_DIR}/${TOOL}" | grep "\\.txt")
for TARGET in ${TARGETS}
do
    NAME=$(echo "$TARGET" | sed "s/-$TOOLSUFFIX.txt//g" | cut -d/ -f4)
    echo ""
    echo "___________________________________________________________"
    echo "Vulnerabilities for ${NAME}:"
    BINARY=$(find ${BUILD_DIR} -executable -name ${NAME})
    echo "Binary = ${BINARY}"
    echo "Results = ${TARGET}"

    if [ ${BINSEC_VERSION} -eq 1 ]
    then
        VULNERABILITIES=$(cat ${TARGET} | grep "\\[relse:result\\] Address" | \
                              cut -d'(' -f 2 | cut -d',' -f 1)
    else
        VULNERABILITIES=$(cat ${TARGET} | grep "\\[checkct:result\\] Instruction" | \
                              cut -d' ' -f 3 | cut -d'x' -f 2)
    fi
    
    if [[ -z ${VULNERABILITIES} ]]
    then
        echo "None"
    else
        for VULN in ${VULNERABILITIES}
        do
            SYMBOL=$(echo "info symbol 0x${VULN}" | gdb ${BINARY} | grep "(gdb)" | head -n 1)
            echo "${VULN}: ${SYMBOL}"
        done
    fi
    echo "___________________________________________________________"
    echo ""
done
exit 0
