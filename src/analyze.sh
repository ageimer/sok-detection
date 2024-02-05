#!/bin/bash

set -e

targetName=$1
testcaseDir=$2

thisDir=$(pwd)
repoRootDir=$(realpath $thisDir/..)
resultsDir=$thisDir/results

mkdir -p $resultsDir
  
echo "Running target ${targetName}..."  
export TESTCASE_DIRECTORY=$testcaseDir
export TARGET_NAME=$targetName
  
mkdir -p $WORK_DIR/work/$targetName
mkdir -p $WORK_DIR/persist/$targetName

pushd $MAP_GENERATOR_PATH
dotnet MapFileGenerator.dll $thisDir/$targetName $thisDir/$targetName.map
popd

cd $MICROWALK_PATH
dotnet Microwalk.dll $thisDir/microwalk_config.yml
