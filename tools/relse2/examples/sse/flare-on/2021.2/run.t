  $ binsec -sse -sse-script crackme.ini -sse-depth 2000 \
  > UnlockYourFiles.exe 2>&1 | grep -e 'Ascii stream' | grep -oe '".*"'
  "No1Trust"
