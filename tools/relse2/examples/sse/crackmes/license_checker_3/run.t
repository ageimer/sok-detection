  $ binsec -sse -sse-script crackme.ini core.snapshot \
  > -sse-alternative-engine 2>&1 |
  > grep -e 'Ascii stream' | grep -oe '".*"'
  "599999"
