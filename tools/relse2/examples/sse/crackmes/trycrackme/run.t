  $ binsec -sse -sse-script crackme.ini -sse-depth 10000 \
  > -sse-alternative-engine core.snapshot 2>&1 |
  > grep -e 'Ascii stream' | grep -oe '".*"'
  "34407373373234353336"
