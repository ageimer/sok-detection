  $ binsec -sse -sse-script crackme.ini -sse-depth 10000 \
  > -sse-self-written-enum 1 -sse-alternative-engine \
  > -fml-solver-timeout 0 core.snapshot 2>&1 | \
  > grep -e 'Ascii stream' | grep -oe '".*"'
  "hello_world_42"
