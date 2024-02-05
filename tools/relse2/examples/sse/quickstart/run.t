  $ binsec -sse -sse-script crackme.ini magic 2>&1 |
  > grep -e 'Value' | grep -oe '0x.*'
  0xc0dedead
