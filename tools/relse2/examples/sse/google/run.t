  $ binsec -config config.cfg -sse-alternative-engine 2>&1 |
  > grep -e 'Ascii stream' | grep -oe '".*"'
  "CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}"
