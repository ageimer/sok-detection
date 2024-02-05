  $ binsec -sse -sse-script crackme.ini very_success.exe 2>&1 |
  > grep -e 'Ascii stream' | grep -oe '".*"'
  "a_Little_b1t_harder_plez@flare-on.com"
