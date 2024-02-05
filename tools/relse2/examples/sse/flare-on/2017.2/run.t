  $ binsec -sse -sse-script crackme.ini -sse-depth 50000 IgniteMe.exe \
  > -sse-alternative-engine 2>&1 |
  > grep -e 'Ascii stream' | grep -oe '".*"'
  "R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com"
