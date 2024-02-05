  $ binsec -sse -sse-script crackme.ini \
  > i_am_happy_you_are_to_playing_the_flareon_challenge.exe 2>&1 |
  > grep -e 'Ascii stream' | grep -oe '".*"'
  "bunny_sl0pe@flare-on.com"
