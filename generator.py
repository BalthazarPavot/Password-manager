#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
from random import randrange, choice


if os.path.exists("all_english_words.txt"):
  with open("all_english_words.txt") as words_file:
    words = tuple(words_file.readlines())
    print(len(words))
else:
  words = ()

while True:
  input("\t".join((
    ''.join(chr(randrange(33, 127)) for _ in range(32)),
     " ".join(choice(words).strip() for x in range(4))
  )))