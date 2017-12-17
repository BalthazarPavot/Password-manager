#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import shutil

import gnupg
from pydget import pydget
import pygame

class PWDFS(object):

  DEFAULT_FILE = "passwords"
  #SEP_SIZE = 256
  SEP_SIZE = 10
  RANDOM_SEP = ''.join(map(
    #lambda x:chr(random.randrange(256)),
    lambda x:chr(random.randrange(32, 128)),
    range(SEP_SIZE)
  ))

  DEFAULT_ALGO = "TWOFISH"
  #DEFAULT_ALGO = "AES256"

  def __init__(self, src=DEFAULT_FILE, algo=DEFAULT_ALGO):
    self.gpg = gnupg.GPG()
    self.src = src
    self.algo = algo
    self.content = list()

  @property
  def raw_content(self):
    if self.content:
      return self.RANDOM_SEP + self.RANDOM_SEP.join(
        map("\r\n".join, self.content)
      )

  def add(self, username, password, info=""):
    if (username, password, info) not in self.content:
      self.content.append((username, password, info))

  def remove(self, username, password, info=""):
    data = (username, password, info)
    while data in self.content:
      self.content.remove(data)

  def open(self, mode="r"):
    if not os.path.exists(self.src) and mode == "r":
      open(self.src, "w").close()
    return open(self.src, mode)

  def read(self, key):
    with self.open() as encrypted:
      decrypted = str(self.gpg.decrypt_file(
        encrypted,
        passphrase=key,
      ))
    if decrypted:
      self.content = [
        tuple(line.split("\r\n")) for line in
        decrypted[self.SEP_SIZE:].split(decrypted[:self.SEP_SIZE])
      ]
    else:
      self.content = list()
    return self.content

  def save(self, key):
    content = self.raw_content
    if not content:
      return self.open("w").close()
    shutil.copy(self.src, self.src+".bak")
    with self.open("w") as key_file:
      key_file.write(str(self.gpg.encrypt(
        content,
        passphrase=key,
        symmetric=self.algo,
        encrypt=False
      )))


fs = PWDFS()

password = input("Password:\n>>> ")
fs.read(password)

while 1:
  print("\n".join(["\n\t".join(x)+"\n" for x in fs.content]))
  user = input("user:\n>>> ")
  if not user:
    break
  pwd = input("pwd:\n>>> ")
  info = input("info:\n>>> ")
  fs.add(user, pwd, info)
  fs.save(password)
  