#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import shutil

import gnupg
from pydget import pydget
import pygame


def bounded_function(function):
  def bind_to(self):
    def bound(*args, **kwargs):
      return function(self, *args, **kwargs)
    return bound
  return bind_to

@bounded_function
def show_text(self, event):
  if self.label_text != self.original_text:
    self._old_original_text = self.label_text
    self.label_text = self.original_text

@bounded_function
def hide_text(self, event):
  if self.label_text == self.original_text:
    self.label_text = self._old_original_text


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

  DEFAULT_DIGEST = "SHA512"

  DEFAULT_COMPRESS = "ZLIB"

  def __init__(
      self, src=DEFAULT_FILE, algo=DEFAULT_ALGO,
      digest=DEFAULT_DIGEST, compress=DEFAULT_COMPRESS
  ):
    self.gpg = gnupg.GPG()
    self.src = src
    self.algo = algo
    self.digest = digest
    self.compress = compress
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
    if os.path.exists(self.src):
      shutil.copy(self.src, self.src+".bak")
    with self.open("w") as key_file:
      key_file.write(str(self.gpg.encrypt(
        content,
        passphrase=key,
        symmetric=self.algo,
        digest_algo=self.digest,
        compress_algo=self.compress,
        encrypt=False
      )))


class App(pydget.WidgetList):

  def __init__(self, builder, fs):
    super().__init__()
    self.builder = builder
    self.fs = fs
    self.running = False

  def load_file_dialog(self):
    name = self.builder.entry_dialog(
      None, (RESOLUTION[0]-100, 85),
      title="File path"
    ).run()
    name and self.load_file(name)

  def load_default_file(self):
    self.load_file("passwords")

  def load_file(self, name):
    if os.path.exists(name):
      self.fs.src = name
      self.build_manager()

  def build(self):
    self.append(
      self.builder.framed_background(
        dim=RESOLUTION,
        frame_corner_smooth=False
      )
    )
    self.build_welcome()

  def build_welcome(self):
    self.build_menus()
    self.extend((
      self.builder.button(
        None, (200, 50), 
        label_text="load pass file", button_action=self.load_file_dialog
      ).move(y=-60), self.builder.button(
        None, (200, 50), 
        label_text="load default pass file", button_action=self.load_default_file
      ),
    ))

  def build_manager(self):
    self.build_menus()
    y = 10
    self.password_entry = self.builder.entry(
      (200, y+24), (300, 24),
      hidden=True
    )
    self.password_panel = self.builder.panel(
      (10, y+80), (RESOLUTION[0] - 20, RESOLUTION[1] - y - 114),
      columns=3, lines=-1, no_scroll=(True, False), force_fit=False
    )
    self.extend((
      self.builder.label((200, y), (0, 24),
      label_text="Password for '%s' file" % self.fs.src),
      self.password_entry,
      self.builder.button(
        (200, y+50), (73, 24), label_text="load",
        button_action=self.load
      ),
      self.builder.button(
        (275, y+50), (73, 24), label_text="save",
        button_action=self.save
      ),
      self.builder.button(
        (350, y+50), (73, 24), label_text="save as",
        button_action=self.save_as
      ),
      self.builder.button(
        (425, y+50), (75, 24), label_text="close",
        button_action=self.build_welcome
      ), self.password_panel
    ))

  def build_menus(self):
    self.algo_dd, self.digest_dd, self.compress_dd, *_ = self[1:] = (
      self.builder.drop_down(
        (-2, 10), (175, 24), menu_content=tuple(
          (name, lambda algo=name:self.set_algo(algo))
          for name in os.popen(
            "gpg --with-colons --list-config ciphername"
          ).read()[:-1].strip("cfg:ciphername:").split(";")
        )
      ), self.builder.drop_down(
        (-2, 35), (175, 24), menu_content=tuple(
          (name, lambda algo=name:self.set_digest(algo))
          for name in os.popen(
            "gpg --with-colons --list-config digestname"
          ).read()[:-1].strip("cfg:digestname:").split(";")
        )
      ), self.builder.drop_down(
        (-2, 60), (175, 24), menu_content=tuple(
          (name, lambda algo=name:self.set_compress(algo))
          for name in ("ZLIB", "BZIP2", "ZIP", "Uncompressed")
        )
      ), self.builder.button(
        (-2, RESOLUTION[1]-30), (175, 24), label_text="quit",
        button_action=self.stop
      ), 
    )
    self.set_algo()
    self.set_digest()
    self.set_compress()

  def set_algo(self, name=None):
    if name is not None:
      self.fs.algo = name
    self.algo_dd.label_text = "Algo: %s" % self.fs.algo

  def set_digest(self, name=None):
    if name is not None:
      self.fs.digest = name
    self.digest_dd.label_text = "Digest: %s" % self.fs.digest

  def set_compress(self, name=None):
    if name is not None:
      self.fs.compress = name
    self.compress_dd.label_text = "Compression: %s" % self.fs.compress

  def get_pass(self):
    self.password_entry.entry_selected_text = \
      self.password_entry.empty_selection
    if self.password_entry.label_text:
      return str(self.password_entry)
    return None

  def load(self):
    password = self.get_pass()
    if password is not None:
      self.fs.read(password)
      self.password_panel.children = None
      for user, password, info in self.fs.content:
        self.password_panel.add_children(
          self.build_password_content(
            user, password, info
          )
        )

  def build_password_content(self, user, password, info):
    if len(user) > 16:
      compact_user = user[:13] + "..."
    else:
      compact_user = user
    children = (
      self.builder.label(label_text=compact_user), 
      self.builder.label(label_text="*"*16), 
      #self.builder.label(label_text=info), 
      self.builder.label(label_text="*"*16), 
    )
    children[0].original_text = user
    if compact_user != user:
      children[0].action_on_hovered = show_text(children[0])
      children[0].action_on_not_hovered = hide_text(children[0])
    children[1].original_text = password
    children[1].action_on_hovered = show_text(children[1])
    children[1].action_on_not_hovered = hide_text(children[1])
    children[2].original_text = info
    children[2].action_on_hovered = show_text(children[2])
    children[2].action_on_not_hovered = hide_text(children[2])
    return children

  def save(self):
    password = self.get_pass()
    if password is not None:
      self.fs.save(password)

  def save_as(self):
    file_name = self.builder.entry_dialog(
      None, (RESOLUTION[0]-100, 85),
      title="New File path"
    ).run()
    if file_name:
      password = self.get_pass()
      if password is not None:
        self.fs.src = file_name
        self.fs.save(password)

  def run(self):
    self.running = True
    self.regulator = pydget.Timer(fps=30)
    self.load_default_file()
    self.load()
    while self.running:
      self.regulator.regulate()
      self.display()
      pygame.display.flip()
      self.manage_events()

  def manage_events(self):
    for event in pygame.event.get():
      if event.type == pygame.QUIT:
        self.stop()
      else:
        self.capture_event(event)

  def stop(self):
    self.running = False

if __name__ == "__main__":

  pygame.init()
  pygame.mixer.quit()
  pygame.key.set_repeat(150, 40)
  RESOLUTION = 640, 480

  fs = PWDFS()
  builder = pydget.WidgetBuilder(
    pydget.WidgetContext(
      pygame.display.set_mode(RESOLUTION)
    )
  )
  app = App(builder, fs)
  app.build()
  app.run()
  exit()

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
  