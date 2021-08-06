from common import hash

class Block:
  def __init__(self, index, crt, gs, ids, domain, pk, sig, expiry, CAsig):
    self.index = index
    self.crt = crt
    self.gs = gs
    self.ids = ids
    self.domain = domain
    self.pk = pk
    self.sig = sig
    self.expiry = expiry
    self.CAsig = CAsig

  @property
  def hash(self):
    return hash(vars(self))

  def __repr__(self):
    t = "Block: index = {0} domain = {1} pk = {2} expiry = {3} status = {4}"
    return t.format(self.index, self.domain, self.pk, self.expiry, self.crt)

  def __str__(self):
    return self.__repr__()