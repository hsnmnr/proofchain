from common import hash

class Transaction:
  def __init__(self, domain, pk, sig, crt):
    self.domain = domain
    self.pk = pk
    self.sig = sig
    self.crt = crt

  def hash(self):
    return hash(vars(self))

  def __repr__(self):
    return "TX: domain = {0} pk = {1} type = {2}".format(self.domain,self.pk,self.crt)
