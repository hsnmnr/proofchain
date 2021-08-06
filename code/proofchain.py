from miner import Miner
from block import Block
from transaction import Transaction
from random import randint
from OpenSSL import crypto
class Proofchain:
  GENESIS = {
      "index": 0,
      "crt": None,
      "gs": None,
      "ids": None,
      "domain": None,
      "pk": None,
      "sig": None,
      "expiry": None,
      "CAsig": None
    }
  def __init__(self):
    self.chain = []
    self.chain.append(self.createBlock(Proofchain.GENESIS))
    self.utp = {} #unvalidated transactions pool
    self.miners = []
    self.registereds = {} #storageArray for verifieds
    self.tokened = {} #those domains who have been given a token

  def gen_csr(self, key = None, **kwargs):
    req = crypto.X509Req()
    if key is None:
      key = crypto.PKey()
      key.generate_key(crypto.TYPE_RSA,1024)
    s = req.get_subject()
    s.CN = kwargs['CN']
    s.ST = kwargs['ST']
    s.L = kwargs['L']
    s.O = kwargs['O']
    s.OU = kwargs['OU']
    s.emailAddress = kwargs['emailAddress']
    req.set_pubkey(key)
    req.sign(key,'sha256')
    return req

  def mine(self, block):
    #only called by a miner, mines a block
    #maintains storage array (registereds)
    self.chain.append(block)
    if block.crt == 'initial':
      self.registereds.setdefault(block.domain, True)
    else:
      self.registereds.pop(block.domain)

  @property
  def top(self):
    return self.chain[-1]

  def createMiner(self):
    m = Miner(self)
    self.miners.append(m)
    return m


  def createBlock(self, blockdata):
    return Block(**blockdata)

  def createTrans(self, transdata):
    t = Transaction(**transdata)
    #self.utp.append(t)
    return t