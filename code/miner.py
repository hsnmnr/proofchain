from OpenSSL import crypto
from common import hash
from time import time
from threading import *

class Miner:
  def __init__(self, blockchain):
    self.key = crypto.PKey()
    self.key.generate_key(crypto.TYPE_RSA,1024)
    self.bc = blockchain
    self.mytokens = {}
    self.identity = self.bc.gen_csr(
      CN="ROOTCA",L="RAM",ST="Tense",O="Intel",
      OU="One Block", emailAddress="miner.root@proofchain.com"
    )
    self.signature = str(crypto.b16encode(crypto.dump_certificate_request(
      crypto.FILETYPE_PEM,self.identity
    )))[-289:-33]
    self.identity = self.create_cert_for(self.identity)
    self.pk = str(crypto.b16encode(
            crypto.dump_publickey(crypto.FILETYPE_ASN1,self.key)
          ))
    self.semaphore = Semaphore(1);


  def _acquire_miner(self):
    self.semaphore.acquire()
    
  def _release_miner(self):
    self.semaphore.release()

  def _miner_available(self):
    return (True if self.semaphore._Semaphore__value == 1 else False)

  def _key_check(self, pk, sig):
    self._acquire_miner();
    #associates Sk with PK using Sig
    #SK is a secret hence not required, sig is enough
    if decrypt_sig(pk, sig) == gen_sigstr(pk):
      self._release_miner();
      return True
    self._release_miner();
    return False

  def _domain_check(self, domain, pk):#, sig):
    self._acquire_miner();
    #returns false if domain in blockchain
    for block in reversed(self.bc.chain):
      if block.domain == domain:
        if block.crt == 'revoked':
          self._release_miner();
          return True
        else:
          self._release_miner();
          return False
        #if block.pk == pk:
          #if decrypt_sig(pk, block.sig) == gen_sigstr(pk):
          #return False
    self._release_miner();
    return True

  def _token_placement(self, trans):
    self._acquire_miner();
    #returns a signed token of trans
    t = ((#crypto.b16encode(
      crypto.sign(self.key,hash(hash(trans)+ self.pk),'sha256')
      ))
    self.mytokens.setdefault(trans.domain,t)
    self._release_miner();
    return t

  def _token_validation(self, issuedtoken, signedToken, cert):
    self._acquire_miner();
    #validates signedtoken using trans and provided pubk
    #calculates the token again without signature as the token issues by miner is not saved
    #anywhere hence recalculate it. Not a bug; decentralization may require it
    #any miner can verify issued token
    crypto.verify(cert,signedToken,issuedtoken,'sha256')

  def mine(self,trans,expiry):
    self._acquire_miner();
    #appends a block in self.bc
    #puts domain in blockchain.tokened to make sure user doesn't keep
    #placing its token and invoking miners to mine again.
    pk, sig = trans.pk, trans.sig
    if True:
      top = self.bc.top
      ids = top if top.domain == trans.domain else None
      gs = top if ids is None else self.bc.chain[-2]
      for block in reversed(self.bc.chain):
        if block.domain == trans.domain:
          ids = block
          break
      block = {
        "index": len(self.bc.chain),
        "crt": trans.crt,
        "gs": gs,
        "ids": ids,
        "domain": trans.domain,
        "pk": crypto.b16encode(crypto.dump_publickey(crypto.FILETYPE_PEM,pk)),
        "sig": sig,
        "expiry": expiry,
        "CAsig": self.signature
      }
      self.bc.mine(self.bc.createBlock(block))
      self.bc.utp.pop(trans.domain)
      self._release_miner();
      return True

  def create_cert_for(self,csr):
    self._acquire_miner();
    cert = crypto.X509()
    cert.set_subject(csr.get_subject())#req added
    cert.gmtime_adj_notAfter(365)
    cert.gmtime_adj_notBefore(0)#valid after 0 seconds
    cert.set_issuer(self.identity.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    key = crypto.load_privatekey(crypto.FILETYPE_PEM,
      crypto.dump_privatekey(crypto.FILETYPE_PEM,csr.get_pubkey())
    )
    cert.sign(key,'sha256')
    self._release_miner();
    return cert
