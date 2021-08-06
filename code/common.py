from hashlib import sha256

def hash(m):
  return sha256(str(m).encode()).hexdigest()
