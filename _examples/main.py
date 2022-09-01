# This Python script generates a random password and uses the Go app to password-hash it.
# Then it will verify the generated password against the original password in Python.

import subprocess
import argon2
import hashlib
import random
import sys

# Generate random password
p = random.randint(1, 10000).to_bytes(2, 'big')
h = hashlib.new('sha256')
h.update(p)

password = h.hexdigest()
print("Password:", password)

# Hash the password using Argon2id via Go application `sample`.
ret = subprocess.run(["sample", password], capture_output=True, text=True)
hashed = str.strip(ret.stdout)
print("Hashed:", hashed)


print('Verify ... ', end='')

# Verify the password in Python
try:
    ph = argon2.PasswordHasher()
    verifyValid = ph.verify(hashed, password)
except:
    print('NG')
    sys.exit(1)
else:
    print('OK')
    sys.exit(0)
