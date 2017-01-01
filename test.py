__author__ = 'cm'

import time
import struct
import hmac
import hashlib
import base64

def test():
    print 'test'

def authenticate(secretkey, code_attempt):
    tm = int(time.time() / 30)
    secretkey = base64.b32decode(secretkey)
    # try 30 seconds behind and ahead as well
    for ix in [-1, 0, 1]:
        # convert timestamp to raw bytes
        b = struct.pack(">q", tm + ix)


        # generate HMAC-SHA1 from timestamp based on secret key
        hm = hmac.HMAC(secretkey, b, hashlib.sha1).digest()

        # extract 4 bytes from digest based on LSB
        offset = ord(hm[-1]) & 0x0F
        truncatedHash = hm[offset:offset+4]

        # get the code from it
        code = struct.unpack(">L", truncatedHash)[0]
        code &= 0x7FFFFFFF;
        code %= 1000000;

        if ("%06d" % code) == str(code_attempt):
            print 'true'
            return True
    print 'false'
    #git add test
    return False
    #pycharm check out form github-

if __name__== '__main__':
    secretkey = 'ZVMDU4NOTXEJGGET'
    code_attempt = '061543'
    authenticate(secretkey, code_attempt)
