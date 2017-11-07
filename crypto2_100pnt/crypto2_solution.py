#!/usr/bin/env python

from random import *
from Crypto.Cipher import DES
from Crypto import Random
from hashlib import sha256
import os
import random,socket
from ctf import welcome_mess,goodluck_mess
from ctf import FLAG


BS = DES.block_size
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
HOST, PORT, buff = '127.0.0.1', 22995, 2048

class DESCipher:
    def __init__(self, key):
        self.key = key.decode("hex")

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(BS)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        return (iv + cipher.encrypt(raw)).encode("hex")

def myDecrypt(raw,key,iv):  # Du lieu la byte 
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(raw)

def read_until(patt):
    buf = bytes()
    while not buf.decode().endswith(patt):
        buf += s.recv(1)
    return buf

def genKey():
    rlt = []
    for i in range(0,256):
        for j in range(0,256):
            seed =  (chr(i) + chr(j)).encode('hex')
            k = sha256(sha256(seed).hexdigest()).hexdigest()[:BS*2]
            rlt.append(k.decode('hex'))
    return rlt

def check(s):
    pad = ord(s[-1])  #
    if( pad <= 8 and pad >1 ):
        p = s[-pad:]
        q = chr(pad) * pad
        if( p == q):
            return True
    return False
def unpad(s):
    return s[:-ord(s[-1])]
def sets(cip):
    rlt = []
    iv = cip[:8]
    arr_key = genKey()
    for key in arr_key:
        tmp = myDecrypt(cip[8:], key, iv)
        if( check(tmp) ):
            tmp = unpad(tmp)
            rlt.append(sha256(tmp).hexdigest())
    return rlt

while True:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((HOST,PORT))
    print s.recv(buff)
    data = s.recv(buff)
    print data
    
    cip = data.split('\n')[0].split(": ")[1]
    cip = cip.decode('hex').decode('hex')
    rlt = sets(cip)
    if( rlt != []):
        s.send(rlt[0] + '\n')
        print s.recv(buff)
    else:
        sleep(5)
    
    
