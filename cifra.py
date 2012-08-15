#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# This is a sample program for teaching 
#  python and some criptography
#  related to the article http://www.babel.it/it/centro-risorse/2012/08/13/58-crittografia-e-integrazione-dei-sistemi-con-python.html
# 


##
## A simple byte swap encryption
##
def shift(i, step=2):
    """Sposta gli indici pari di una stringa."""
    if i > 7: raise Exception("Valore dell’indice non valido: %s" % i)
    if i % 2: return i
    return (i - step) % 8
def codifica(stringa):
    """Ritorna la sequenza di numeri associata a una stringa"""
    ord_a=ord("A")
    ret = ""
    for carattere in stringa:
        # anteponi lo zero ai numeri minori di 10
        ret += "%02d" % (ord(carattere)-ord_a)
    return ret
def cifra(stringa):
    ret = ""
    stringa_codificata = codifica(stringa)
    print "stringa_codificata: %s" % stringa_codificata
    # una stringa e’ un’array di caratteri
    for i in range(len(stringa_codificata)):    
        ret += stringa_codificata[shift(i)]
    return ret

def cifra_test():
    test_list=[ ("CASA", "02000810") ]
    for (input,output) in test_list:
        cifra_input = cifra(input)
        assert cifra_input == output, "Valore inatteso per %s: ho %s, aspettavo %s" % (codifica(input), cifra_input, output)

# esegui cifra_test()
cifra_test()

##
## A simple implementation of the Diffie-Hellman
##   encryption algorithm
##
def find_pubkey(p,q):
  """Crea una chiave pubblica a partire da due numeri primi p e q"""
  from fractions import gcd
  ring_2 = (p-1)*(q-1)
  for pub_k in range(2, ring_2):
    if gcd(pub_k, ring_2) == 1: return pub_k

def find_privkey(p,q,pub_key):
  """Crea una chiave privata a partire da due numeri primi e da una chiave pubblica"""
  ring_2 = (p-1)*(q-1)
  for prv_k in range(2, ring_2):
    if prv_k * pub_key % ring_2 == 1: return prv_k

def genera_chiavi_test():
  """Genera una coppia di chiavi"""
  (p,q) = (5,11)
  pub_key = find_pubkey(p,q)
  prv_key = find_privkey(p,q,pub_key)
  print "pub: %s, prv: %s, ring: %s, ring2: %s" % (pub_key, prv_key, p*q, (p-1) * (q-1))

genera_chiavi_test()


##
## Exercise: write an example encryption-decryption test using
##   a couple of keys generated with the previous algorithm
##
