# Mles WebWorker

Mles WebWorker is an open source Mles (Modern Lightweight channEl Service) client layer protocol implementation written in JavaScript. It used as part of MlesTalk Android app, but it can be used independently by any application over its messaging application interface.

All messaging is secured by Blowfish [1] (56-bit key) with ciphertext stealing (CTS) [2] + All-or-nothing-transform (AONT) [3] and Blake2 [4] HMAC.

Please see http://mles.io/app for more details about MlesTalk.

## Mles WebWorker Messaging API

To be added...

## References

  1. Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish), B. Schneier, 1994
  2. The Security of Ciphertext Stealing, Rogaway, Wooding & Zhang, 2012
  3. All-or-nothing transform, Rivest, 1997
  4. BLAKE2: simpler, smaller, fast as MD5, Aumasson, Neves, Wilcox-O’Hearn & Winnerlein, 2013
