# Mles WebWorker

Mles WebWorker is an open source Mles (Modern Lightweight channEl Service) WebSocket client layer protocol implementation written in JavaScript. Mles WebWorker can be used independently by any application over its messaging application interface. It used as part of [MlesTalk](http://mles.io/app) Android application.

All messaging is secured by Blowfish [1] (56-bit key) including ciphertext stealing (CTS) [2], All-or-nothing-transform (AONT) [3] and Blake2 [4] HMAC.

Please see http://mles.io for details about Mles protocol.

## Mles WebWorker Messaging API

### Init message array
```
/**
 * Initialize Mles WebSocket connection
 *
 * @param  init {String}              IN: command parameter
 * @param  data {String}              IN: data, null for "init"
 * @param  addr {String}              IN: TCP/IP address to connect to
 * @param  port {String}              IN: TCP/IP port to connect to
 * @param  uid {String}               IN: Mles User Id
 * @param  channel {String}           IN: Mles Channel
 * @param  key {String}               IN: Encryption key
 * @param  isEncryptedChannel {bool}  IN: is the channel already in encrypted form
 */
 worker.postMessage[("init", data, addr, port, uid, channel, key, isEncryptedChannel)]
```
### Init message receive
 \["init", uid, channel, myuid, mychannel\]

### Reconnect message
 \["reconnect"\, data\]
 
 ### Reconnect message receive
 \["init", uid, channel, myuid, mychannel\]
 
### Send message
 \["send", data, uid, channel,  isEncryptedChannel, randarr, isImage, isMultipart, isFirst, isLast\]
 
### Send message receive
 \["send", uid, channel,  isMultipart\]
 
### Data message receive
 \["data", uid, channel, msgTimestamp, message, isImage, isMultipart, isFirst, isLast\]
 
### Close message
  \["close", data\]

### Close message receive
  \["close"\]




## References

  1. B. Schneier, 1994. Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish).
  2. Rogaway, Wooding & Zhang, 2012. The Security of Ciphertext Stealing.
  3. Rivest, 1997. All-or-nothing transform.
  4. Aumasson, Neves, Wilcox-O’Hearn & Winnerlein, 2013. BLAKE2: simpler, smaller, fast as MD5.
