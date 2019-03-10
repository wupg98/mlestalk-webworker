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
 * @param  init {String}              IN: command parameter "init"
 * @param  data {String}              IN: data, null for "init"
 * @param  addr {String}              IN: TCP/IP address to connect to
 * @param  port {String}              IN: TCP/IP port to connect to
 * @param  uid {String}               IN: Mles User Id
 * @param  channel {String}           IN: Mles Channel
 * @param  key {String}               IN: Encryption key
 * @param  isEncryptedChannel {bool}  IN: true, if the channel is already in encrypted form
 */
 webWorker.postMessage[("init", data, addr, port, uid, channel, key, isEncryptedChannel)]
```
### Init/Reconnect message receive
```
/**
 * Mles WebSocket connection init receive after successful WebSocket initialization
 *
 * @param  init {String}              IN: command parameter of receive "init"
 * @param  uid {String}               IN: Original Mles User Id
 * @param  channel {String}           IN: Original Mles Channel
 * @param  myuid {String}             IN: Encrypted Mles User Id for reference
 * @param  mychannel {String}         IN: Encrypted Mles Channel for reference
 */
 webWorker.onmessage = e.data["init", uid, channel, myuid, mychannel]
```
### Reconnect message
```
/**
 * Reconnect Mles WebSocket connection after close
 *
 * @param  reconnect {String}         IN: command parameter "reconnect"
 * @param  data {String}              IN: data, null for "reconnect"
 */
 webWorker.postMessage[("reconnect", data)]
 ```
### Send message
```
/**
 * Send message over Mles WebSocket connection
 *
 * @param  send {String}              IN: command parameter "send"
 * @param  data {String}              IN: data to be sent
 * @param  uid {String}               IN: Mles User Id
 * @param  channel {String}           IN: Mles Channel
 * @param  isEncryptedChannel {bool}  IN: true, if the channel is already in encrypted form
 * @param  randarr {Uint32Array}      IN: cryptocraphically random array of length 6
 * @param  isImage {bool}             IN: true, if an image
 * @param  isMultipart {bool}         IN: true, if multipart send
 * @param  isFirst {bool}             IN: true, if first of multipart send
 * @param  isLast {bool}              IN: true, if last of multipart send
 */
 webWorker.postMessage[("send", data, uid, channel,  isEncryptedChannel, randarr, isImage, isMultipart, isFirst, isLast)]
 ```
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
