# MlesTalk WebWorker

MlesTalk WebWorker is an open source Mles (Modern Lightweight channEl Service) WebSocket client layer protocol implementation written in JavaScript. MlesTalk WebWorker can be used independently by any application over its messaging application interface. It used as part of [MlesTalk](http://mles.io/app) Android application.

All messaging is secured by Blowfish [1] (56-bit key, low level of security) including ciphertext stealing (CTS) [2], All-or-nothing-transform (AONT) [3] and Blake2 [4] HMAC.

Please see http://mles.io for details about Mles protocol.

## Protocol analysis
Verifpal 0.7.5 analysis shows no issues at the moment in the Mles WebWorker protocol logic:
```
Verifpal 0.7.5 (go1.13.3)
© 2019 Nadim Kobeissi — https://verifpal.com
WARNING: Verifpal is experimental software.

 Verifpal! parsing model "mles-websocket.vp"...
 Verifpal! verification initiated at 15:57:25
 Analysis! Alice has sent cipher_msg_alice_name to Bob, rendering it public
 Analysis! Alice has sent hmac_cipher_msg_alice_name to Bob, rendering it public
 Analysis! Alice has sent cipher_msg_alice_channel to Bob, rendering it public
 Analysis! Alice has sent hmac_cipher_msg_alice_channel to Bob, rendering it public
 Analysis! Alice has sent cipher_msg_alice to Bob, rendering it public
 Analysis! Alice has sent hmac_cipher_msg_alice to Bob, rendering it public
 Analysis! Bob has sent cipher_msg_bob_name to Alice, rendering it public
 Analysis! Bob has sent hmac_cipher_msg_bob_name to Alice, rendering it public
 Analysis! Bob has sent cipher_msg_bob_channel to Alice, rendering it public
 Analysis! Bob has sent hmac_cipher_msg_bob_channel to Alice, rendering it public
 Analysis! Bob has sent cipher_msg_bob to Alice, rendering it public
 Analysis! Bob has sent hmac_cipher_msg_bob to Alice, rendering it public
     Info! attacker is configured as active
Deduction! cipher_msg_alice_name resolves to ENC(HASH(HASH(key_string)), name_alice)
Deduction! hmac_cipher_msg_alice_name resolves to MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_alice)) (analysis 0, depth 1)
Deduction! ENC(HASH(HASH(key_string)), channel) found by attacker by equivocating with cipher_msg_alice_channel (analysis 0, depth 2)
Deduction! MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), channel)) found by attacker by equivocating with hmac_cipher_msg_alice_channel (analysis 0, depth 3)
Deduction! cipher_msg_alice resolves to ENC(HASH(key_string), msg_alice) (analysis 0, depth 4)
Deduction! hmac_cipher_msg_alice resolves to MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_alice)) (analysis 0, depth 5)
Deduction! cipher_msg_bob_name resolves to ENC(HASH(HASH(key_string)), name_bob) (analysis 0, depth 6)
Deduction! hmac_cipher_msg_bob_name resolves to MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_bob)) (analysis 0, depth 7)
Deduction! cipher_msg_bob resolves to ENC(HASH(key_string), msg_bob) (analysis 0, depth 8)
Deduction! hmac_cipher_msg_bob resolves to MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_bob)) (analysis 0, depth 9)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_alice)), MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_alice)))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_alice)), MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_alice)) (analysis 0, depth 10)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), channel)), MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), channel)))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), channel)), MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), channel)) (analysis 0, depth 11)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_alice)), MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_alice)))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_alice)), MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_alice)) (analysis 0, depth 12)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_bob)), MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_bob)))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_bob)), MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_bob)) (analysis 0, depth 13)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_bob)), MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_bob)))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_bob)), MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_bob)) (analysis 0, depth 14)
 Analysis! MAC(nil, nil) now conceivable by reconstructing with nil, nil (analysis 9, depth 0)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_alice)), MAC(nil, nil))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_alice)), MAC(nil, nil) (analysis 9, depth 1)
Deduction! ENC(nil, nil) found by attacker by reconstructing with nil (analysis 12, depth 0)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), channel)), MAC(nil, nil))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), channel)), MAC(nil, nil) (analysis 17, depth 0)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_alice)), MAC(nil, nil))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_alice)), MAC(nil, nil) (analysis 34, depth 0)
 Analysis! MAC(nil, nil) now conceivable by reconstructing with nil, nil (analysis 102, depth 0)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_bob)), MAC(nil, nil))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(key_string), msg_bob)), MAC(nil, nil) (analysis 102, depth 1)
Deduction! ENC(nil, nil) found by attacker by reconstructing with nil (analysis 105, depth 0)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), channel)), MAC(nil, nil))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), channel)), MAC(nil, nil) (analysis 110, depth 0)
 Analysis! ASSERT(MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_bob)), MAC(nil, nil))? now conceivable by reconstructing with MAC(HASH(HASH(key_string)), ENC(HASH(HASH(key_string)), name_bob)), MAC(nil, nil) (analysis 127, depth 0)
 Stage 2, Analysis 192...
 Verifpal! verification completed at 15:57:31
 Verifpal! thank you for using verifpal!
     Info! verifpal is experimental software and may miss attacks.
```

## MlesTalk WebWorker Messaging API

### Init message
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
 * @param  init {String}              OUT: command parameter of receive "init"
 * @param  uid {String}               OUT: Original Mles User Id
 * @param  channel {String}           OUT: Original Mles Channel
 * @param  myuid {String}             OUT: Encrypted Mles User Id for reference
 * @param  mychannel {String}         OUT: Encrypted Mles Channel for reference
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
 * @param  uid {String}               IN: Mles User Id
 * @param  channel {String}           IN: Mles Channel
 */
 webWorker.postMessage[("reconnect", data, uid, channel)]
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
 * @param  randArray {Uint32Array}    IN: random array filled with input of length 6 x Uint32
 * @param  isFull {bool}              IN: true, if a full message
 * @param  isImage {bool}             IN: true, if an image
 * @param  isMultipart {bool}         IN: true, if multipart send
 * @param  isFirst {bool}             IN: true, if first of multipart send
 * @param  isLast {bool}              IN: true, if last of multipart send
 */
 webWorker.postMessage[("send", data, uid, channel,  isEncryptedChannel, randarr, isFull, isImage, isMultipart, isFirst, isLast)]
 ```
### Send message receive
```
/**
 * Mles WebSocket send receive after send
 *
 * @param  send {String}              OUT: command parameter of receive "send"
 * @param  uid {String}               OUT: Original Mles User Id
 * @param  channel {String}           OUT: Original Mles Channel
 * @param  isMultipart {boo           OUT: true, if send was multipart
 */
 webWorker.onmessage = e.data["send", uid, channel,  isMultipart]
``` 
### Data message receive
```
/**
 * Mles WebSocket RX data receive
 *
 * @param  data {String}               OUT: command parameter of receive "data"
 * @param  uid {String}                OUT: Original Mles User Id
 * @param  channel {String}            OUT: Original Mles Channel
 * @param  msgTimestamp {Date.valueOf} OUT: timestamp of the message in X format
 * @param  message {String}            OUT: received message
 * @param  isFull {bool}               OUT: true, if a full message
 * @param  isImage {bool}              OUT: true, if an image
 * @param  isMultipart {bool}          OUT: true, if multipart
 * @param  isFirst {bool}              OUT: true, if first of multipart
 * @param  isLast {bool}               OUT: true, if last of multipart
 */
 webWorker.onmessage = e.data["data", uid, channel, msgTimestamp, message, isFull, isImage, isMultipart, isFirst, isLast]
```
### Close message
```
/**
 * Close message over Mles WebSocket connection
 *
 * @param  close {String}             IN: command parameter "close"
 * @param  data {String}              IN: data, null for close
 * @param  uid {String}               IN: Mles User Id
 * @param  channel {String}           IN: Mles Channel
 */
 webWorker.postMessage[("close", data, uid, channel)]
 ```
### Close message receive
```
/**
 * Mles WebSocket connection close receive after WebSocket closing
 *
 * @param  close {String}             OUT: command parameter of receive "close"
 * @param  uid {String}               OUT: Original Mles User Id
 * @param  channel {String}           OUT: Original Mles Channel
 * @param  myuid {String}             OUT: Encrypted Mles User Id for reference
 * @param  mychannel {String}         OUT: Encrypted Mles Channel for reference
 */
 webWorker.onmessage = e.data["close", uid, channel, myuid, mychannel]
```

## References

  1. B. Schneier, 1994. Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish).
  2. Rogaway, Wooding & Zhang, 2012. The Security of Ciphertext Stealing.
  3. Rivest, 1997. All-or-nothing transform.
  4. Aumasson, Neves, Wilcox-O’Hearn & Winnerlein, 2013. BLAKE2: simpler, smaller, fast as MD5.
