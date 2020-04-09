/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019 MlesTalk WebWorker developers
 */

importScripts('cbor.js', 'blake2s.js', 'blowfish.js');

let gWebSocket;
let gMyAddr;
let gMyPort;
let gMyUid;
let gMyChannel;
let gEcbKey;
const SCATTERSIZE = 15;
const ISFULL = 0x8000
const ISIMAGE = 0x4000;
const ISMULTI = 0x4000;
const ISFIRST = 0x2000;
const ISLAST = 0x1000;
const BEGIN = new Date(Date.UTC(2018, 0, 1, 0, 0, 0));
const HMAC_LEN = 12;
const NONCE_LEN = 16;

function scatterTime(rvalU32, valU32, timeU15) {
	//check first which bits to use
	let tbit = new Uint32Array(1);
	let bit = new Uint32Array(1);
	let numofones = 0;
	let isOnes = true;
	for (let i = 31; i >= 0; i--) {
		bit[0] = (rvalU32 & (1 << i)) >> i;
		if (bit[0] > 0) {
			numofones++;
		}
	}
	let timeslot = SCATTERSIZE;
	if (numofones <= timeslot)
		isOnes = false;
	for (let i = 31; i >= 0; i--) {
		bit[0] = (rvalU32 & (1 << i)) >> i;
		if ((isOnes && bit[0] > 0) || (false == isOnes && 0 == bit[0])) {
			//apply setting to next item
			tbit[0] = (timeU15 & (1 << timeslot)) >> timeslot;
			if (tbit[0] > 0) {
				valU32 |= (1 << i);
			}
			else {
				valU32 &= ~(1 << i);
			}
			timeslot--;
			if (timeslot < 0)
				break;
		}
	}
	return valU32;
}

function unscatterTime(rvalU32, svalU32) {
	//check first which bits to use
	let timeU15 = new Uint32Array(1);
	let sbit = new Uint32Array(1);
	let bit = new Uint32Array(1);
	let numofones = 0;
	let isOnes = true;
	for (let i = 31; i >= 0; i--) {
		bit[0] = (rvalU32 & (1 << i)) >> i;
		if (bit[0] > 0) {
			numofones++;
		}
	}
	let timeslot = SCATTERSIZE;
	if (numofones <= timeslot)
		isOnes = false;
	for (let i = 31; i >= 0; i--) {
		bit[0] = (rvalU32 & (1 << i)) >> i;
		if ((isOnes && bit[0] > 0) || (false == isOnes && 0 == bit[0])) {
			sbit[0] = (svalU32 & (1 << i)) >> i;
			if (sbit[0] > 0)
				timeU15[0] |= (1 << timeslot);
			timeslot--;
			if (timeslot < 0)
				break;
		}
	}
	return timeU15[0];
}

function createTimestamp(valueofdate, weekstamp) {
	let begin = BEGIN;
	let this_week = new Date(begin.valueOf() + weekstamp * 1000 * 60 * 60 * 24 * 7);
	let timestamp = parseInt((valueofdate - this_week) / 1000 / 60);
	return timestamp;
}

function createWeekstamp(valueofdate) {
	let begin = BEGIN;
	let now = new Date(valueofdate);
	let weekstamp = parseInt((now - begin) / 1000 / 60 / 60 / 24 / 7);
	return weekstamp;
}

function readTimestamp(timestamp, weekstamp) {
	let begin = BEGIN;
	let weeks = new Date(begin.valueOf() + weekstamp * 1000 * 60 * 60 * 24 * 7);
	let extension = timestamp * 1000 * 60;
	let time = new Date(weeks.valueOf() + extension);
	return time;
}

function isEqualHmacs(hmac, rhmac) {
	let mac1 = new BLAKE2s(HMAC_LEN);
	let mac2 = new BLAKE2s(HMAC_LEN);

	mac1.update(hmac);
	mac2.update(rhmac);

	let hmac1 = mac1.digest();
	let hmac2 = mac2.digest();

	for (let i = 0; i < hmac1.byteLength; i++) {
		if (hmac1[i] != hmac2[i]) {
			return false;
		}
	}
	return true;
}

function nonce2u8arr(nonce) {
	let nonceu8 = new Uint8Array(NONCE_LEN);
	nonceu8[0] = nonce[0] >> 24;
	nonceu8[1] = nonce[0] >> 16 & 0xff;
	nonceu8[2] = nonce[0] >> 8 & 0xff;
	nonceu8[3] = nonce[0] & 0xff;
	nonceu8[4] = nonce[1] >> 24;
	nonceu8[5] = nonce[1] >> 16 & 0xff;
	nonceu8[6] = nonce[1] >> 8 & 0xff;
	nonceu8[7] = nonce[1] & 0xff;
	nonceu8[8] = nonce[2] >> 24;
	nonceu8[9] = nonce[2] >> 16 & 0xff;
	nonceu8[10] = nonce[2] >> 8 & 0xff;
	nonceu8[11] = nonce[2] & 0xff;
	nonceu8[12] = nonce[3] >> 24;
	nonceu8[13] = nonce[3] >> 16 & 0xff;
	nonceu8[14] = nonce[3] >> 8 & 0xff;
	nonceu8[15] = nonce[3] & 0xff;
	return nonceu8;
}

function u8arr2nonce(noncem) {
	let nonce = new Uint32Array(4);
	nonce[0] = noncem[0] << 24 | noncem[1] << 16 | noncem[2] << 8 | noncem[3];
	nonce[1] = noncem[4] << 24 | noncem[5] << 16 | noncem[6] << 8 | noncem[7];
	return nonce;
}

function load32(a, i) {
	return (a[i + 0] & 0xff) | ((a[i + 1] & 0xff) << 8) |
		((a[i + 2] & 0xff) << 16) | ((a[i + 3] & 0xff) << 24);
}

function store32(a, i, val) {
	a[i + 0] = val & 0xff;
	a[i + 1] = (val & 0xff00) >> 8;
	a[i + 2] = (val & 0xff0000) >> 16;
	a[i + 3] = (val & 0xff000000) >> 24;
	return a;
}

function StringToUint8(str) {
	let arr = new Uint8Array(str.length);
	let len = str.length;
	for (let i = 0; i < len; i++) {
		arr[i] = str.charCodeAt(i);
	}
	return arr;
}

function Uint8ToString(arr) {
	let str = new String('');
	for (let i = 0; i < arr.length; i++) {
		str += String.fromCharCode(arr[i]);
	};
	return str;
}

function processOnMessageData(msg) {
	//sanity
	if (msg.message.byteLength <= NONCE_LEN || msg.message.byteLength > 0xffffff) {
		return;
	}

	let noncem = msg.message.slice(0, NONCE_LEN);
	let arr = msg.message.slice(NONCE_LEN, msg.message.byteLength - HMAC_LEN);
	let hmac = msg.message.slice(msg.message.byteLength - HMAC_LEN, msg.message.byteLength)
	let message = Uint8ToString(arr);

	//verify first hmac
	let hmacarr = new Uint8Array(noncem.byteLength + arr.byteLength);
	hmacarr.set(noncem, 0);
	hmacarr.set(arr, noncem.byteLength);
	let blakehmac = new BLAKE2s(HMAC_LEN, gEcbKey);
	blakehmac.update(hmacarr);
	let rhmac = blakehmac.digest();
	if (false == isEqualHmacs(hmac, rhmac)) {
		return;
	}

	let nonce = u8arr2nonce(noncem);
	let iv = nonce.slice(0, 2);

	let uid = bfEcb.trimZeros(bfEcb.decrypt(atob(msg.uid)));
	let channel = bfEcb.trimZeros(bfEcb.decrypt(atob(msg.channel)));
	let decrypted = bfCbc.decrypt(message, iv);

	if (decrypted.length < 16) {
		return;
	}

	let timestring = decrypted.slice(0, 8);
	let rarray = bfCbc.split64by32(timestring);
	let timeU15 = unscatterTime(rarray[0], rarray[1]);
	let weekstring = decrypted.slice(8, 16);
	let warray = bfCbc.split64by32(weekstring);
	let weekU15 = unscatterTime(warray[0], warray[1]);
	let msgDate = readTimestamp(timeU15 & ~(ISFULL | ISIMAGE), weekU15 & ~(ISMULTI | ISFIRST | ISLAST));
	message = decrypted.slice(16, decrypted.byteLength);

	let isFull = false;
	let isImage = false;
	let isMultipart = false;
	let isFirst = false;
	let isLast = false;
	if (timeU15 & ISFULL) {
		isFull = true;
	}
	if (timeU15 & ISIMAGE)
		isImage = true;
	if (weekU15 & ISMULTI)
		isMultipart = true;
	if (weekU15 & ISFIRST)
		isFirst = true;
	if (weekU15 & ISLAST)
		isLast = true;

	postMessage(["data", uid, channel, msgDate.valueOf(), message, isFull, isImage, isMultipart, isFirst, isLast]);
}

function msgDecode(data) {
	try {
		return CBOR.decode(data);
	} catch (err) {
		return null;
	}
}

function msgEncode(obj) {
	try {
		return CBOR.encode(obj);
	} catch (err) {
		return null;
	}
}

function processOnClose() {
	gWebSocket.close();
	let uid = bfEcb.trimZeros(bfEcb.decrypt(atob(gMyUid)));
	let channel = bfEcb.trimZeros(bfEcb.decrypt(atob(gMyChannel)));
	postMessage(["close", uid, channel, gMyUid, gMyChannel]);
}

function processOnOpen() {
	let uid = bfEcb.trimZeros(bfEcb.decrypt(atob(gMyUid)));
	let channel = bfEcb.trimZeros(bfEcb.decrypt(atob(gMyChannel)));
	postMessage(["init", uid, channel, gMyUid, gMyChannel]);
}

function openSocket(gMyPort, gMyAddr, uid, channel) {
	if (gWebSocket !== undefined && gWebSocket.readyState == WebSocket.OPEN) {
		return;
	}

	gWebSocket = new WebSocket("wss://" + gMyAddr + ":" + gMyPort
		+ "?myname=" + uid
		+ "&gMyChannel=" + channel, "mles-websocket");
	gWebSocket.binaryType = "arraybuffer";
	gWebSocket.onopen = function (event) {
		let ret = processOnOpen();
		if(ret < 0)
			console.log("Process on open failed: " + ret);

	};

	gWebSocket.onmessage = function (event) {
		if (event.data) {
			let msg = msgDecode(event.data);
			if(!msg)
				return;

			let ret = processOnMessageData(msg);
			if(ret < 0)
				console.log("Process on message data failed: " + ret);
		}
	};

	gWebSocket.onclose = function (event) {
		let ret = processOnClose();
		if(ret < 0)
			console.log("Process on close failed: " + ret)
	};
}

onmessage = function (e) {
	let cmd = e.data[0];
	let data = e.data[1];

	switch (cmd) {
		case "init":
			{
				gMyAddr = e.data[2];
				gMyPort = e.data[3];
				let uid = e.data[4];
				let channel = e.data[5];
				let fullkey = StringToUint8(e.data[6]);
				let isEncryptedChannel = e.data[7];


				let round = new BLAKE2s(32, fullkey);

				let blakecb = new BLAKE2s(7); //56-bits max key len
				blakecb.update(round.digest());
				let gEcbKey = blakecb.digest();

				round = new BLAKE2s(32, fullkey);
				round.update(fullkey);
				let blakeaontecb = new BLAKE2s(8); //aont key len
				blakeaontecb.update(round.digest());
				let ecbaontkey = blakeaontecb.digest();

				let blakecbc = new BLAKE2s(7); //56-bits max key len
				blakecbc.update(fullkey);
				let cbckey = blakecbc.digest();

				round = new BLAKE2s(32, fullkey);
				round.update(fullkey);
				round.update(fullkey);

				//drop unused
				fullkey = "";

				let blakeaontcbc = new BLAKE2s(8); //aont key len
				blakeaontcbc.update(round.digest());
				let cbcaontkey = blakeaontcbc.digest();

				bfEcb = new Blowfish(gEcbKey, ecbaontkey);
				bfCbc = new Blowfish(cbckey, cbcaontkey, "cbc");
				gMyUid = btoa(bfEcb.encrypt(uid));

				let bfchannel;
				if (!isEncryptedChannel) {
					bfchannel = bfEcb.encrypt(channel);
					gMyChannel = btoa(bfchannel);
				}
				else {
					gMyChannel = channel;
				}
				openSocket(gMyPort, gMyAddr, gMyUid, gMyChannel);
			}
			break;
		case "reconnect":
			{
				let uid = e.data[2];
				let channel = e.data[3];
				let isEncryptedChannel = e.data[4];

				uid = btoa(bfEcb.encrypt(uid));
				if (!isEncryptedChannel) {
					bfchannel = bfEcb.encrypt(channel);
					channel = btoa(bfchannel);
				}
				// verify that we have already opened the channel earlier
				if (gMyUid === uid && gMyChannel === channel) {
					openSocket(gMyPort, gMyAddr, gMyUid, gMyChannel);
				}
			}
			break;
		case "send":
			{
				let uid = e.data[2];
				let channel = e.data[3];
				let isEncryptedChannel = e.data[4];
				let randarr = e.data[5];

				//sanity
				if (randarr.length != 8) {
					break;
				}

				let isFull = e.data[6];
				let isImage = e.data[7];
				let isMultipart = e.data[8];
				let isFirst = e.data[9];
				let isLast = e.data[10];
				let valueofdate = e.data[11];

				let iv = randarr.slice(0, 2);
				let nonce = randarr.slice(0, 4);
				let rarray = randarr.slice(4);

				if (isEncryptedChannel) {
					channel = bfEcb.trimZeros(bfEcb.decrypt(atob(channel)));
				}

				let weekstamp = createWeekstamp(valueofdate);
				let timestamp = createTimestamp(valueofdate, weekstamp);
				if (isFull) {
					timestamp |= ISFULL;
				}
				if (isImage) {
					timestamp |= ISIMAGE;
				}
				if (isMultipart) {
					weekstamp |= ISMULTI;
					if (isFirst) {
						weekstamp |= ISFIRST;
					}
					if (isLast) {
						weekstamp |= ISLAST;
					}
				}
				let sval = scatterTime(rarray[0], rarray[1], timestamp);
				rarray[1] = sval;
				sval = scatterTime(rarray[2], rarray[3], weekstamp);
				rarray[3] = sval;

				let newmessage = bfCbc.num2block32(rarray[0]) + bfCbc.num2block32(rarray[1]) +
					bfCbc.num2block32(rarray[2]) + bfCbc.num2block32(rarray[3]) + data;
				let encrypted = bfCbc.encrypt(newmessage, iv);
				let noncearr = nonce2u8arr(nonce);
				let arr = StringToUint8(encrypted);

				// calculate hmac
				let hmacarr = new Uint8Array(noncearr.byteLength + arr.byteLength);
				hmacarr.set(noncearr, 0);
				hmacarr.set(arr, noncearr.byteLength);

				let blakehmac = new BLAKE2s(HMAC_LEN, gEcbKey);
				blakehmac.update(hmacarr);
				let hmac = blakehmac.digest();

				let newarr = new Uint8Array(noncearr.byteLength + arr.byteLength + hmac.byteLength);
				newarr.set(noncearr, 0);
				newarr.set(arr, noncearr.byteLength);
				newarr.set(hmac, noncearr.byteLength + arr.byteLength);
				let obj = {
					uid: btoa(bfEcb.encrypt(uid)),
					channel: btoa(bfEcb.encrypt(channel)),
					message: newarr
				};
				let encodedMsg = msgEncode(obj);
				if(!encodedMsg)
					break;
				try {
					gWebSocket.send(encodedMsg);
				} catch (err) {
					break;
				}
				postMessage(["send", uid, channel, isMultipart]);
			}
			break;
		case "close":
			{
				//let uid = e.data[2];
				//let channel = e.data[3];
				//let isEncryptedChannel = e.data[4];
				gWebSocket.close();
			}
			break;
	}
}
