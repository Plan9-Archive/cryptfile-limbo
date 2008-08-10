Pbkdf2: module {
	PATH:	con "pbkdf2.dis";
	init:		fn();
	makekey:	fn(salt: array of byte, keylen, rounds: int): (string, array of byte);
	derivekey:	fn(pass, salt: array of byte, keylen, rounds: int): (string, array of byte);
};
