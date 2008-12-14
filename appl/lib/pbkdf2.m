# see rfc2898

Pbkdf2: module {
	PATH:	con "/dis/lib/pbkdf2.dis";

	init:		fn();
	derivekey:	fn(pass, salt: array of byte, keylen, rounds: int): (array of byte, string);
};
