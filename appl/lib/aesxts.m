Aesxts: module
{
	PATH:	con "/dis/lib/aesxts.dis";

	init:	fn();

	crypt:	fn(st1, st2: ref Keyring->AESstate, seq: big, buf: array of byte, n: int, direction: int);
};
