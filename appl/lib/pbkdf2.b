# see rfc2898

implement Pbkdf2;

include "sys.m";
	sys: Sys;
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "security.m";
include "keyring.m";
	kr: Keyring;
include "pbkdf2.m";


init()
{
	sys = load Sys Sys->PATH;
	bufio = load Bufio Bufio->PATH;
	kr = load Keyring Keyring->PATH;
}

prf(unew, pass, uprev: array of byte)
{
	kr->hmac_sha1(uprev, len uprev, pass, unew, nil);
}

f(block, pass, salt: array of byte, rounds, i: int)
{
	saltint := array[len salt+4] of byte;
	saltint[:] = salt;
	p32(saltint[len salt:], i);
	prf(block, pass, saltint);

	unew := array[len block] of byte;
	for(k := 1; k < rounds; k++) {
		prf(unew, pass, block);
		for(j := 0; j < len unew; j++)
			block[j] ^= unew[j];
	}
}

derivekey(pass, salt: array of byte, keylen, rounds: int): (array of byte, string)
{
	if(big keylen > ((big 1<<31)- big 1) * big kr->SHA1dlen)
		return (nil, "derived key too long");
	if(len pass > 64)
		return (nil, "pass phrase too long"); # inferno's hmac_sha1 only allows up to 64 characters...

	bsize: con kr->SHA1dlen;
	nblocks := (keylen/8+bsize-1)/bsize;
	key := array[bsize*nblocks] of byte;
	for(i := 0; i < nblocks; i++)
		f(key[i*bsize:(i+1)*bsize], pass, salt, rounds, i+1);
	return (key[:keylen/8], nil);
}

p32(buf: array of byte, v: int)
{
	o := 0;
	buf[o++] = byte (v>>24);
	buf[o++] = byte (v>>16);
	buf[o++] = byte (v>>8);
	buf[o++] = byte (v>>0);
}
