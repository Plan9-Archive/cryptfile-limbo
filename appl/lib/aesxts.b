implement Aesxts;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "keyring.m";
	kr: Keyring;
include "aesxts.m";

Bsize: con kr->AESbsize;

init()
{
	sys = load Sys Sys->PATH;
	kr = load Keyring Keyring->PATH;
}

xtsblock(st: ref kr->AESstate, x, block: array of byte, direction: int)
{
	for(i := 0; i < Bsize; i++)
		block[i] ^= x[i];
	kr->aesecb(st, block, Bsize, direction);
	for(i = 0; i < Bsize; i++)
		block[i] ^= x[i];
}

xtsmult(x: array of byte)
{
	bin := bout := byte 0;
	for(i := 0; i < Bsize; i++) {
		bout = x[i]>>7;
		x[i] = (x[i]<<1)|bin;
		bin = bout;
	}
	if(bin != byte 0)
		x[0] ^= byte 16r87; # alpha
}

# C = Ek1(P xor X) xor X
# X = Ek2(i) xor alpha^j, with i = sector number, j = block number, alpha = 0x87
crypt(st1, st2: ref kr->AESstate, sector: big, buf: array of byte, n: int, direction: int)
{
	# calculate X for first block
	x := array[Bsize] of {* => byte 0};
	p64le(x, sector);
	kr->aesecb(st2, x, Bsize, kr->Encrypt);

	for(o := 0; o < n; o += Bsize) {
		xtsblock(st1, x, buf[o:o+Bsize], direction);
		xtsmult(x);
	}
}

p64le(d: array of byte, v: big)
{
	o := 8;
	d[--o] = byte (v>>56);
	d[--o] = byte (v>>48);
	d[--o] = byte (v>>40);
	d[--o] = byte (v>>32);
	d[--o] = byte (v>>24);
	d[--o] = byte (v>>16);
	d[--o] = byte (v>>8);
	d[--o] = byte (v>>0);
}
