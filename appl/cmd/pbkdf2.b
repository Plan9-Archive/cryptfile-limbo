# see rfc2898

implement Pbkdf2;

include "sys.m";
include "keyring.m";
include "security.m";
include "bufio.m";

include "pbkdf2.m";

sys: Sys;
keyring: Keyring;
bufio: Bufio;
Iobuf: import bufio;


init()
{
	sys = load Sys Sys->PATH;
	keyring = load Keyring Keyring->PATH;
	bufio = load Bufio Bufio->PATH;
}


makekey(salt: array of byte, keylen, rounds: int): (string, array of byte)
{
	if(keylen % 8 != 0)
		return ("key length must be multiple of eight", nil);
	passstr := askpass(1);
	if(passstr == nil)
		return ("could not read passphrase", nil);
	(r, key) := derivekey(array of byte passstr, salt, keylen, rounds);
	return (r, key);
}


askpass(twice: int): string
{
	for(;;) {
		pass := readpass("password");
		if(pass == nil)
			return nil;
		if(len array of byte pass > 64) {
			sys->print("pass phrase cannot be longer than 64 bytes\n");
			continue;
		}
		if(!twice)
			return pass;
		pass2 := readpass("re-enter password");
		if(pass == pass2)
			return pass;
		sys->print("passwords do not match, try again\n");
	}
}


prf(unew, pass, uprev: array of byte)
{
	keyring->hmac_sha1(uprev, len uprev, pass, unew, nil);
}


f(block, pass, salt: array of byte, rounds, i: int)
{
	saltint := array[len salt + 4] of byte;
	for(j := 0; j < len salt; j++)
		saltint[j] = salt[j];

	saltint[j++] = byte ((i>>24) & 16rff);
	saltint[j++] = byte ((i>>16) & 16rff);
	saltint[j++] = byte ((i>>8) & 16rff);
	saltint[j++] = byte ((i>>0) & 16rff);

	prf(block, pass, saltint);

	unew := array[len block] of byte;
	for(k := 1; k < rounds; k++) {
		prf(unew, pass, block);
		for(j = 0; j < len unew; j++)
			block[j] ^= unew[j];
	}
}


derivekey(pass, salt: array of byte, keylen, rounds: int): (string, array of byte)
{
	if(big keylen > ((big 1<<31)- big 1) * big keyring->SHA1dlen)
		return ("derived key too long", nil);
	if(len pass > 64)
		return ("pass phrase too long", nil); # inferno's hmac_sha1 only allows up to 64 characters...

	blocklen := keyring->SHA1dlen;
	nblocks := (keylen/8+blocklen-1)/blocklen;
	key := array[blocklen * nblocks] of byte;
	for(i := 0; i < nblocks; i++)
		f(key[i*blocklen:(i+1)*blocklen], pass, salt, rounds, i+1);
	return (nil, key[:keylen/8]);
}


# this code is from auth/aescbc.b
readpass(prompt: string): string
{
	cons := sys->open("/dev/cons", Sys->ORDWR);
	if(cons == nil)
		return nil;
	stdin := bufio->fopen(cons, Sys->OREAD);
	if(stdin == nil)
		return nil;
	cfd := sys->open("/dev/consctl", Sys->OWRITE);
	if (cfd == nil || sys->fprint(cfd, "rawon") <= 0)
		sys->fprint(sys->fildes(2), "warning: cannot hide typed password\n");
	s: string;
L:
	for(;;){
		sys->fprint(cons, "%s: ", prompt);
		s = "";
		while ((c := stdin.getc()) >= 0){
			case c {
			'\n' =>
				break L;
			'\b' or 8r177 =>
				if(len s > 0)
					s = s[0:len s - 1];
			'u' & 8r037 =>
				sys->fprint(cons, "\n");
				continue L;
			* =>
				s[len s] = c;
			}
		}
	}
	sys->fprint(cons, "\n");
	return s;
}
