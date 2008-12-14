implement Testpbkdf2;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
	arg: Arg;
include "arg.m";
include "keyring.m";
include "security.m";
	random: Random;
include "factotum.m";
	fact: Factotum;
include "../lib/pbkdf2.m";
	pbkdf2: Pbkdf2;

Testpbkdf2: module {
	init:	fn(nil: ref Draw->Context, nil: list of string);
};

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg = load Arg Arg->PATH;
	random = load Random Random->PATH;
	fact = load Factotum Factotum->PATH;
	fact->init();
	pbkdf2 = load Pbkdf2 Pbkdf2->PATH;
	if(pbkdf2 == nil)
		fail(sprint("loading pbkdf2: %r"));
	pbkdf2->init();

	rounds := 2000;
	saltlen := 128;	# bytes
	keylen := 128;	# bits
	havesalt := 0;
	salt: array of byte;

	arg->init(args);
	arg->setusage("testpbkdf2 [-k keylen] [-r rounds] [-s saltlen] [-S salt]");
	while((c := arg->opt()) != 0)
		case c {
		'k' =>	keylen = int arg->earg();
		'r' =>	rounds = int arg->earg();
		's' =>	saltlen = int arg->earg();
		'S' =>  havesalt = 1;
			salt = unhex(array of byte arg->earg());
		* =>	arg->usage();
		}
	args = arg->argv();
	if(args != nil)
		arg->usage();

	if(keylen % 8 != 0)
		fail("key length should be multiple of 8");

	if(!havesalt) {
		salt = random->randombuf(random->NotQuiteRandom, saltlen);
		if(salt == nil)
			fail("could not create salt");
	}
	sys->print("generating key\n");
	(nil, pass) := fact->getuserpasswd("proto=pass service=testpbkdf2");
	if(pass == nil)
		fail("no password");
	(key, err) := pbkdf2->derivekey(array of byte pass, salt, keylen, rounds);
	if(err != nil)
		fail(sprint("deriving key: %s", err));
	sys->print("rounds: %d\n", rounds);
	sys->print("salt: %s\n", hex(salt));
	sys->print("key: %s\n", hex(key));
}

hex(buf: array of byte): string
{
	s := "";
	for(i := 0; i < len buf; i++)
		s += sys->sprint("%02x", int buf[i]);
	return s;
}

hexint(char: int): int
{
	if(char >= '0' && char <= '9')
		return char-'0';
	if(char >= 'a' && char <= 'f')
		return char-'a'+10;
	if(char >= 'A' && char <= 'F')
		return char-'A'+10;
	return -1;
}

unhex(s: array of byte): array of byte
{
	if(len s % 2 != 0)
		raise "fail:uneven number of characters in salt";
	a := array[len s / 2] of byte;
	for(i := 0; i < len a; i++)
		a[i] = byte (16 * hexint(int s[i*2]) + hexint(int s[i*2+1]));
	return a;
}

fail(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
	raise "fail:"+s;
}
