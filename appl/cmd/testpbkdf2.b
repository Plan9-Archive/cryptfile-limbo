implement Testpbkdf2;

include "sys.m";
include "draw.m";
include "arg.m";
include "keyring.m";
include "security.m";

include "pbkdf2.m";

sys: Sys;
arg: Arg;
random: Random;
pbkdf2: Pbkdf2;

usagestr := "testpbkdf2 [-k keylen] [-r rounds] [-s saltlen] [-S salt]";


Testpbkdf2: module {
	PATH:	con "testpbkdf2.dis";
	init:	fn(nil: ref Draw->Context, nil: list of string);
};


error(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
	raise "fail:"+s;
}


usage()
{
	sys->fprint(sys->fildes(2), "usage: %s\n", usagestr);
	raise "fail:usage";
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
		return char - '0';
	if(char >= 'a' && char <= 'f')
		return 10 + char - 'a';
	if(char >= 'A' && char <= 'F')
		return 10 + char - 'A';
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


init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg = load Arg Arg->PATH;
	random = load Random Random->PATH;
	pbkdf2 = load Pbkdf2 Pbkdf2->PATH;

	pbkdf2->init();
	arg->init(args);
	arg->setusage(usagestr);

	rounds := 2000;
	saltlen := 128;	# bytes
	keylen := 128;	# bits
	havesalt := 0;
	salt: array of byte;
	while((c := arg->opt()) != 0)
		case c {
		'k' =>	keylen = int arg->earg();
		'r' =>	rounds = int arg->earg();
		's' =>	saltlen = int arg->earg();
		'S' =>  havesalt = 1;
			salt = unhex(array of byte arg->earg());
		* =>	usage();
		}
	args = arg->argv();
	if(args != nil)
		usage();

	if(keylen % 8 != 0)
		error("key length should be multiple of 8");

	if(!havesalt) {
		salt = random->randombuf(random->NotQuiteRandom, saltlen);
		if(salt == nil)
			error("could not create salt");
	}
	sys->print("generating key\n");
	(r, key) := pbkdf2->makekey(salt, keylen, rounds);
	if(r != nil)
		error(sys->sprint("could not create key: %s", r));
	sys->print("rounds: %d\n", rounds);
	sys->print("salt: %s\n", hex(salt));
	sys->print("key: %s\n", hex(key));
}
