implement Cryptfile;

# first sector contains information about the cryptfile.  example format:
# cryptfile0\n
# alg aes\n
# keylen 128\n
# rounds 10000\n
# salt base64salt\n
# ivec base64ivec\n
# crypted base64crypted\n
#
# base64* are base64-encoded strings.
#
# the key used to encrypt the data sectors is `keylen' bits,
# calculated using `rounds' rounds of pbkdf2, with `salt'.
# the calculation should take some time (e.g. a second), so password
# guessing is slow.
#
# `crypted' is the alg-cbc using the derived key of the concatenation of (only for aes for now):
# - random cookie, length is alg-bsize + leftover to make crypted a multiple of alg-bsize 
# - `keylen' bits of key
# - sha1 of cookie || key || header
# where header is the header minus `crypted'.
# this allows the password from the user to be verified.

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "string.m";
	str: String;
include "lists.m";
	lists: Lists;
include "daytime.m";
	daytime: Daytime;
include "styx.m";
	styx: Styx;
	Tmsg, Rmsg: import Styx;
	Styxserver, Fid, Navigator, Navop: import styxservers;
include "styxservers.m";
	styxservers: Styxservers;
include "security.m";
	random: Random;
include "keyring.m";
	kr: Keyring;
include "factotum.m";
	fact: Factotum;
include "encoding.m";
	base64: Encoding;
include "../lib/pbkdf2.m";
	pbkdf2: Pbkdf2;

Dflag, dflag, iflag: int;

Sectorsize:	con 512;
Hdrsize:	con 512;
Bsize:	con kr->AESbsize;
Saltlen: 	con 128; # bytes

filefd:	ref Sys->FD;
time0:	int;
config:	ref Cfg;
keyspec:	string;
filesize:	big;
keystate:	ref kr->AESstate;

Qroot, Qctl, Qdata: con iota;
tab := array[] of {
	(Qroot,		".",	Sys->DMDIR|8r555),
	(Qctl,		"ctl",	8r222),
	(Qdata,		"data",	8r666),
};
Qfirst:	con Qctl;
Qlast:	con Qdata;

srv: ref Styxserver;

Cfg: adt {
	alg:	string;
	keylen:	int;
	rounds:	int;
	salt:	array of byte;
	ivec:	array of byte;
	crypted:	array of byte;
};
Hdr: con "cryptfile0\n";

Cryptfile: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	str = load String String->PATH;
	lists = load Lists Lists->PATH;
	daytime = load Daytime Daytime->PATH;
	styx = load Styx Styx->PATH;
	styx->init();
	styxservers = load Styxservers Styxservers->PATH;
	styxservers->init(styx);
	kr = load Keyring Keyring->PATH;
	random = load Random Random->PATH;
	fact = load Factotum Factotum->PATH;
	fact->init();
	base64 = load Encoding Encoding->BASE64PATH;
	pbkdf2 = load Pbkdf2 Pbkdf2->PATH;
	pbkdf2->init();

	sys->pctl(Sys->NEWPGRP, nil);

	arg->init(args);
	arg->setusage(arg->progname()+" [-Ddi] [-k keyspec] file");
	while((c := arg->opt()) != 0)
		case c {
		'D' =>	Dflag++;
			styxservers->traceset(Dflag);
		'd' =>	dflag++;
		'i' =>	iflag++;
		'k' =>	keyspec = arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	file := hd args;

	filefd = sys->open(file, sys->ORDWR);
	if(filefd == nil)
		fail(sprint("open %q: %r", file));
	(ok, dir) := sys->fstat(filefd);
	if(ok != 0)
		fail(sprint("fstat %q", file));
	filesize = dir.length;

	if(iflag) {
		salt := random->randombuf(Random->NotQuiteRandom, Saltlen);
		ivec := random->randombuf(Random->ReallyRandom, Bsize);
		config = ref Cfg ("aes", 128, 10000, salt, ivec, nil);

		key := random->randombuf(Random->ReallyRandom, 128/8);
		config.crypted = makecrypted(config, key);
		zero(key);

		err := ensurekey();
		if(err == nil)
			err = writeheader(config, filefd);
		if(err != nil)
			fail(err);

		# force keystate to be recalculated below, to test key derivation & verification
		keystate = nil;
	}

	err: string;
	(config, err) = readheader(filefd);
	if(err == nil)
		err = ensurekey();
	if(err != nil)
		fail(err);

	time0 = daytime->now();

	navch := chan of ref Navop;
	spawn navigator(navch);

	nav := Navigator.new(navch);
	msgc: chan of ref Tmsg;
	(msgc, srv) = Styxserver.new(sys->fildes(0), nav, big Qroot);

	spawn serve(msgc);
}

serve(msgc: chan of ref Tmsg)
{
done:
	for(;;) alt {
	gm := <-msgc =>
		if(gm == nil)
			break done;
		pick m := gm {
		Readerror =>
			warn("read error: "+m.error);
			break done;
		}
		dostyx(gm);
	}
	killgrp(sys->pctl(0, nil));
}

makecrypted(c: ref Cfg, key: array of byte): array of byte
{
	cfgbuf := array of byte cfgpack(c);

	nkey := c.keylen/8;
	nb := 1+(nkey+Bsize-1)/Bsize+(kr->SHA1dlen+Bsize-1)/Bsize;
	crypted := array[nb*Bsize] of byte;

	ncookie := len crypted-(c.keylen/8+kr->SHA1dlen);
	cookie := random->randombuf(Random->NotQuiteRandom, ncookie);

	crypted[:] = cookie;
	crypted[ncookie:] = key;
	dg := kr->sha1(crypted, ncookie+len key, nil, nil);
	kr->sha1(cfgbuf, len cfgbuf, crypted[ncookie+len key:], dg);

	(ukey, err) := getuserkey();
	if(err != nil)
		fail(err);
	ks := kr->aessetup(ukey, c.ivec);
	zero(ukey);
	kr->aescbc(ks, crypted, len crypted, kr->Encrypt);
	return crypted;
}

cfgpack(c: ref Cfg): string
{
	# note: without c.crypted
	return sprint("%salg %s\nkeylen %d\nrounds %d\nsalt %s\nivec %s\n",
			Hdr, c.alg, c.keylen, c.rounds,
			base64->enc(c.salt), base64->enc(c.ivec));
}

verifysig(c: ref Cfg, buf: array of byte): string
{
	cfgbuf := array of byte cfgpack(c);
	sig := array[kr->SHA1dlen] of byte;
	dg := kr->sha1(buf, len buf-kr->SHA1dlen, nil, nil);
	kr->sha1(cfgbuf, len cfgbuf, sig, dg);
	if(!eq(buf[len buf-kr->SHA1dlen:], sig))
		return "bad signature";
	return nil;
}

getuserkey(): (array of byte, string)
{
	(nil, pass) := fact->getuserpasswd("proto=pass service=cryptfile "+keyspec);
	if(pass == nil)
		return (nil, "no key");
	return pbkdf2->derivekey(array of byte pass, config.salt, config.keylen, config.rounds);
}

ensurekey(): string
{
	if(keystate != nil)
		return nil;

	(ukey, err) := getuserkey();
	if(err != nil)
		fail(err);

	plain := array[len config.crypted] of byte;
	plain[:] = config.crypted;

	ks := kr->aessetup(ukey, config.ivec);
	zero(ukey);
	kr->aescbc(ks, plain, len plain, kr->Decrypt);

	err = verifysig(config, plain);
	if(err != nil)
		return err;

	nkey := config.keylen/8;
	key := plain[len plain-(nkey+kr->SHA1dlen):];
	keystate = kr->aessetup(key[:nkey], nil);
	if(keystate == nil)
		return sprint("key: %r");
	zero(plain);

	return nil;
}

getval(l, key: string): (string, string)
{
	if(!str->prefix(key+" ", l))
		return (nil, sprint("bad header, missing key %#q", key));
	return (l[len key+1:], nil);
}

getint(key, s: string): (int, string)
{
	if(str->drop(s, "0-9") != nil)
		return (0, sprint("bad header, key %#q: not a number", key));
	return (int s, nil);
}

lines(s: string): list of string
{
	l: list of string;
	line: string;
	for(;;) {
		if(s == nil || s[0] == '\0')
			break;
		(line, s) = str->splitstrl(s, "\n");
		if(s != nil)
			s = s[1:];
		l = line::l;
	}
	return lists->reverse(l);
}

readheader(fd: ref Sys->FD): (ref Cfg, string)
{
	buf := array[Hdrsize] of byte;
	n := preadn(fd, buf, len buf, big 0);
	if(n < 0)
		fail(sprint("reading header: %r"));
	if(n != len buf)
		fail("short read for header");

	s := string buf;
	if(!str->prefix(Hdr, s))
		return (nil, "bad header, not a cryptfile");
	s = s[len Hdr:];

	l := lines(s);
	if(len l != 6)
		return (nil, sprint("bad header, wrong number of lines (%d)", len l));

	a := l2a(l);
	v := array[len a] of string;
	keys := array[] of {"alg", "keylen", "rounds", "salt", "ivec", "crypted"};
	err: string;
	for(i := 0; err == nil && i < len keys; i++)
		(v[i], err) = getval(a[i], keys[i]);

	alg: string;
	keylen, rounds: int;
	salt, ivec, crypted: array of byte;
	if(err == nil && (alg = v[0]) != "aes")
		err = sprint("alg not 'aes': %#q", alg);
	if(err == nil)
		(keylen, err) = getint(keys[1], v[1]);
	if(err == nil)
		(rounds, err) = getint(keys[2], v[2]);
	if(err == nil)
		salt = base64->dec(v[3]);
	if(err == nil)
		ivec = base64->dec(v[4]);
	if(err == nil)
		crypted = base64->dec(v[5]);

	cfg := ref Cfg (alg, keylen, rounds, salt, ivec, crypted);
	if(err == nil && cfg.keylen != 128)
		err = "only 128 bits keys supported for now";
	if(err == nil && len cfg.salt != Saltlen)
		err = sprint("bad header, len salt %d != %d", len cfg.salt, Saltlen);
	if(err == nil && len cfg.crypted % Bsize != 0)
		err = sprint("bad header, len crypted %d %% Bsize != 0", len crypted);
	if(err == nil && len cfg.crypted < Bsize+Bsize+kr->SHA1dlen)
		err = sprint("bad header, len crypted %d too small", len crypted);
	return (cfg, err);
}


writeheader(c: ref Cfg, fd: ref Sys->FD): string
{
	buf := array[Hdrsize] of {* => byte 0};
	cfgbuf := array of byte cfgpack(c);
	cryptbuf := sys->aprint("crypted %s\n", base64->enc(c.crypted));
	if(len cfgbuf+len cryptbuf > len buf)
		return "header too large";
	buf[:] = cfgbuf;
	buf[len cfgbuf:] = cryptbuf;
	
	n := sys->pwrite(fd, buf, len buf, big 0);
	if(n != len buf)
		return sprint("writing header: %r");
	return nil;
}


bufincr(d: array of byte)
{
	for(i := len d-1; i >= 0; i--)
		if(++d[i] != byte 0)
			return;
}

bufxor(dst, buf: array of byte, n: int)
{
	for(i := 0; i < n; i++)
		dst[i] ^= buf[i];
}

cbcsector(st: ref kr->AESstate, ivec: array of byte, buf: array of byte, n: int, direction: int)
{
	if(direction == kr->Encrypt) {
		bufxor(buf, ivec, len ivec);
		kr->aesecb(st, buf, Bsize, kr->Encrypt);
		for(o := Bsize; o < n; o += Bsize) {
			bufxor(buf[o:], buf[o-Bsize:], Bsize);
			kr->aesecb(st, buf[o:], Bsize, kr->Encrypt);
		}
	} else {
		for(o := n-Bsize; o > 0; o -= Bsize) {
			kr->aesecb(st, buf[o:], Bsize, kr->Decrypt);
			bufxor(buf[o:], buf[o-Bsize:], Bsize);
		}
		kr->aesecb(st, buf[o:], Bsize, kr->Decrypt);
		bufxor(buf[o:], ivec, len ivec);
	}
}

crypt(off: big, buf: array of byte, direction: int): string
{
	#say(sprint("aes ecb off=%bd n=%d", off, len buf));

	err := ensurekey();
	if(err != nil)
		return err;

	n := len buf/Sectorsize;
	ctr := array[Bsize] of {* => byte 0};
	p64(ctr, off/big Sectorsize);
	for(i := 0; i < n; i++) {
		#say(sprint("crypt, sector %bd, ctr %s", (off/big Sectorsize)+big i, hex(ctr)));

		# encrypt the sector number to get an ivec
		xor := array[len ctr] of byte;
		xor[:] = ctr;
		kr->aesecb(keystate, xor, len xor, kr->Encrypt);

		# then cbc the data with the ivec
		cbcsector(keystate, xor, buf, Sectorsize, direction);

		# and prepare for the next
		bufincr(ctr);
		buf = buf[Sectorsize:];
	}
	return nil;
}

aligned(off: big, n: int): string
{
	if(off % big Sectorsize != big 0 || n % Sectorsize != 0)
		return "not aligned";

	if(off > filesize)
		return "beyong file end";
	return nil;
}

dowrite(buf: array of byte, off: big): string
{
	say(sprint("write, off=%bd len=%d", off, len buf));

	err := aligned(off, len buf);
	if(err != nil)
		return "write: "+err;

	if(off+big len buf > filesize)
		return "write outside file boundaries";

	err = crypt(off, buf, kr->Encrypt);
	if(err != nil)
		return err;
	n := sys->pwrite(filefd, buf, len buf, off+big Hdrsize);
	if(n < len buf)
		return sprint("write: %r");
	return nil;
}

doread(n: int, off: big): (array of byte, string)
{
	say(sprint("read, off=%bd n=%d", off, n));

	err := aligned(off, n);
	if(err != nil)
		return (nil, "read: "+err);

	buf := array[n] of byte;
	nn := preadn(filefd, buf, len buf, off+big Hdrsize);
	if(nn < 0)
		return (nil, sprint("read: %r"));
	if(nn % Sectorsize != 0)
		return (nil, "partial read misaligned");
	buf = buf[:nn];
	err = crypt(off, buf, kr->Decrypt);
	return (buf, err);
}

dostyx(gm: ref Tmsg)
{
	pick m := gm {
	Open =>
		(fid, nil, nil, err) := srv.canopen(m);
		if(fid == nil)
			return replyerror(m, err);

		srv.default(m);

	Write =>
		(f, err) := srv.canwrite(m);
		if(f == nil)
			return replyerror(m, err);
		q := int f.path&16rff;

		case q {
		Qctl =>
			s := string m.data;
			if(s == "forget" || s == "forget\n") {
				keystate = nil;
				srv.reply(ref Rmsg.Write(m.tag, len m.data));
			} else
				replyerror(m, "bad ctl");
				
		Qdata =>
			werr := dowrite(m.data, m.offset);
			if(werr != nil)
				srv.reply(ref Rmsg.Error(m.tag, werr));
			else
				srv.reply(ref Rmsg.Write(m.tag, len m.data));
		* =>
			srv.default(m);
		}

	Clunk or Remove =>
		srv.default(m);

	Read =>
		f := srv.getfid(m.fid);
		if(f.qtype & Sys->QTDIR) {
			srv.default(m);
			return;
		}
		q := int f.path&16rff;

		case q {
		Qdata =>
			(buf, err) := doread(m.count, m.offset);
			
			if(err != nil)
				srv.reply(ref Rmsg.Error(m.tag, err));
			else
				srv.reply(ref Rmsg.Read(m.tag, buf));
		* =>
			srv.default(m);
		}

	Wstat =>
		f := srv.getfid(m.fid);
		q := int f.path&16rff;

		case q {
		Qdata =>
			# xxx only allow a "flush to disk" (nulldir) wstat?
			srv.reply(ref Rmsg.Wstat(m.tag));
		* =>
			srv.default(m);
		}

	Flush =>
		srv.default(gm);
	* =>
		srv.default(gm);
	}
}

navigator(c: chan of ref Navop)
{
again:
	for(;;) {
		navop := <-c;
		q := int (navop.path&big 16rff);

		pick op := navop {
		Stat =>
			op.reply <-= (dir(int op.path, 0), nil);

		Walk =>
			if(op.name == "..") {
				op.reply <-= (dir(Qroot, 0), nil);
				continue again;
			}
			case q {
			Qroot =>
				for(i := Qfirst; i <= Qlast; i++)
					if(tab[i].t1 == op.name) {
						op.reply <-= (dir(tab[i].t0, time0), nil);
						continue again;
					}
				op.reply <-= (nil, styxservers->Enotfound);

			* =>
				op.reply <-= (nil, styxservers->Enotdir);
			}
		Readdir =>
			if(int op.path == Qroot) {
				avail := Qlast+1-Qfirst;
				have := 0;
				for(i := op.offset; have < op.count && i < avail; i++)
					case Qfirst+i {
					Qctl or Qdata =>
						op.reply <-= (dir(Qfirst+i, 0), nil);
						have++;
					* =>
						raise "internal bad";
					}
			} else {
				raise "internal bad";
			}
			op.reply <-= (nil, nil);
		}
	}
}

dir(path, mtime: int): ref Sys->Dir
{
	(nil, name, perm) := tab[path&16rff];
	d := ref sys->zerodir;
	d.name = name;
	d.uid = d.gid = "cryptfile";
	d.qid.path = big path;
	if(perm&Sys->DMDIR)
		d.qid.qtype = Sys->QTDIR;
	else
		d.qid.qtype = Sys->QTFILE;
	d.mtime = d.atime = mtime;
	d.mode = perm;
	if(path == Qdata)
		d.length = filesize-big Hdrsize;
	return d;
}

replyerror(m: ref Tmsg, s: string)
{
	srv.reply(ref Rmsg.Error(m.tag, s));
}

preadn(fd: ref Sys->FD, buf: array of byte, n: int, off: big): int
{
	t := 0;
	while(n > 0) {
		nn := sys->pread(fd, buf[t:], n, off);
		if(nn < 0)
			return nn;
		if(nn == 0)
			break;
		n -= nn;
		off += big nn;
		t += nn;
	}
	return t;
}

hex(d: array of byte): string
{
	s := "";
	for(i := 0; i < len d; i++)
		s += sprint("%02x", int d[i]);
	return s;
}

eq(a, b: array of byte): int
{
	if(len a != len b)
		return 0;
	for(i := 0; i < len a; i++)
		if(a[i] != b[i])
			return 0;
	return 1;
}

p64(d: array of byte, v: big)
{
	d = d[len d-8:];
	o := 0;
	d[o++] = byte (v>>56);
	d[o++] = byte (v>>48);
	d[o++] = byte (v>>40);
	d[o++] = byte (v>>32);
	d[o++] = byte (v>>24);
	d[o++] = byte (v>>16);
	d[o++] = byte (v>>8);
	d[o++] = byte (v>>0);
}

zero(d: array of byte)
{
	d[:] = array[len d] of {* => byte '0'};
}

l2a[T](l: list of T): array of T
{
	a := array[len l] of T;
	i := 0;
	for(; l != nil; l = tl l)
		a[i++] = hd l;
	return a;
}

progctl(pid: int, ctl: string)
{
	fd := sys->open(sprint("/prog/%d/ctl", pid), Sys->OWRITE);
	if(fd != nil)
		sys->fprint(fd, "%s", ctl);
}

killgrp(pid: int)
{
	progctl(pid, "killgrp");
}

warn(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}

say(s: string)
{
	if(dflag)
		warn(s);
}

fail(s: string)
{
	warn(s);
	killgrp(sys->pctl(0, nil));
	raise "fail:"+s;
}
