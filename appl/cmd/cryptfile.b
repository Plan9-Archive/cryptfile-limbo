implement Cryptfile;

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
include "daytime.m";
	daytime: Daytime;
include "styx.m";
	styx: Styx;
	Tmsg, Rmsg: import Styx;
	Styxserver, Fid, Navigator, Navop: import styxservers;
include "styxservers.m";
	styxservers: Styxservers;
include "keyring.m";
	kr: Keyring;

Dflag, dflag: int;

Sectorsize:	con 512;
Bsize:	con kr->AESbsize;
filesize:	big;
filefd:	ref Sys->FD;
starttime:	int;
keystate:	ref kr->AESstate;


Qroot, Qdata: con iota;
tab := array[] of {
	(Qroot,		".",	Sys->DMDIR|8r555),
	(Qdata,		"data",	8r666),
	# xxx also implement a ctl file to clear & forget the keystate.
};
Qfirst:	con Qdata;
Qlast:	con Qdata;

srv: ref Styxserver;

Cryptfile: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	str = load String String->PATH;
	daytime = load Daytime Daytime->PATH;
	styx = load Styx Styx->PATH;
	styx->init();
	styxservers = load Styxservers Styxservers->PATH;
	styxservers->init(styx);
	kr = load Keyring Keyring->PATH;

	sys->pctl(Sys->NEWPGRP, nil);

	arg->init(args);
	arg->setusage(arg->progname()+" [-Dd] file");
	while((c := arg->opt()) != 0)
		case c {
		'D' =>	Dflag++;
			styxservers->traceset(Dflag);
		'd' =>	dflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	file := hd args;

	navch := chan of ref Navop;
	spawn navigator(navch);

	nav := Navigator.new(navch);
	msgc: chan of ref Tmsg;
	(msgc, srv) = Styxserver.new(sys->fildes(0), nav, big Qroot);

	# xxx get proper key somewhere (factotum)
	cryptkey := array of byte "Ais5ahjei2uzeyoo";
	say(sprint("len cryptkey=%d", len cryptkey));
	keystate = kr->aessetup(cryptkey, nil);
	zero(cryptkey);

	filefd = sys->open(file, sys->ORDWR);
	if(filefd == nil)
		fail(sprint("open %q: %r", file));
	(ok, dir) := sys->fstat(filefd);
	if(ok != 0)
		fail(sprint("fstat %q", file));
	filesize = dir.length;
	starttime = daytime->now();

done:
	for(;;) alt {
	gm := <-msgc =>
		if(gm == nil)
			break;
		pick m := gm {
		Readerror =>
			warn("read error: "+m.error);
			break done;
		}
		dostyx(gm);
	}
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

cbcsector(st: ref kr->AESstate, ivec: array of byte, buf: array of byte, direction: int)
{
	if(direction == kr->Encrypt) {
		#say(sprint("cbc encrypt, ivec %s, len buf %d", hex(ivec), len buf));
		bufxor(buf, ivec, len ivec);
		kr->aesecb(st, buf, Bsize, kr->Encrypt);
		for(o := Bsize; o < Sectorsize; o += Bsize) {
			bufxor(buf[o:], buf[o-Bsize:], Bsize);
			kr->aesecb(st, buf[o:], Bsize, kr->Encrypt);
			#say(sprint("cbc encrypt, o %d, cipher %s", o, hex(buf[o:o+Bsize])));
		}
	} else {
		#say(sprint("cbc decrypt, ivec %s, len buf %d", hex(ivec), len buf));
		for(o := Sectorsize-Bsize; o > 0; o -= Bsize) {
			#say(sprint("cbc encrypt, o %d, cipher %s", o, hex(buf[o:o+Bsize])));
			kr->aesecb(st, buf[o:], Bsize, kr->Decrypt);
			bufxor(buf[o:], buf[o-Bsize:], Bsize);
			#say(sprint("cbc encrypt, o %d, plain %s", o, hex(buf[o:o+Bsize])));
		}
		#say(sprint("cbc encrypt last, o %d, cipher %s", o, hex(buf[o:o+Bsize])));
		kr->aesecb(st, buf[o:], Bsize, kr->Decrypt);
		bufxor(buf[o:], ivec, len ivec);
		#say(sprint("cbc encrypt last, o %d, plain %s", o, hex(buf[o:o+Bsize])));
	}
}

crypt(off: big, buf: array of byte, direction: int)
{
	#say(sprint("aes ecb off=%bd n=%d", off, len buf));

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
		cbcsector(keystate, xor, buf, direction);

		# and prepare for the next
		bufincr(ctr);
		buf = buf[Sectorsize:];
	}
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

	crypt(off, buf, kr->Encrypt);
	n := sys->pwrite(filefd, buf, len buf, off);
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
	nn := preadn(filefd, buf, len buf, big off);
	if(nn < 0)
		return (nil, sprint("read: %r"));
	if(nn % Sectorsize != 0)
		return (nil, "partial read misaligned");
	buf = buf[:nn];
	crypt(off, buf, kr->Decrypt);
	return (buf, nil);
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

		# xxx make sure write is on proper boundaries, and do write
		case q {
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
		say(sprint("read f.path=%bd", f.path));
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

		if(q != Qdata) {
			srv.default(m);
			return;
		}

		# xxx handle case for Qdata, only allow a "flush to disk" (nulldir) wstat?

		srv.reply(ref Rmsg.Wstat(m.tag));

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
		say(sprint("have navop, tag %d", tagof navop));
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
						op.reply <-= (dir(tab[i].t0, starttime), nil);
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
					Qdata =>
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
		d.length = filesize;
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

kill(pid: int)
{
	fd := sys->open(sprint("/prog/%d/ctl", pid), Sys->OWRITE);
	if(fd != nil)
		sys->fprint(fd, "kill");
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
	raise "fail:"+s;
}
