implement Cryptfile;

include "sys.m";
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "string.m";
include "daytime.m";
include "styx.m";
	Tmsg, Rmsg: import Styx;
include "styxservers.m";
include "keyring.m";

sys: Sys;
str: String;
daytime: Daytime;
styx: Styx;
styxservers: Styxservers;
keyring: Keyring;

sprint: import sys;
Styxserver, Fid, Navigator, Navop: import styxservers;

Dflag, dflag: int;

Sectorsize:	con 512;
filesize:	big;
filefd:	ref Sys->FD;
cryptkey:	array of byte;
starttime:	int;


Qroot, Qdata: con iota;
tab := array[] of {
	(Qroot,		".",	Sys->DMDIR|8r555),
	(Qdata,		"data",	8r666),
	# xxx also implement a ctl file to forget and give a password.  and a file that that raises needs for a key.
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
	keyring = load Keyring Keyring->PATH;

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


	# xxx get proper key somewhere
	cryptkey = array of byte "Ais5ahjei2uzeyoo";
	say(sprint("len cryptkey=%d", len cryptkey));

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


cbc(key: array of byte, offset: big, buf: array of byte, direction: int)
{
	say(sprint("aes offset=%bd len buf=%d", offset, len buf));
	n := len buf / Sectorsize;
	ivec := array[len key] of byte;
	for(i := 0; i < n; i++) {
		for(j := 0; j < len ivec; j++)
			ivec[j] = byte 0;
		j = 0;
		for(index := offset / big Sectorsize + big i; index > big 0; index >>= 8)
			ivec[j++] = byte (index & big 16rff);
		state := keyring->aessetup(key, ivec);
		keyring->aescbc(state, ivec, len ivec, keyring->Encrypt);
		state = keyring->aessetup(key, ivec);
		keyring->aescbc(state, buf[i*Sectorsize:], Sectorsize, direction);
	}
}

dowrite(buf: array of byte, offset: big): string
{
		say(sprint("write received, offset=%bd len=%d", offset, len buf));
		if(offset % big Sectorsize != big 0 || len buf % Sectorsize != 0)
			return "write not aligned";

		if(offset+big len buf > filesize)
			return "write outside file boundaries";

		cbc(cryptkey, offset, buf, keyring->Encrypt);
		n := sys->pwrite(filefd, buf, len buf, big offset);
		if(n < len buf)
			return sprint("writing to file: %r");
		return nil;
}

doread(count: int, offset: big): (array of byte, string)
{
		say(sprint("read received, offset=%bd count=%d", offset, count));
		if(offset % big Sectorsize != big 0 || count % Sectorsize != 0)
			return (nil, "read not aligned");

		if(big offset > filesize)
			return (nil, "offset lies outside file");

		buf := array[count] of byte;
		n := sys->pread(filefd, buf, len buf, big offset);
		if(n < 0)
			return (nil, sprint("reading from file: %r"));
		n &= ~(Sectorsize-1);
		buf = buf[:n];
		cbc(cryptkey, offset, buf, keyring->Decrypt);
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

		# xxx make sure read is on proper boundaries, and do read

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
