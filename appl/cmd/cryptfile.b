# remove passphrase from memory when key has been derived
# stop using file2chan since it cannot give the size of the file.  need something very similar though.

implement Crypt;

include "sys.m";
include "draw.m";
include "keyring.m";

sys: Sys;
print, sprint, fprint: import sys;
keyring: Keyring;


Crypt: module {
	PATH:	con "cryptfile.dis";
	init:	fn(nil: ref Draw->Context, nil: list of string);
};


debug(s: string)
{
	fprint(sys->fildes(2), "%s\n", s);
}


error(s: string)
{
	fprint(sys->fildes(2), "%s: %r\n", s);
	raise sys->sprint("fail:%s: %r", s);
}


usage()
{
	fprint(sys->fildes(2), "usage: %s store name\n", "crypt");
	raise "fail:usage";
}


cbc(key: array of byte, offset: big, buf: array of byte, sectorsize: int, direction: int)
{
	debug(sprint("aes offset=%bd len buf=%d", offset, len buf));
	n := len buf / sectorsize;
	ivec := array[len key] of byte;
	for(i := 0; i < n; i++) {
		for(j := 0; j < len ivec; j++)
			ivec[j] = byte 0;
		j = 0;
		for(index := offset / big sectorsize + big i; index > big 0; index >>= 8)
			ivec[j++] = byte (index & big 16rff);
		state := keyring->aessetup(key, ivec);
		keyring->aescbc(state, ivec, len ivec, keyring->Encrypt);
		state = keyring->aessetup(key, ivec);
		keyring->aescbc(state, buf[i*sectorsize:], sectorsize, direction);
	}
}


init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	keyring = load Keyring Keyring->PATH;

	sectorsize := 512;

	args = tl args;
	if(len(args) != 2)
		usage();
	storename := hd args;
	name := hd tl args;

	key := array of byte "Ais5ahjei2uzeyoo";
	debug(sprint("len key=%d", len key));

	store := sys->open(storename, sys->ORDWR);
	if(store == nil)
		error(sprint("open %s", storename));
	(r, dir) := sys->fstat(store);
	if(r != 0)
		error(sprint("fstat %s", storename));
	storesize := dir.length;

	fio := sys->file2chan("/srv", name);
	if(fio == nil)
		error("file2chan");

	for(;;) alt {
	# read
	(offset, count, fid, rc) := <- fio.read =>
		if(rc == nil)
			continue;

		debug(sprint("read received, offset=%d count=%d fid=%d", offset, count, fid));
		if(offset % sectorsize != 0 || count % sectorsize != 0) {
			debug("read not aligned");
			rc <- = (nil, "read not aligned");
			continue;
		}

		if(big offset > storesize) {
			rc <- = (nil, "offset lies outside file");
			continue;
		}

		data := array[count] of byte;
		n := sys->pread(store, data, len data, big offset);
		if(n < 0) {
			rc <- = (nil, sprint("error while reading: %r"));
			continue;
		}
		n &= ~(sectorsize-1);
		data = data[:n];
		cbc(key, big offset, data, sectorsize, keyring->Decrypt);
		rc <- = (data, nil);

	# write
	(offset, data, fid, wc) := <- fio.write =>
		if(wc == nil)
			continue;

		debug(sprint("write received, offset=%d len=%d fid=%d", offset, len(data), fid));
		if(offset % sectorsize != 0 || len data % sectorsize != 0) {
			debug("write not aligned");
			wc <- = (0 , "write not aligned");
			continue;
		}

		if(big (offset+len data) > storesize) {
			wc <- = (0, "write outside file boundaries");
			continue;
		}

		cbc(key, big offset, data, sectorsize, keyring->Encrypt);
		n := sys->pwrite(store, data, len data, big offset);
		if(n < len data) {
			wc <- = (n, sprint("write error: %r"));
			continue;
		}
		wc <- = (n, nil);
	};
}
