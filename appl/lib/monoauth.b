implement Monoauth;

#
# monoauth -- mutual authentication and an encrypted stream with $Mono
#
# Both sides hold an EdDSA key pair and a certificate from the machine's
# signer (/keydb/mono-signer).  The exchange is:
#
#	one message each, in either direction, then a shared key
#	len name || name || pk || cert || ephemeral pk
#
# Each certificate signs name || "\n" || pk, so the name is bound to the
# key.  The ephemeral X25519 keys produce a shared secret; BLAKE2b
# derives one key per direction; XChaCha20-Poly1305 protects each
# record, with a per-direction counter as the nonce.
#
# Records are: 4-byte length, 16-byte tag, ciphertext.  The plaintext
# side is a file2chan stream, because callers (rcmd, cpu, listen) need
# one fd they can both read and write, and may hand it to export(2).
#
# Identity file (/usr/<name>/keyring/mono):
#
#	name <name>
#	sk <64 bytes, hex>
#	cert <64 bytes, hex>
#
# The signer file (/keydb/mono-signer) has the same sk line; its public
# half (sk[32:64]) is what verifies every certificate.
#

include "sys.m";
	sys: Sys;

include "draw.m";

include "mono.m";
	mono: Mono;

include "monoauth.m";

SIGNER:		con "/keydb/mono-signer";
CHANDIR:	con "/tmp/mono";
MAXREC:		con 4096;

Id: adt
{
	name:	string;
	sk:	array of byte;
	pk:	array of byte;
	cert:	array of byte;
};

# ---- entry points ----------------------------------------------------

server(keyfile: string, fd: ref Sys->FD): (ref Sys->FD, string)
{
	return run(keyfile, fd, 1);
}

client(keyfile: string, fd: ref Sys->FD): (ref Sys->FD, string)
{
	return run(keyfile, fd, 0);
}

run(keyfile: string, fd: ref Sys->FD, isserver: int): (ref Sys->FD, string)
{
	sys = load Sys Sys->PATH;
	mono = load Mono Mono->PATH;
	if(mono == nil)
		return (nil, "cannot load " + Mono->PATH);

	(me, err) := loadid(keyfile);
	if(me == nil)
		return (nil, err);
	(signer, serr) := loadsigner();
	if(signer == nil)
		return (nil, serr);

	# Ephemeral X25519 key: random scalar, public key from the library.
	ephx := readrandom(32);
	if(ephx == nil)
		return (nil, "cannot read /dev/random");
	ephpk := mono->xpublic(ephx);
	if(ephpk == nil)
		return (nil, "ephemeral key generation failed");

	if(writeall(fd, me, ephpk) < 0)
		return (nil, sys->sprint("handshake write: %r"));
	(peer, peereph, perr) := readpeer(fd);
	if(peer == nil)
		return (nil, perr);

	if(!verify(peer, signer))
		return (nil, "peer certificate does not verify");

	# readpeer returns slices of the message buffer; copy before use.
	pr := array[32] of byte;
	for(i := 0; i < 32; i++)
		pr[i] = peereph[i];
	shared := mono->x25519(ephx, pr);
	if(shared == nil)
		return (nil, "x25519 failed");

	cname: string;
	cpk, ceph: array of byte;
	cname = me.name;
	cpk = me.pk;
	ceph = ephpk;
	sname := peer.name;
	spk := peer.pk;
	seph := peereph;
	if(isserver){
		cname = peer.name;
		cpk = peer.pk;
		ceph = peereph;
		sname = me.name;
		spk = me.pk;
		seph = ephpk;
	}
	(ksend, krecv) := keypair(cname, cpk, ceph, sname, spk, seph, shared, isserver);

	(plainfd, merr) := mkchannel(fd, ksend, krecv);
	if(plainfd == nil)
		return (nil, merr);
	return (plainfd, peer.name);
}

# ---- handshake -------------------------------------------------------

writeall(fd: ref Sys->FD, id: ref Id, ephpk: array of byte): int
{
	msg := array[1 + len id.name + 32 + 64 + 32] of byte;
	msg[0] = byte len id.name;
	put(msg, 1, array of byte id.name);
	put(msg, 1+len id.name, id.pk);
	put(msg, 1+len id.name+32, id.cert);
	put(msg, 1+len id.name+96, ephpk);
	return allwrite(fd, msg);
}

readpeer(fd: ref Sys->FD): (ref Id, array of byte, string)
{
	hdr := array[1] of byte;
	if(allread(fd, hdr) < 0)
		return (nil, nil, "handshake read");
	n := int hdr[0];
	if(n == 0 || n > 64)
		return (nil, nil, "bad name length");
	buf := array[n + 128] of byte;
	if(allread(fd, buf) < 0)
		return (nil, nil, "handshake read");
	id := ref Id;
	id.name = string buf[0:n];
	id.pk = buf[n:n+32];
	id.cert = buf[n+32:n+96];
	eph := buf[n+96:n+128];
	return (id, eph, nil);
}

verify(id: ref Id, signerpk: array of byte): int
{
	signed := cat(cat(array of byte id.name, array of byte "\n"), id.pk);
	return mono->edcheck(id.cert, signerpk, signed) == 1;
}

# Key order is fixed by role, so both sides derive the same material.
keypair(cname: string, cpk: array of byte, ceph: array of byte,
	sname: string, spk: array of byte, seph: array of byte,
	shared: array of byte, isserver: int): (array of byte, array of byte)
{
	t := array[0] of byte;
	t = cat(t, array of byte cname);
	t = cat(t, cpk);
	t = cat(t, ceph);
	t = cat(t, array of byte sname);
	t = cat(t, spk);
	t = cat(t, seph);
	t = cat(t, shared);
	c2s := mono->blake2b(cat(t, array of byte "c2s"), nil, 32);
	s2c := mono->blake2b(cat(t, array of byte "s2c"), nil, 32);
	if(isserver)
		return (s2c, c2s);
	return (c2s, s2c);
}

# ---- records ---------------------------------------------------------

nonce(ctr: int): array of byte
{
	# Limbo does not guarantee a fresh array is zeroed, so clear it.
	n := array[24] of byte;
	for(i := 0; i < 24; i++)
		n[i] = byte 0;
	for(i = 0; i < 8; i++)
		n[23-i] = byte (ctr >> (8*i));
	return n;
}

cryptwrite(fd: ref Sys->FD, key: array of byte, ctr: int, plain: array of byte): int
{
	(ct, tag) := mono->aeadlock(key, nonce(ctr), nil, plain);
	if(ct == nil)
		return -1;
	hdr := array[4] of byte;
	hdr[0] = byte (len ct >> 24);
	hdr[1] = byte (len ct >> 16);
	hdr[2] = byte (len ct >> 8);
	hdr[3] = byte len ct;
	if(allwrite(fd, hdr) < 0 || allwrite(fd, tag) < 0 || allwrite(fd, ct) < 0)
		return -1;
	return 0;
}

cryptread(fd: ref Sys->FD, key: array of byte, ctr: int): array of byte
{
	hdr := array[4] of byte;
	if(allread(fd, hdr) < 0)
		return nil;
	n := (int hdr[0] << 24) | (int hdr[1] << 16) | (int hdr[2] << 8) | int hdr[3];
	if(n < 0 || n > MAXREC)
		return nil;
	tag := array[16] of byte;
	if(allread(fd, tag) < 0)
		return nil;
	ct := array[n] of byte;
	if(n > 0 && allread(fd, ct) < 0)
		return nil;
	return mono->aeadunlock(key, nonce(ctr), tag, nil, ct);
}

# ---- plaintext side --------------------------------------------------

mkchannel(net: ref Sys->FD, ksend, krecv: array of byte): (ref Sys->FD, string)
{
	if(sys->create("/tmp", Sys->OREAD, Sys->DMDIR|8r777) == nil)
		;	# already there
	if(sys->create(CHANDIR, Sys->OREAD, Sys->DMDIR|8r777) == nil && !statok(CHANDIR))
		return (nil, "cannot create " + CHANDIR);
	# file2chan needs a srv(3) directory, not a disk directory.
	if(sys->bind("#s", CHANDIR, Sys->MREPL) < 0)
		return (nil, "cannot bind #s on " + CHANDIR + ": " + sys->sprint("%r"));

	name := string sys->pctl(0, nil) + "." + string counter++;
	io := sys->file2chan(CHANDIR, name);
	if(io == nil)
		return (nil, "file2chan " + CHANDIR + ": " + sys->sprint("%r"));
	fd := sys->open(CHANDIR + "/" + name, Sys->ORDWR);
	if(fd == nil)
		return (nil, "open channel: " + sys->sprint("%r"));

	(inr, inw) := mkpipe();
	(outr, outw) := mkpipe();
	if(inr == nil || outr == nil)
		return (nil, "pipe failed");

	done := chan[2] of int;
	spawn pumpin(net, inw, krecv, done);
	spawn pumpout(net, outr, ksend, done);
	spawn servecrypt(io, inr, outw);
	spawn reap(CHANDIR + "/" + name, done);
	return (fd, nil);
}

# net -> plaintext pipe
pumpin(net: ref Sys->FD, w: ref Sys->FD, key: array of byte, done: chan of int)
{
    {
	ctr := 0;
	for(;;){
		pt := cryptread(net, key, ctr);
		if(pt == nil)
			break;
		ctr++;
		if(sys->write(w, pt, len pt) < 0)
			break;
	}
	w = nil;
	done <-= 1;
    } exception e {
    "*" => sys->print("monoauth: pumpin failed: %s\n", e);
    }
}

# plaintext pipe -> net
pumpout(net: ref Sys->FD, r: ref Sys->FD, key: array of byte, done: chan of int)
{
    {
	ctr := 0;
	buf := array[MAXREC] of byte;
	for(;;){
		n := sys->read(r, buf, len buf);
		if(n <= 0)
			break;
		if(cryptwrite(net, key, ctr, buf[0:n]) < 0)
			break;
		ctr++;
	}
	r = nil;
	done <-= 1;
    } exception e {
    "*" => sys->print("monoauth: pumpout failed: %s\n", e);
    }
}

servecrypt(io: ref Sys->FileIO, r: ref Sys->FD, w: ref Sys->FD)
{
    {
	spawn servewrites(io, w);
	for(;;){
		(off, n, fid, rc) := <-io.read;
		if(rc == nil)		# file closed
			break;
		buf := array[n] of byte;
		m := sys->read(r, buf, n);
		if(m <= 0)
			rc <-= (array[0] of byte, nil);
		else
			rc <-= (buf[0:m], nil);
	}
    } exception e {
    "*" => sys->print("monoauth: servecrypt failed: %s\n", e);
    }
}

servewrites(io: ref Sys->FileIO, w: ref Sys->FD)
{
    {
	for(;;){
		(off, data, fid, wc) := <-io.write;
		if(wc == nil)		# file closed
			break;
		n := sys->write(w, data, len data);
		if(n < 0)
			wc <-= (-1, sys->sprint("%r"));
		else
			wc <-= (n, nil);
	}
    } exception e {
    "*" => sys->print("monoauth: servewrites failed: %s\n", e);
    }
}

reap(path: string, done: chan of int)
{
    {
	<-done;
	<-done;
	sys->remove(path);
    } exception e {
    "*" => sys->print("monoauth: reap failed: %s\n", e);
    }
}

# ---- identity files --------------------------------------------------

loadid(keyfile: string): (ref Id, string)
{
	data := readfile(keyfile);
	if(data == "")
		return (nil, "cannot read " + keyfile);
	id := ref Id;
	for(s := data; len s > 0;){
		(line, rest) := splitline(s);
		s = rest;
		(f, v) := splitfield(line);
		case f {
		"name" => id.name = v;
		"sk" => id.sk = hex2bytes(v);
		"cert" => id.cert = hex2bytes(v);
		}
	}
	if(id.name == "" || id.sk == nil || len id.sk != 64 || id.cert == nil || len id.cert != 64)
		return (nil, keyfile + ": needs name, sk (64 bytes) and cert (64 bytes)");
	id.pk = id.sk[32:64];
	return (id, nil);
}

loadsigner(): (array of byte, string)
{
	data := readfile(SIGNER);
	if(data == "")
		return (nil, "cannot read " + SIGNER);
	sk: array of byte;
	for(s := data; len s > 0;){
		(line, rest) := splitline(s);
		s = rest;
		(f, v) := splitfield(line);
		if(f == "sk")
			sk = hex2bytes(v);
	}
	if(sk == nil || len sk != 64)
		return (nil, SIGNER + ": needs a 64-byte sk");
	return (sk[32:64], nil);
}

# ---- utilities -------------------------------------------------------

hex(a: array of byte): string
{
	s := "";
	for(i := 0; i < len a; i++)
		s += sys->sprint("%.2x", int a[i]);
	return s;
}

readrandom(n: int): array of byte
{
	fd := sys->open("/dev/random", Sys->OREAD);
	if(fd == nil)
		return nil;
	buf := array[n] of byte;
	if(sys->readn(fd, buf, n) != n)
		return nil;
	return buf;
}

mkpipe(): (ref Sys->FD, ref Sys->FD)
{
	fds := array[2] of ref Sys->FD;
	if(sys->pipe(fds) < 0)
		return (nil, nil);
	return (fds[0], fds[1]);
}

allwrite(fd: ref Sys->FD, buf: array of byte): int
{
	for(off := 0; off < len buf;){
		n := sys->write(fd, buf[off:], len buf - off);
		if(n <= 0)
			return -1;
		off += n;
	}
	return 0;
}

allread(fd: ref Sys->FD, buf: array of byte): int
{
	if(sys->readn(fd, buf, len buf) != len buf)
		return -1;
	return 0;
}

put(a: array of byte, off: int, b: array of byte)
{
	for(i := 0; i < len b; i++)
		a[off+i] = b[i];
}

cat(a, b: array of byte): array of byte
{
	c := array[len a + len b] of byte;
	put(c, 0, a);
	put(c, len a, b);
	return c;
}

statok(path: string): int
{
	(ok, nil) := sys->stat(path);
	return ok >= 0;
}

readfile(path: string): string
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return "";
	buf := array[8192] of byte;
	n := sys->read(fd, buf, len buf);
	fd = nil;
	if(n <= 0)
		return "";
	return string buf[0:n];
}

splitline(s: string): (string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] == '\n')
			return (s[0:i], s[i+1:]);
	return (s, "");
}

# splitfield returns the first word and the trimmed remainder.
splitfield(s: string): (string, string)
{
	i := 0;
	while(i < len s && s[i] != ' ' && s[i] != '\t')
		i++;
	key := s[0:i];
	while(i < len s && (s[i] == ' ' || s[i] == '\t'))
		i++;
	val := s[i:];
	while(len val > 0 && (val[len val-1] == '\r' || val[len val-1] == ' '))
		val = val[0:len val-1];
	return (key, val);
}

hexval(c: int): int
{
	if(c >= '0' && c <= '9')
		return c - '0';
	if(c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if(c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return 0;
}

hex2bytes(s: string): array of byte
{
	a := array[len s / 2] of byte;
	for(i := 0; i < len a; i++)
		a[i] = byte ((hexval(s[2*i]) << 4) | hexval(s[2*i+1]));
	return a;
}

counter := 0;
