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

include "dial.m";
	dial: Dial;

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
	(l, err) := link(keyfile, fd, 1);
	if(l == nil)
		return (nil, err);
	(nil, sfd) := linkaccept(l);
	return (sfd, l.name);
}

client(keyfile: string, fd: ref Sys->FD): (ref Sys->FD, string)
{
	(l, err) := link(keyfile, fd, 0);
	if(l == nil)
		return (nil, err);
	return (linkopen(l, 1), l.name);
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

OPEN:	con 1;
DATA:	con 2;
FIN:	con 3;

# A record's plaintext is: session(4) | type(1) | data.
frame(sess, typ: int, data: array of byte): array of byte
{
	f := array[5 + len data] of byte;
	f[0] = byte (sess >> 24);
	f[1] = byte (sess >> 16);
	f[2] = byte (sess >> 8);
	f[3] = byte sess;
	f[4] = byte typ;
	for(i := 0; i < len data; i++)
		f[5+i] = data[i];
	return f;
}

cryptwrite(fd: ref Sys->FD, key: array of byte, ctr: int, sess, typ: int, data: array of byte): int
{
	(ct, tag) := mono->aeadlock(key, nonce(ctr), nil, frame(sess, typ, data));
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

cryptread(fd: ref Sys->FD, key: array of byte, ctr: int): (int, int, array of byte)
{
	hdr := array[4] of byte;
	if(allread(fd, hdr) < 0)
		return (0, 0, nil);
	n := (int hdr[0] << 24) | (int hdr[1] << 16) | (int hdr[2] << 8) | int hdr[3];
	if(n < 5 || n > MAXREC)
		return (0, 0, nil);
	tag := array[16] of byte;
	if(allread(fd, tag) < 0)
		return (0, 0, nil);
	ct := array[n] of byte;
	if(allread(fd, ct) < 0)
		return (0, 0, nil);
	pt := mono->aeadunlock(key, nonce(ctr), tag, nil, ct);
	if(pt == nil || len pt < 5)
		return (0, 0, nil);
	sess := (int pt[0] << 24) | (int pt[1] << 16) | (int pt[2] << 8) | int pt[3];
	return (sess, int pt[4], pt[5:]);
}

# ---- plaintext side --------------------------------------------------

# link authenticates and returns a multiplexed connection.  Each frame
# carries a session tag; OPEN creates a session, DATA carries bytes and
# FIN closes it.  One writer proc serialises frames so tags cannot
# interleave inside a record.
link(keyfile: string, fd: ref Sys->FD, isserver: int): (ref Link, string)
{
	sys = load Sys Sys->PATH;
	mono = load Mono Mono->PATH;
	if(mono == nil)
		return (nil, "cannot load " + Mono->PATH);
	dial = load Dial Dial->PATH;
	if(dial == nil)
		return (nil, "cannot load " + Dial->PATH);

	(me, err) := loadid(keyfile);
	if(me == nil)
		return (nil, err);
	(signer, serr) := loadsigner();
	if(signer == nil)
		return (nil, serr);

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

	l := ref Link;
	l.name = peer.name;
	l.net = fd;
	l.send = chan[64] of (int, int, array of byte);
	l.news = chan[16] of (int, ref Sys->FD);
	l.sessions = nil;
	spawn linkwrite(l, ksend);
	spawn linkread(l, krecv);
	return (l, nil);
}

linkaccept(l: ref Link): (int, ref Sys->FD)
{
	(tag, fd) := <-l.news;
	return (tag, fd);
}

linkopen(l: ref Link, tag: int): ref Sys->FD
{
	(s, cli) := mksession(l, tag);
	l.sessions = s :: l.sessions;
	l.send <-= (tag, OPEN, array[0] of byte);
	return cli;
}

linkwrite(l: ref Link, key: array of byte)
{
	ctr := 0;
	for(;;){
		(tag, typ, data) := <-l.send;
		if(cryptwrite(l.net, key, ctr, tag, typ, data) < 0)
			break;
		ctr++;
	}
}

linkread(l: ref Link, key: array of byte)
{
	ctr := 0;
	for(;;){
		(tag, typ, data) := cryptread(l.net, key, ctr);
		if(typ != OPEN && typ != DATA && typ != FIN)
			break;
		ctr++;
		case typ {
		OPEN =>
			(s, cli) := mksession(l, tag);
			l.sessions = s :: l.sessions;
			l.news <-= (tag, cli);
		DATA =>
			s := find(l, tag);
			if(s != nil && s.fd != nil)
				sys->write(s.fd, data, len data);
		FIN =>
			s := find(l, tag);
			if(s != nil){
				s.fd = nil;
				l.sessions = remove(l.sessions, s);
			}
		}
	}
}

mksession(l: ref Link, tag: int): (ref Sess, ref Sys->FD)
{
	(c, cli) := socketpair();
	if(c == nil)
		return (nil, nil);
	s := ref Sess;
	s.tag = tag;
	s.fd = c;
	spawn sessionout(l, s);
	return (s, cli);
}

# plaintext -> link
sessionout(l: ref Link, s: ref Sess)
{
    {
	buf := array[MAXREC] of byte;
	n := 0;
	for(;;){
		if(s.fd == nil)
			break;
		n = sys->read(s.fd, buf, len buf);
		if(n <= 0)
			break;
		l.send <-= (s.tag, DATA, buf[0:n]);
	}
	if(n == 0)
		l.send <-= (s.tag, FIN, array[0] of byte);
	s.fd = nil;
    } exception e {
    "*" => sys->print("monoauth: session failed: %s\n", e);
    }
}

find(l: ref Link, tag: int): ref Sess
{
	for(sl := l.sessions; sl != nil; sl = tl sl)
		if((hd sl).tag == tag)
			return hd sl;
	return nil;
}

remove(l: list of ref Sess, s: ref Sess): list of ref Sess
{
	r: list of ref Sess;
	for(; l != nil; l = tl l)
		if(hd l != s)
			r = hd l :: r;
	return r;
}

# A loopback socket pair gives one bidirectional fd per session, which
# mount(2) and export(2) accept.
socketpair(): (ref Sys->FD, ref Sys->FD)
{
	c := dial->announce("tcp!127.0.0.1!0");
	if(c == nil)
		return (nil, nil);
	addr := localaddr(c);
	if(addr == nil)
		return (nil, nil);
	cli := dial->dial("tcp!" + addr, nil);
	if(cli == nil)
		return (nil, nil);
	srv := dial->listen(c);
	if(srv == nil)
		return (nil, nil);
	sfd := dial->accept(srv);
	if(sfd == nil)
		return (nil, nil);
	return (sfd, cli.dfd);
}

localaddr(c: ref Dial->Connection): string
{
	fd := sys->open(c.dir + "/local", Sys->OREAD);
	if(fd == nil)
		return nil;
	buf := array[64] of byte;
	n := sys->read(fd, buf, len buf);
	if(n <= 0)
		return nil;
	s := string buf[0:n];
	while(len s > 0 && (s[len s-1] == '\n' || s[len s-1] == ' '))
		s = s[0:len s-1];
	return s;
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
