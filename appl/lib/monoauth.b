implement Monoauth;

#
# monoauth -- mutual authentication and an encrypted stream with $Mono
#
# Both sides hold an EdDSA key pair, a certificate from the machine's
# signer (/keydb/mono-signer) and, normally, an epoch proof from monoca:
# a Merkle root over the authorised name/key/expiry triples, signed by
# the same signer.  The exchange is:
#
#	client hello, server hello + signature, client signature
#
# A hello carries the identity (name, key, certificate), the ephemeral
# X25519 key, the scope (domain and path) and, when available, an
# inclusion proof.  Each certificate signs name || "\n" || pk, so the
# name is bound to the key.  The hellos are hashed into a transcript;
# the server signs it, the client verifies and signs it back, so a relay
# cannot splice one hello into another session.  The X25519 shared
# secret plus the transcript derives one key per direction; BLAKE2b
# expands them and XChaCha20-Poly1305 protects each record, with a
# per-direction counter as the nonce.
#
# The scope is enforced on both sides: domain and path must match, so a
# server and client only talk when provisioned for the same capability.
# A peer that presents no proof is accepted only under box/, and a local
# identity outside box/ refuses to start without one.  A missing,
# unverifiable or stale epoch therefore fails closed to box/.
#
# Records are: 4-byte length, 16-byte tag, ciphertext.  The plaintext
# side is a file2chan stream, because callers (rcmd, cpu, listen) need
# one fd they can both read and write, and may hand it to export(2).
#
# Identity file (/usr/<name>/keyring/mono):
#
#	name <name>
#	domain <authentication domain>	(default mono)
#	path <capability path>		(default box/default)
#	sk <64 bytes, hex>
#	cert <64 bytes, hex>
#
# Verifiers read the signer's public key from /keydb/mono-signer.pub and
# never need the secret, which lives only on the issuing host.
#

include "sys.m";
	sys: Sys;

include "draw.m";

include "mono.m";
	mono: Mono;

include "dial.m";
	dial: Dial;

include "merkle.m";
	mk: Merkle;

include "daytime.m";
	daytime: Daytime;

include "monosigner.m";
	sgn: Monosigner;

include "monoauth.m";

SIGNER:		con "/keydb/mono-signer";
CHANDIR:	con "/tmp/mono";
MAXREC:		con 4096;

Id: adt
{
	name:	string;
	domain:	string;
	path:	string;
	sk:	array of byte;
	pk:	array of byte;
	cert:	array of byte;
};

Proof: adt
{
	have:	int;
	exp:	int;
	n:	int;
	t:	int;
	w:	int;
	root:	array of byte;
	esig:	array of byte;
	leaf:	array of byte;
	index:	int;
	path:	list of array of byte;
};

Hello: adt
{
	name:	string;
	pk:	array of byte;
	cert:	array of byte;
	eph:	array of byte;
	domain:	string;
	path:	string;
	p:	ref Proof;
};

Rd: adt
{
	d:	array of byte;
	n:	int;
	o:	int;
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

VERSION:	con 2;
MONOCA:		con "/keydb/monoca";

# A hello is length-prefixed on the wire.  The server signs the
# transcript of both hellos and the client signs it back, binding the
# session to both identities, the scope and the epoch proof.
buildhello(id: ref Id, p: ref Proof, eph: array of byte): array of byte
{
	b := array[4096] of byte;
	o := 0;
	o = ab(b, o, VERSION);
	o = astr(b, o, id.name);
	o = abytes(b, o, id.pk);
	o = abytes(b, o, id.cert);
	o = abytes(b, o, eph);
	o = astr(b, o, id.domain);
	o = astr(b, o, id.path);
	o = ab(b, o, p.have);
	if(p.have == 1){
		o = a8(b, o, p.exp);
		o = a8(b, o, p.n);
		o = a8(b, o, p.t);
		o = a8(b, o, p.w);
		o = abytes(b, o, p.root);
		o = abytes(b, o, p.esig);
		o = abytes(b, o, p.leaf);
		o = a8(b, o, p.index);
		o = ab(b, o, count(p.path));
		for(l := p.path; l != nil; l = tl l){
			h := hd l;
			if(h == nil)
				o = ab(b, o, 0);
			else{
				o = ab(b, o, 1);
				o = abytes(b, o, h);
			}
		}
	}
	return b[0:o];
}

parsehello(b: array of byte): (ref Hello, string)
{
	r := ref Rd(b, len b, 0);
	if(rd8(r) != VERSION)
		return (nil, "mono: bad handshake version");
	h := ref Hello;
	h.p = ref Proof;
	h.p.have = 0;
	h.p.exp = 0;
	h.p.n = 0;
	h.p.t = 0;
	h.p.w = 0;
	h.p.root = nil;
	h.p.esig = nil;
	h.p.leaf = nil;
	h.p.index = 0;
	h.p.path = nil;
	n := rd8(r);
	if(n <= 0 || n > 64)
		return (nil, "mono: bad name");
	a := rdbytes(r, n);
	if(a == nil)
		return (nil, "mono: short name");
	h.name = string a;
	h.pk = rdbytes(r, 32);
	h.cert = rdbytes(r, 64);
	h.eph = rdbytes(r, 32);
	if(h.pk == nil || h.cert == nil || h.eph == nil)
		return (nil, "mono: short identity");
	n = rd8(r);
	if(n <= 0 || n > 64)
		return (nil, "mono: bad domain");
	a = rdbytes(r, n);
	if(a == nil)
		return (nil, "mono: short domain");
	h.domain = string a;
	n = rd8(r);
	if(n <= 0 || n > 128)
		return (nil, "mono: bad path");
	a = rdbytes(r, n);
	if(a == nil)
		return (nil, "mono: short path");
	h.path = string a;
	have := rd8(r);
	if(have < 0 || have > 1)
		return (nil, "mono: bad proof flag");
	h.p.have = have;
	if(have == 1){
		h.p.exp = r8(r);
		h.p.n = r8(r);
		h.p.t = r8(r);
		h.p.w = r8(r);
		h.p.root = rdbytes(r, 32);
		h.p.esig = rdbytes(r, 64);
		h.p.leaf = rdbytes(r, 32);
		h.p.index = r8(r);
		if(h.p.root == nil || h.p.esig == nil || h.p.leaf == nil)
			return (nil, "mono: short proof");
		np := rd8(r);
		if(np < 0 || np > 32)
			return (nil, "mono: bad path length");
		pl: list of array of byte;
		for(i := 0; i < np; i++){
			present := rd8(r);
			if(present == 1){
				q := rdbytes(r, 32);
				if(q == nil)
					return (nil, "mono: short inclusion path");
				pl = q :: pl;
			}else if(present == 0)
				pl = nil :: pl;
			else
				return (nil, "mono: bad inclusion path");
		}
		h.p.path = reverse(pl);
	}
	return (h, nil);
}

epochmsg(n, t, w: int, root: array of byte): array of byte
{
	b := array[8+8+8+32] of byte;
	a8(b, 0, n);
	a8(b, 8, t);
	a8(b, 16, w);
	for(i := 0; i < 32; i++)
		b[24+i] = root[i];
	return cat(array of byte "epoch1", b);
}

parseepoch(s: string): (int, int, int, array of byte, array of byte)
{
	n := 0;
	t := 0;
	w := 0;
	root: array of byte;
	sig: array of byte;
	for(; len s > 0;){
		(line, rest) := splitline(s);
		s = rest;
		(f, v) := splitfield(line);
		case f {
		"epoch" => n = int v;
		"time" => t = int v;
		"window" => w = int v;
		"root" => root = hex2bytes(v);
		"sig" => sig = hex2bytes(v);
		}
	}
	return (n, t, w, root, sig);
}

# loadproof builds an inclusion proof for this identity from the local
# CA state.  A missing or stale epoch, an unenrolled key or a bad proof
# leaves have=0, which restricts the identity to a box/ path.
loadproof(id: ref Id, signers: list of array of byte): ref Proof
{
	p := ref Proof;
	p.have = 0;
	p.exp = 0;
	p.n = 0;
	p.t = 0;
	p.w = 0;
	p.root = nil;
	p.esig = nil;
	p.leaf = nil;
	p.index = 0;
	p.path = nil;
	ep := readfile(MONOCA + "/epoch");
	if(ep == ""){
		return p;
	}
	(n, t, w, root, esig) := parseepoch(ep);
	if(root == nil || len root != 32 || esig == nil || len esig != 64){
		return p;
	}
	now := daytime->now();
	if(now < t || now > t + w){
		return p;
	}
	if(!certok(esig, signers, epochmsg(n, t, w, root))){
		return p;
	}
	ls := readfile(MONOCA + "/leaves");
	leaves: list of array of byte;
	myleaf: array of byte;
	myexp := 0;
	for(; len ls > 0;){
		(line, rest) := splitline(ls);
		ls = rest;
		(name, pkhex, exps) := split3(line);
		if(name == "")
			continue;
		pk := hex2bytes(pkhex);
		if(len pk != 32)
			continue;
		e := int exps;
		h := mk->leaf(name, pk, e);
		if(h == nil)
			continue;
		leaves = h :: leaves;
		if(name == id.name && mono->equal(pk, id.pk)){
			myleaf = h;
			myexp = e;
		}
	}
	if(myleaf == nil){
		return p;
	}
	if(myexp != 0 && myexp < now){
		return p;
	}
	sorted := sortleaves(leaves);
	idx := leafindex(sorted, myleaf);
	if(idx < 0){
		return p;
	}
	path := mk->path(sorted, idx);
	if(mk->verify(myleaf, path, idx, root) != 1){
		return p;
	}
	p.have = 1;
	p.exp = myexp;
	p.n = n;
	p.t = t;
	p.w = w;
	p.root = root;
	p.esig = esig;
	p.leaf = myleaf;
	p.index = idx;
	p.path = path;
	return p;
}

checkcommon(h: ref Hello, my: ref Id, signers: list of array of byte, now: int): string
{
	signed := cat(cat(array of byte h.name, array of byte "\n"), h.pk);
	if(!certok(h.cert, signers, signed))
		return "mono: peer certificate does not verify";
	if(h.domain != my.domain || h.path != my.path)
		return "mono: scope mismatch";
	if(h.p.have){
		if(h.p.exp != 0 && h.p.exp < now)
			return "mono: identity has expired";
		if(!certok(h.p.esig, signers,
		   epochmsg(h.p.n, h.p.t, h.p.w, h.p.root)))
			return "mono: epoch signature does not verify";
		if(now < h.p.t || now > h.p.t + h.p.w)
			return "mono: epoch is stale";
		leaf := mk->leaf(h.name, h.pk, h.p.exp);
		if(leaf == nil || mono->equal(leaf, h.p.leaf) != 1)
			return "mono: leaf does not match the identity";
		if(mk->verify(h.p.leaf, h.p.path, h.p.index, h.p.root) != 1)
			return "mono: inclusion proof does not verify";
	}else if(!hasprefix(h.path, "box/"))
		return "mono: no epoch proof outside box/";
	return nil;
}

# certok accepts a signature from any currently trusted signer key, so a
# rotation can add the new key before the old one stops being used.
certok(sig: array of byte, signers: list of array of byte, msg: array of byte): int
{
	for(; signers != nil; signers = tl signers)
		if(mono->edcheck(sig, hd signers, msg) == 1)
			return 1;
	return 0;
}

hashhello(c, s: array of byte): array of byte
{
	return mono->blake2b(cat(cat(array of byte "mono2hello", c), s), nil, 32);
}

signmsg(t: array of byte): array of byte
{
	return cat(array of byte "mono2sig", t);
}

# Both sides derive the same keys from the X25519 secret and the hello
# transcript; the role labels keep the two directions independent.
keypair(shared, bind: array of byte, isserver: int): (array of byte, array of byte)
{
	b := cat(shared, bind);
	c2s := mono->blake2b(cat(b, array of byte "c2s"), nil, 32);
	s2c := mono->blake2b(cat(b, array of byte "s2c"), nil, 32);
	if(isserver)
		return (s2c, c2s);
	return (c2s, s2c);
}

# ---- hello encoding --------------------------------------------------

ab(b: array of byte, o: int, v: int): int
{
	if(o < len b){
		b[o] = byte (v & 16rff);
		o++;
	}
	return o;
}

abytes(b: array of byte, o: int, a: array of byte): int
{
	for(i := 0; i < len a && o < len b; i++){
		b[o] = a[i];
		o++;
	}
	return o;
}

astr(b: array of byte, o: int, s: string): int
{
	if(len s > 255)
		s = s[0:255];
	o = ab(b, o, len s);
	for(i := 0; i < len s && o < len b; i++){
		b[o] = byte s[i];
		o++;
	}
	return o;
}

a8(b: array of byte, o: int, v: int): int
{
	if(o + 8 > len b)
		return o;
	b[o] = byte 0;
	b[o+1] = byte 0;
	b[o+2] = byte 0;
	b[o+3] = byte 0;
	b[o+4] = byte ((v >> 24) & 16rff);
	b[o+5] = byte ((v >> 16) & 16rff);
	b[o+6] = byte ((v >> 8) & 16rff);
	b[o+7] = byte (v & 16rff);
	return o + 8;
}

r8(r: ref Rd): int
{
	v := 0;
	for(i := 0; i < 8; i++){
		c := rd8(r);
		if(c < 0)
			return 0;
		if(i >= 4)
			v = (v << 8) | c;
	}
	return v;
}

rd8(r: ref Rd): int
{
	if(r.o >= r.n)
		return -1;
	v := int r.d[r.o];
	r.o++;
	return v;
}

rdbytes(r: ref Rd, n: int): array of byte
{
	if(n < 0 || r.o + n > r.n)
		return nil;
	a := r.d[r.o:r.o+n];
	r.o += n;
	return a;
}

count(l: list of array of byte): int
{
	n := 0;
	for(; l != nil; l = tl l)
		n++;
	return n;
}

reverse(l: list of array of byte): list of array of byte
{
	r: list of array of byte;
	for(; l != nil; l = tl l)
		r = hd l :: r;
	return r;
}

hasprefix(s, p: string): int
{
	if(len s < len p)
		return 0;
	return s[0:len p] == p;
}

bytescmp(a, b: array of byte): int
{
	n := len a;
	if(len b < n)
		n = len b;
	for(i := 0; i < n; i++){
		if(a[i] < b[i])
			return -1;
		if(a[i] > b[i])
			return 1;
	}
	if(len a < len b)
		return -1;
	if(len a > len b)
		return 1;
	return 0;
}

insertleaf(s: list of array of byte, h: array of byte): list of array of byte
{
	if(s == nil)
		return h :: nil;
	if(bytescmp(h, hd s) < 0)
		return h :: s;
	return hd s :: insertleaf(tl s, h);
}

sortleaves(l: list of array of byte): list of array of byte
{
	s: list of array of byte;
	for(; l != nil; l = tl l)
		s = insertleaf(s, hd l);
	return s;
}

leafindex(l: list of array of byte, h: array of byte): int
{
	i := 0;
	for(; l != nil; l = tl l){
		if(mono->equal(hd l, h))
			return i;
		i++;
	}
	return -1;
}

split3(s: string): (string, string, string)
{
	w0, w1, w2: string;
	i := 0;
	k := 0;
	while(k < 3){
		while(i < len s && (s[i] == ' ' || s[i] == '\t'))
			i++;
		j := i;
		while(j < len s && s[j] != ' ' && s[j] != '\t')
			j++;
		if(i == j)
			break;
		if(k == 0)
			w0 = s[i:j];
		else if(k == 1)
			w1 = s[i:j];
		else
			w2 = s[i:j];
		k++;
		i = j;
	}
	if(k < 3)
		return ("", "", "");
	return (w0, w1, w2);
}

# ---- handshake messages ----------------------------------------------

write4(fd: ref Sys->FD, b: array of byte): int
{
	h := array[4] of byte;
	h[0] = byte (len b >> 24);
	h[1] = byte (len b >> 16);
	h[2] = byte (len b >> 8);
	h[3] = byte len b;
	if(allwrite(fd, h) < 0)
		return -1;
	return allwrite(fd, b);
}

read4(fd: ref Sys->FD): array of byte
{
	h := array[4] of byte;
	if(allread(fd, h) < 0)
		return nil;
	n := (int h[0] << 24) | (int h[1] << 16) | (int h[2] << 8) | int h[3];
	if(n <= 0 || n > 8192)
		return nil;
	b := array[n] of byte;
	if(allread(fd, b) < 0)
		return nil;
	return b;
}

write64(fd: ref Sys->FD, b: array of byte): int
{
	if(len b != 64)
		return -1;
	return allwrite(fd, b);
}

read64(fd: ref Sys->FD): array of byte
{
	b := array[64] of byte;
	if(allread(fd, b) < 0)
		return nil;
	return b;
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
	mk = load Merkle Merkle->PATH;
	daytime = load Daytime Daytime->PATH;
	sgn = load Monosigner Monosigner->PATH;
	if(mk == nil || daytime == nil || sgn == nil)
		return (nil, "cannot load merkle, daytime or monosigner");

	(me, err) := loadid(keyfile);
	if(me == nil)
		return (nil, err);
	(signers, serr) := sgn->pubs(SIGNER);
	if(signers == nil)
		return (nil, serr);

	p := loadproof(me, signers);
	if(!p.have && !hasprefix(me.path, "box/"))
		return (nil, "mono: no epoch proof for " + me.path);

	ephx := readrandom(32);
	if(ephx == nil)
		return (nil, "cannot read /dev/notquiterandom");
	ephpk := mono->xpublic(ephx);
	if(ephpk == nil)
		return (nil, "ephemeral key generation failed");

	peer: ref Hello;
	t: array of byte;
	e: string;
	if(!isserver){
		cb := buildhello(me, p, ephpk);
		if(write4(fd, cb) < 0)
			return (nil, sys->sprint("handshake write: %r"));
		sb := read4(fd);
		if(sb == nil)
			return (nil, "handshake read");
		sh: ref Hello;
		(sh, e) = parsehello(sb);
		if(sh == nil)
			return (nil, e);
		t = hashhello(cb, sb);
		ssig := read64(fd);
		if(ssig == nil)
			return (nil, "handshake signature read");
		e = checkcommon(sh, me, signers, daytime->now());
		if(e != nil)
			return (nil, e);
		if(mono->edcheck(ssig, sh.pk, signmsg(t)) != 1)
			return (nil, "mono: server transcript signature does not verify");
		csig := mono->edsign(me.sk, signmsg(t));
		if(csig == nil)
			return (nil, "mono: signing failed");
		if(write64(fd, csig) < 0)
			return (nil, sys->sprint("handshake signature write: %r"));
		peer = sh;
	}else{
		cb := read4(fd);
		if(cb == nil)
			return (nil, "handshake read");
		ch: ref Hello;
		(ch, e) = parsehello(cb);
		if(ch == nil)
			return (nil, e);
		e = checkcommon(ch, me, signers, daytime->now());
		if(e != nil)
			return (nil, e);
		sb := buildhello(me, p, ephpk);
		t = hashhello(cb, sb);
		ssig := mono->edsign(me.sk, signmsg(t));
		if(ssig == nil)
			return (nil, "mono: signing failed");
		if(write4(fd, sb) < 0 || write64(fd, ssig) < 0)
			return (nil, sys->sprint("handshake write: %r"));
		csig := read64(fd);
		if(csig == nil)
			return (nil, "handshake signature read");
		if(mono->edcheck(csig, ch.pk, signmsg(t)) != 1)
			return (nil, "mono: client transcript signature does not verify");
		peer = ch;
	}

	shared := mono->x25519(ephx, peer.eph);
	if(shared == nil)
		return (nil, "x25519 failed");

	(ksend, krecv) := keypair(shared, t, isserver);

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

# hangup sends a reset, so the peer of fd (here, the caller's session
# socket) sees an error rather than waiting forever for EOF.
hangup(fd: ref Sys->FD)
{
	if(fd == nil)
		return;
	path := sys->fd2path(fd);
	if(path == nil)
		return;
	# /net/tcp/N/data -> /net/tcp/N/ctl
	i := len path - 1;
	while(i > 0 && path[i] != '/')
		i--;
	if(i <= 0)
		return;
	ctl := sys->open(path[0:i] + "/ctl", Sys->OWRITE);
	if(ctl == nil)
		return;
	sys->fprint(ctl, "hangup");
	ctl = nil;
}

linkclose(l: ref Link, tag: int)
{
	s := find(l, tag);
	if(s == nil)
		return;
	hangup(s.fd);
	s.fd = nil;
	l.send <-= (tag, FIN, array[0] of byte);
	l.sessions = remove(l.sessions, s);
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
				hangup(s.fd);
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
		"domain" => id.domain = v;
		"path" => id.path = v;
		"sk" => id.sk = hex2bytes(v);
		"cert" => id.cert = hex2bytes(v);
		}
	}
	if(id.name == "" || id.sk == nil || len id.sk != 64 || id.cert == nil || len id.cert != 64)
		return (nil, keyfile + ": needs name, sk (64 bytes) and cert (64 bytes)");
	id.pk = id.sk[32:64];
	if(id.domain == "")
		id.domain = "mono";
	if(id.path == "")
		id.path = "box/default";
	return (id, nil);
}

# ---- utilities -------------------------------------------------------

hex(a: array of byte): string
{
	s := "";
	for(i := 0; i < len a; i++)
		s += sys->sprint("%.2x", int a[i]);
	return s;
}

# Ephemeral keys only: /dev/random accumulates about one byte per 50 ms,
# so it is too slow for a handshake.  The fast generator is seeded from
# it once, by init or by the first user.
readrandom(n: int): array of byte
{
	fd := sys->open("/dev/notquiterandom", Sys->OREAD);
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
