#
#  tlsget -- fetch one Gemini URL over TLS 1.3, with the handshake in Dis.
#
#  This is the client counterpart of gemserve's 1.3 path: the same
#  record layer and key schedule, reversed.  It uses $TLS for AES-GCM
#  and signature verification, $Mono for X25519 and $Crypt for SHA-256,
#  so it runs on the kernel and on the hosted emulator.
#
implement Tlsget;

include "sys.m";
	sys: Sys;
include "draw.m";
include "dial.m";
	dial: Dial;
include "ipints.m";
include "crypt.m";
	crypt: Crypt;
include "mono.m";
	mono: Mono;
include "tls.m";
	tls: TLS;

Tlsget: module
{
	init:	fn(nil: ref Draw->Context, args: list of string);
};

CONN:	con "tcp!";
MAXREC:	con 16384;

Rd: adt
{
	d:	array of byte;
	n:	int;
	o:	int;
};

Bo: adt
{
	d:	array of byte;
	n:	int;
};

Conn: adt
{
	fd:	ref Sys->FD;
	host:	string;
	fp:	string;			# leaf certificate fingerprint
	srvseq:	int;
	cliseq:	int;
	cakk:	array of byte;
	caiv:	array of byte;
	sakk:	array of byte;
	saiv:	array of byte;
};

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	dial = load Dial Dial->PATH;
	crypt = load Crypt Crypt->PATH;
	mono = load Mono Mono->PATH;
	tls = load TLS TLS->PATH;
	if(crypt == nil || mono == nil || tls == nil){
		sys->print("tlsget: module missing\n");
		return;
	}
	args = tl args;
	if(args == nil){
		sys->print("usage: tlsget host[!port] [urlpath [servername]]\n");
		return;
	}
	addr := hd args;
	args = tl args;
	path := "/";
	if(args != nil){
		path = hd args;
		args = tl args;
	}
	host := "";
	if(args != nil)
		host = hd args;
	if(host == ""){
		host = addr;
		for(i := 0; i < len addr; i++)
			if(addr[i] == '!'){
				host = addr[0:i];
				break;
			}
	}
	c := dial->dial(CONN + addr, nil);
	if(c == nil){
		sys->print("tlsget: dial %s: %r\n", CONN + addr);
		return;
	}
	fd := sys->open(c.dir + "/data", Sys->ORDWR);
	if(fd == nil){
		sys->print("tlsget: open data: %r\n");
		return;
	}
	conn := ref Conn(fd, host, "", 0, 0, nil, nil, nil, nil);
	e := handshake(conn);
	if(e != nil){
		sys->print("tlsget: %s\n", e);
		return;
	}
	sys->print("tlsget: cert sha256 %s\n", conn.fp);

	req := "gemini://" + host + path + "\r\n";
	e = writeapp(conn, array of byte req);
	if(e != nil){
		sys->print("tlsget: write: %s\n", e);
		return;
	}
	b: array of byte;
	for(;;){
		(b, e) = readapp(conn);
		if(e != nil){
			if(e != "eof")
				sys->print("tlsget: read: %s\n", e);
			break;
		}
		if(len b == 0)
			break;
		sys->write(sys->fildes(1), b, len b);
	}
}

# ---- handshake --------------------------------------------------------

handshake(c: ref Conn): string
{
	# ---- ClientHello ----
	sk := randombytes(32);
	if(sk == nil)
		return "no random";
	spub := mono->xpublic(sk);
	if(spub == nil)
		return "x25519 key";
	sess := randombytes(32);
	if(sess == nil)
		return "no random";

	chb := ref Bo(array[1024] of byte, 0);
	b16(chb, 16r0303);
	bpa(chb, randombytes(32));
	bp(chb, len sess);
	bpa(chb, sess);
	b16(chb, 2);
	b16(chb, 16r1301);
	bp(chb, 1);
	bp(chb, 0);

	ext := ref Bo(array[512] of byte, 0);
	# server_name
	sn := ref Bo(array[256] of byte, 0);
	bp(sn, 0);
	b16(sn, len c.host);
	for(i := 0; i < len c.host; i++)
		bp(sn, c.host[i]);
	b16(ext, 0);
	b16(ext, sn.n + 2);
	b16(ext, sn.n);
	bpa(ext, sn.d[0:sn.n]);
	# supported_groups
	b16(ext, 10); b16(ext, 4); b16(ext, 2); b16(ext, 29);
	# signature_algorithms
	b16(ext, 13); b16(ext, 4); b16(ext, 2); b16(ext, 16r0403);
	# supported_versions
	b16(ext, 43); b16(ext, 3); bp(ext, 2); b16(ext, 16r0304);
	# key_share
	ks := ref Bo(array[128] of byte, 0);
	b16(ks, 36); b16(ks, 29); b16(ks, 32); bpa(ks, spub);
	b16(ext, 51); b16(ext, ks.n); bpa(ext, ks.d[0:ks.n]);
	b16(chb, ext.n);
	bpa(chb, ext.d[0:ext.n]);

	ch := hsmsg(1, chb.d[0:chb.n]);
	tr := array[65536] of byte;
	trn := tapp(tr, 0, ch);
	rec := hsrec(ch);
	if(writeall(c.fd, rec) < 0)
		return "write ClientHello";

	# ---- ServerHello ----
	(typ, data, e) := readrecord(c.fd);
	if(e != nil)
		return e;
	if(typ != 22)
		return "expected ServerHello, got record " + string typ;
	r := ref Rd(data, len data, 0);
	if(rd8(r) != 2)
		return "not a ServerHello";
	ln := rd24(r);
	body := rdbytes(r, ln);
	if(body == nil)
		return "short ServerHello";
	sh := hsmsg(2, body);
	trn = tapp(tr, trn, sh);

	shp := ref Rd(body, len body, 0);
	rd16(shp);				# legacy_version
	rdbytes(shp, 32);			# random
	slen := rd8(shp);
	rdbytes(shp, slen);
	suite := rd16(shp);
	rd8(shp);				# compression
	extlen := rd16(shp);
	exts := rdbytes(shp, extlen);
	if(suite != 16r1301)
		return "server chose suite " + string suite;
	serverpub: array of byte;
	ok13 := 0;
	er := ref Rd(exts, len exts, 0);
	while(er.o + 4 <= er.n){
		et := rd16(er);
		el := rd16(er);
		ed := rdbytes(er, el);
		if(ed == nil)
			break;
		if(et == 43)
			ok13 = ((int ed[0] << 8) | int ed[1]) == 16r0304;
		if(et == 51)
			serverpub = keyof(ed);
	}
	if(!ok13)
		return "server did not select TLS 1.3";
	if(serverpub == nil)
		return "no key share";

	shared := mono->x25519(sk, serverpub);
	if(shared == nil)
		return "x25519";

	# ---- key schedule ----
	zeros := array[32] of byte;
	for(i = 0; i < 32; i++)
		zeros[i] = byte 0;
	empty := array[0] of byte;
	eh := sha256(empty);
	early := hkdfextract(zeros, zeros);
	derived := derivsec(early, "derived", eh);
	hs := hkdfextract(derived, shared);
	th := sha256(tr[0:trn]);
	chs := derivsec(hs, "c hs traffic", th);
	shs := derivsec(hs, "s hs traffic", th);
	chsk := hkexp(chs, "key", empty, 16);
	chsiv := hkexp(chs, "iv", empty, 12);
	shsk := hkexp(shs, "key", empty, 16);
	shsiv := hkexp(shs, "iv", empty, 12);

	# ---- server flight ----
	hb := array[65536] of byte;
	hbn := 0;
	thcert: array of byte;
	certder: array of byte;
	gotfin := 0;
	gotcreq := 0;
	cvok := 0;
	done := 0;
	t: int;
	d: array of byte;
	while(!done){
		(t, d, e) = readenc(c.fd, shsk, shsiv, c.srvseq);
		if(e != nil)
			return "server flight: " + e;
		c.srvseq++;
		if(t != 22)
			return "server flight: inner type " + string t;
		for(i = 0; i < len d; i++){
			hb[hbn] = d[i];
			hbn++;
		}
		for(;;){
			if(hbn < 4)
				break;
			ml := (int hb[1] << 16) | (int hb[2] << 8) | int hb[3];
			if(4 + ml > hbn)
				break;
			mt := int hb[0];
			mb := hb[4:4+ml];
			# Every handshake message is hashed, including ones
			# this client does not act on (CertificateRequest).
			if(mt == 15){
				if(!verifycv(certder, mb, thcert))
					return "CertificateVerify failed";
				cvok = 1;
				trn = tapp(tr, trn, hsmsg(15, mb));
			} else if(mt == 20){
				fk := hkexp(shs, "finished", empty, 32);
				want := hmac(fk, sha256(tr[0:trn]));
				if(!eq(want, mb))
					return "bad server Finished";
				trn = tapp(tr, trn, hsmsg(20, mb));
				gotfin = 1;
				done = 1;
			} else {
				trn = tapp(tr, trn, hsmsg(mt, mb));
				if(mt == 11){
					certder = leafcert(mb);
					if(certder == nil)
						return "no certificate";
					thcert = sha256(tr[0:trn]);
				}
				if(mt == 13)
					gotcreq = 1;
			}
			# drop the message just consumed
			for(j := 0; j + 4 + ml < hbn; j++)
				hb[j] = hb[j+4+ml];
			hbn -= 4 + ml;
			if(done)
				break;
		}
	}
	if(!cvok || !gotfin)
		return "incomplete server flight";

	# application secrets use the transcript through server Finished
	derived2 := derivsec(hs, "derived", eh);
	master := hkdfextract(derived2, zeros);
	thfin := sha256(tr[0:trn]);
	capp := derivsec(master, "c ap traffic", thfin);
	sapp := derivsec(master, "s ap traffic", thfin);
	cakk := hkexp(capp, "key", empty, 16);
	caiv := hkexp(capp, "iv", empty, 12);
	sakk := hkexp(sapp, "key", empty, 16);
	saiv := hkexp(sapp, "iv", empty, 12);
	c.srvseq = 0;
	c.cliseq = 0;
	c.cakk = cakk;
	c.caiv = caiv;
	c.sakk = sakk;
	c.saiv = saiv;

	# middlebox-compat ChangeCipherSpec
	ccs := array[6] of byte;
	ccs[0] = byte 20; ccs[1] = byte 3; ccs[2] = byte 3;
	ccs[3] = byte 0; ccs[4] = byte 1; ccs[5] = byte 1;
	chseq := 0;
	frec: array of byte;
	e2: string;
	if(writeall(c.fd, ccs) < 0)
		return "write CCS";

	# A server that asked for a client certificate gets an empty one.
	if(gotcreq){
		cb := ref Bo(array[16] of byte, 0);
		bp(cb, 0);
		b24(cb, 0);
		cm := hsmsg(11, cb.d[0:cb.n]);
		trn = tapp(tr, trn, cm);
		(frec, e2) = sealrec(22, cm, chsk, chsiv, chseq);
		if(e2 != nil)
			return e2;
		chseq++;
		if(writeall(c.fd, frec) < 0)
			return "write Certificate";
	}

	# ---- client Finished ----
	cfk := hkexp(chs, "finished", empty, 32);
	cfv := hmac(cfk, sha256(tr[0:trn]));
	cfin := hsmsg(20, cfv);
	(frec, e2) = sealrec(22, cfin, chsk, chsiv, chseq);
	if(e2 != nil)
		return e2;
	if(writeall(c.fd, frec) < 0)
		return "write Finished";

	c.fp = certfingerprint(certder);
	return nil;
}


# ---- certificate ------------------------------------------------------

leafcert(mb: array of byte): array of byte
{
	r := ref Rd(mb, len mb, 0);
	ctx := rd8(r);
	rdbytes(r, ctx);
	ll := rd24(r);
	lst := rdbytes(r, ll);
	if(lst == nil)
		return nil;
	lr := ref Rd(lst, len lst, 0);
	cl := rd24(lr);
	d := rdbytes(lr, cl);
	if(d == nil)
		return nil;
	# copy: d aliases the handshake buffer, which is shifted as
	# messages are consumed
	der := array[cl] of byte;
	for(i := 0; i < cl; i++)
		der[i] = d[i];
	return der;
}

# Pull the SubjectPublicKeyInfo public key out of the leaf DER.
# Returns 04||X||Y for P-256 or the 32-byte Ed25519 key; nil if the
# certificate does not use one of those.
certpub(der: array of byte): array of byte
{
	(t, l, h) := dertlv(der, 0);	# Certificate SEQUENCE
	if(t != 16r30)
		return nil;
	tbs := h;			# its content starts at tbsCertificate
	(t, l, h) = dertlv(der, tbs);
	if(t != 16r30)
		return nil;
	o := tbs + h;			# first field of tbsCertificate
	if(tagat(der, o) == 16rA0)	# optional [0] version
		o = skip(der, o);
	for(k := 0; k < 5; k++){	# serial, signature, issuer,
		o = skip(der, o);	# validity, subject
	}
	if(o < 0)
		return nil;
	(t, l, h) = dertlv(der, o);	# SubjectPublicKeyInfo SEQUENCE
	if(t != 16r30)
		return nil;
	sp := o + h;			# AlgorithmIdentifier
	bs := skip(der, sp);		# the subjectPublicKey BIT STRING
	if(bs < 0)
		return nil;
	(bt, bl, bh) := dertlv(der, bs);
	if(bt != 3 || bl < 2)
		return nil;
	bits := der[bs+bh:bs+bh+bl];
	if(int bits[0] != 0)
		return nil;
	return bits[1:];
}

tagat(a: array of byte, off: int): int
{
	if(off < 0 || off >= len a)
		return -1;
	return int a[off];
}

# offset just past the element that starts at off, or -1
skip(a: array of byte, off: int): int
{
	(t, l, h) := dertlv(a, off);
	if(h == 0)
		return -1;
	return off + h + l;
}

dertlv(a: array of byte, off: int): (int, int, int)
{
	if(off + 2 > len a)
		return (0, 0, 0);
	t := int a[off];
	l := int a[off+1];
	o := off + 2;
	if(l & 16r80){
		n := l & 16r7f;
		l = 0;
		for(i := 0; i < n; i++){
			if(o >= len a)
				return (0, 0, 0);
			l = (l << 8) | int a[o];
			o++;
		}
	}
	if(o + l > len a)
		return (0, 0, 0);
	return (t, l, o - off);
}

verifycv(der: array of byte, mb: array of byte, th: array of byte): int
{
	pub := certpub(der);
	if(pub == nil)
		return 0;
	r := ref Rd(mb, len mb, 0);
	sigalg := rd16(r);
	sig := rdbytes(r, rd16(r));
	if(sig == nil)
		return 0;
	# only ecdsa_secp256r1_sha256 for now
	if(sigalg != 16r0403 || len pub != 65)
		return 0;
	msg := ref Bo(array[512] of byte, 0);
	for(i := 0; i < 64; i++)
		bp(msg, 16r20);
	bpa(msg, array of byte "TLS 1.3, server CertificateVerify");
	bp(msg, 0);
	bpa(msg, th);
	return tls->ecverify(pub, sha256(msg.d[0:msg.n]), sig);
}


certfingerprint(der: array of byte): string
{
	h := sha256(der);
	s := "";
	for(i := 0; i < len h; i++)
		s += sys->sprint("%.2x", int h[i]);
	return s;
}

# ---- application records ---------------------------------------------

writeapp(c: ref Conn, b: array of byte): string
{
	(rec, e) := sealrec(23, b, c.cakk, c.caiv, c.cliseq);
	if(e != nil)
		return e;
	c.cliseq++;
	if(writeall(c.fd, rec) < 0)
		return "write";
	return nil;
}

readapp(c: ref Conn): (array of byte, string)
{
	for(;;){
		(t, d, e) := readenc(c.fd, c.sakk, c.saiv, c.srvseq);
		if(e != nil)
			return (nil, e);
		c.srvseq++;
		if(t == 21)
			return (nil, "eof");
		if(t == 22)		# NewSessionTicket and friends
			continue;
		if(t != 23)
			return (nil, "inner type " + string t);
		return (d, nil);
	}
}

# ---- records ---------------------------------------------------------

hsrec(msg: array of byte): array of byte
{
	b := ref Bo(array[16384] of byte, 0);
	bp(b, 22);
	b16(b, 16r0301);
	b16(b, len msg);
	bpa(b, msg);
	return b.d[0:b.n];
}

sealrec(inner: int, data: array of byte,
	key, iv: array of byte, seq: int): (array of byte, string)
{
	b := ref Bo(array[16384] of byte, 0);
	bpa(b, data);
	bp(b, inner);
	nonce := mkn(iv, seq);
	hdr := ref Bo(array[8] of byte, 0);
	bp(hdr, 23);
	b16(hdr, 16r0303);
	b16(hdr, len b.d[0:b.n] + 16);
	cipher := tls->gcmseal(key, nonce, hdr.d[0:hdr.n], b.d[0:b.n]);
	if(cipher == nil)
		return (nil, "gcm seal failed");
	out := ref Bo(array[16384] of byte, 0);
	bpa(out, hdr.d[0:hdr.n]);
	bpa(out, cipher);
	return (out.d[0:out.n], nil);
}

readrecord(fd: ref Sys->FD): (int, array of byte, string)
{
	h := array[5] of byte;
	if(readn(fd, h, 5) != 5)
		return (-1, nil, "short record header");
	n := (int h[3] << 8) | int h[4];
	if(n <= 0 || n > MAXREC)
		return (-1, nil, "bad record length");
	d := array[n] of byte;
	if(readn(fd, d, n) != n)
		return (-1, nil, "short record");
	return (int h[0], d, nil);
}

readenc(fd: ref Sys->FD, key, iv: array of byte,
	seq: int): (int, array of byte, string)
{
	h := array[5] of byte;
	for(;;){
		if(readn(fd, h, 5) != 5)
			return (-1, nil, "short record header");
		n := (int h[3] << 8) | int h[4];
		if(n <= 0 || n > MAXREC)
			return (-1, nil, "bad record length");
		d := array[n] of byte;
		if(readn(fd, d, n) != n)
			return (-1, nil, "short record");
		if(int h[0] == 20)		# compatibility CCS
			continue;
		if(int h[0] != 23)
			return (-1, nil, "unexpected record type");
		nonce := mkn(iv, seq);
		p := tls->gcmopen(key, nonce, h, d);
		if(p == nil)
			return (-1, nil, "bad record tag");
		i := len p - 1;
		while(i >= 0 && p[i] == byte 0)
			i--;
		if(i < 0)
			return (-1, nil, "empty plaintext");
		return (int p[i], p[0:i], nil);
	}
}

mkn(iv: array of byte, seq: int): array of byte
{
	n := array[12] of byte;
	for(i := 0; i < 12; i++)
		n[i] = iv[i];
	n[11] = byte (int n[11] ^ (seq & 16rff));
	n[10] = byte (int n[10] ^ ((seq >> 8) & 16rff));
	n[9] = byte (int n[9] ^ ((seq >> 16) & 16rff));
	n[8] = byte (int n[8] ^ ((seq >> 24) & 16rff));
	return n;
}

# ---- TLS 1.3 key schedule --------------------------------------------

hkdfextract(salt, ikm: array of byte): array of byte
{
	return hmac(salt, ikm);
}

hkexp(secret: array of byte, label: string, ctx: array of byte, l: int): array of byte
{
	full := "tls13 " + label;
	info := ref Bo(array[128] of byte, 0);
	bp(info, l >> 8);
	bp(info, l & 16rff);
	bp(info, len full);
	bpa(info, array of byte full);
	bp(info, len ctx);
	bpa(info, ctx);
	return hkdfexpand(secret, info.d[0:info.n], l);
}

hkdfexpand(prk, info: array of byte, l: int): array of byte
{
	out := array[l] of byte;
	t := array[0] of byte;
	n := 0;
	i := 1;
	while(n < l){
		m := cat(t, info);
		one := array[1] of byte;
		one[0] = byte i;
		t = hmac(prk, cat(m, one));
		for(j := 0; j < len t && n < l; j++){
			out[n] = t[j];
			n++;
		}
		i++;
	}
	return out;
}

derivsec(secret: array of byte, label: string, th: array of byte): array of byte
{
	return hkexp(secret, label, th, 32);
}

hmac(key, msg: array of byte): array of byte
{
	k := key;
	if(len k > 64)
		k = sha256(k);
	ip := array[64] of byte;
	op := array[64] of byte;
	for(i := 0; i < 64; i++){
		b := 0;
		if(i < len k)
			b = int k[i];
		ip[i] = byte (b ^ 16r36);
		op[i] = byte (b ^ 16r5c);
	}
	return sha256(cat(op, sha256(cat(ip, msg))));
}

sha256(d: array of byte): array of byte
{
	out := array[32] of byte;
	crypt->sha256(d, len d, out, nil);
	return out;
}

# ---- handshake helpers ------------------------------------------------

hsmsg(typ: int, body: array of byte): array of byte
{
	b := ref Bo(array[16384] of byte, 0);
	bp(b, typ);
	b24(b, len body);
	bpa(b, body);
	return b.d[0:b.n];
}

keyof(d: array of byte): array of byte
{
	if(len d < 4)
		return nil;
	kl := (int d[2] << 8) | int d[3];
	if(4 + kl > len d)
		return nil;
	return d[4:4+kl];
}

# ---- byte helpers -----------------------------------------------------

rd8(r: ref Rd): int
{
	if(r.o >= r.n)
		return -1;
	return int r.d[r.o++];
}

rd16(r: ref Rd): int
{
	if(r.o + 2 > r.n)
		return -1;
	v := (int r.d[r.o] << 8) | int r.d[r.o+1];
	r.o += 2;
	return v;
}

rd24(r: ref Rd): int
{
	if(r.o + 3 > r.n)
		return -1;
	v := (int r.d[r.o] << 16) | (int r.d[r.o+1] << 8) | int r.d[r.o+2];
	r.o += 3;
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

bp(b: ref Bo, v: int)
{
	if(b.n < len b.d)
		b.d[b.n++] = byte (v & 16rff);
}

b16(b: ref Bo, v: int)
{
	bp(b, v >> 8);
	bp(b, v);
}

b24(b: ref Bo, v: int)
{
	bp(b, v >> 16);
	bp(b, v >> 8);
	bp(b, v);
}

bpa(b: ref Bo, a: array of byte)
{
	for(i := 0; i < len a && b.n < len b.d; i++)
		b.d[b.n++] = a[i];
}

cat(a, b: array of byte): array of byte
{
	c := array[len a + len b] of byte;
	for(i := 0; i < len a; i++)
		c[i] = a[i];
	for(i = 0; i < len b; i++)
		c[len a + i] = b[i];
	return c;
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

tapp(d: array of byte, off: int, a: array of byte): int
{
	for(i := 0; i < len a && off + i < len d; i++)
		d[off+i] = a[i];
	return off + len a;
}

randombytes(n: int): array of byte
{
	fd := sys->open("/dev/random", Sys->OREAD);
	if(fd == nil)
		return nil;
	b := array[n] of byte;
	if(readn(fd, b, n) != n)
		b = nil;
	fd = nil;
	return b;
}

readn(fd: ref Sys->FD, b: array of byte, n: int): int
{
	o := 0;
	while(o < n){
		m := sys->read(fd, b[o:n], n - o);
		if(m <= 0)
			return o;
		o += m;
	}
	return o;
}

writeall(fd: ref Sys->FD, b: array of byte): int
{
	o := 0;
	while(o < len b){
		m := sys->write(fd, b[o:], len b - o);
		if(m <= 0)
			return -1;
		o += m;
	}
	return 0;
}
