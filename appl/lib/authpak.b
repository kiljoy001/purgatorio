implement Authpak;

#
# AuthPAK (SPAKE2 Elligator edition) for dp9ik, in portable Limbo.
# The curve is Ed448 with Decaf encoding, following 9front's
# libauthsrv/decaf.mp, ed448.mp, edwards.mp, elligator2.mp, msqrt.mp
# and spake2ee.mp.
#

include "sys.m";
	sys: Sys;

include "keyring.m";
	kr: Keyring;
	IPint: import kr;

include "authpak.m";

p, d, gx, gy, one, zero: ref IPint;
halfp, sqrtexp, misqrtexp, legexp: ref IPint;
inited := 0;

init()
{
	if(inited)
		return;
	sys = load Sys Sys->PATH;
	kr = load Keyring Keyring->PATH;
	if(kr == nil)
		return;
	one = IPint.inttoip(1);
	zero = IPint.inttoip(0);
	p = one.shl(448).sub(one.shl(224)).sub(one);
	d = p.sub(IPint.inttoip(39081)).mod(p);
	gx = IPint.strtoip("117812161263436946737282484343310064665180535357016373416879082147939404277809514858788439644911793978499419995990477371552926308078495", 10);
	gy = IPint.inttoip(19);
	halfp = fdiv(p.sub(one), IPint.inttoip(2));
	sqrtexp = fdiv(p.add(one), IPint.inttoip(4));
	misqrtexp = fdiv(p.sub(IPint.inttoip(3)), IPint.inttoip(4));
	legexp = fdiv(p.sub(one), IPint.inttoip(2));
	inited = 1;
}

fdiv(a, b: ref IPint): ref IPint
{
	(q, nil) := a.div(b);
	return q;
}

fadd(a, b: ref IPint): ref IPint
{
	return a.add(b).mod(p);
}

fsub(a, b: ref IPint): ref IPint
{
	return a.add(p).sub(b).mod(p);
}

fmul(a, b: ref IPint): ref IPint
{
	return a.mul(b).mod(p);
}

fsqr(a: ref IPint): ref IPint
{
	return fmul(a, a);
}

fneg(a: ref IPint): ref IPint
{
	return p.sub(a.mod(p)).mod(p);
}

finv(a: ref IPint): ref IPint
{
	return a.invert(p);
}

fpow(a, e: ref IPint): ref IPint
{
	return a.mod(p).expmod(e, p);
}

fiszero(a: ref IPint): int
{
	return a.mod(p).eq(zero);
}

cat(a, b: array of byte): array of byte
{
	r := array[len a + len b] of byte;
	r[0:] = a;
	r[len a:] = b;
	return r;
}

cat4(a, b, c, d: array of byte): array of byte
{
	return cat(cat(a, b), cat(c, d));
}

to56(x: ref IPint): array of byte
{
	b := x.iptobebytes();
	if(len b == PAKSLEN)
		return b;
	r := array[PAKSLEN] of {* => byte 0};
	if(len b > PAKSLEN)
		b = b[len b - PAKSLEN:];
	r[PAKSLEN - len b:] = b;
	return r;
}

betoint(b: array of byte): ref IPint
{
	return IPint.bebytestoip(b);
}

sha256b(b: array of byte): array of byte
{
	dg := array[Keyring->SHA256dlen] of byte;
	kr->sha256(b, len b, dg, nil);
	return dg;
}

sha256cat(a, b: array of byte): array of byte
{
	dg := array[Keyring->SHA256dlen] of byte;
	st := kr->sha256(a, len a, nil, nil);
	kr->sha256(b, len b, dg, st);
	return dg;
}

hmacsha256(key, data: array of byte): array of byte
{
	block := 64;
	k := array[block] of {* => byte 0};
	if(len key > block)
		key = sha256b(key);
	k[0:] = key;
	ipad := array[block] of byte;
	opad := array[block] of byte;
	for(i := 0; i < block; i++){
		ipad[i] = byte (int k[i] ^ 16r36);
		opad[i] = byte (int k[i] ^ 16r5c);
	}
	inner := sha256b(cat(ipad, data));
	return sha256b(cat(opad, inner));
}

hkdf(salt, info, ikm: array of byte, n: int): array of byte
{
	init();
	if(kr == nil || n <= 0)
		return nil;
	if(salt == nil || len salt == 0)
		salt = array[Keyring->SHA256dlen] of {* => byte 0};
	prk := hmacsha256(salt, ikm);
	out := array[0] of byte;
	t := array[0] of byte;
	for(i := 1; len out < n; i++){
		c := array[1] of byte;
		c[0] = byte i;
		t = hmacsha256(prk, cat(cat(t, info), c));
		out = cat(out, t);
	}
	return out[0:n];
}

be32(v: int): array of byte
{
	b := array[4] of byte;
	b[0] = byte (v >> 24);
	b[1] = byte (v >> 16);
	b[2] = byte (v >> 8);
	b[3] = byte v;
	return b;
}

aeskey(pw: string): array of byte
{
	init();
	pwb := array of byte pw;
	salt := array of byte "Plan 9 key derivation";
	dg := array[Keyring->SHA1dlen] of byte;
	kr->hmac_sha1(cat(salt, be32(1)), len salt + 4, pwb, dg, nil);
	t := dg;
	out := array[16] of byte;
	for(i := 0; i < 16; i++)
		out[i] = t[i];
	for(i = 2; i <= 9001; i++){
		next := array[Keyring->SHA1dlen] of byte;
		kr->hmac_sha1(t, len t, pwb, next, nil);
		t = next;
		for(j := 0; j < 16; j++)
			out[j] = byte (int out[j] ^ int t[j]);
	}
	return out;
}

Point: adt
{
	x, y, z, t: ref IPint;
};

pointid(): Point
{
	return Point(zero, one, one, zero);
}

pointneg(a: Point): Point
{
	return Point(fneg(a.x), a.y, a.z, fneg(a.t));
}

edadd(a, b: Point): Point
{
	aa := fmul(a.x, b.x);
	bb := fmul(a.y, b.y);
	cc := fmul(fmul(d, a.t), b.t);
	dz := fmul(a.z, b.z);
	ee := fsub(fsub(fmul(fadd(a.x, a.y), fadd(b.x, b.y)), aa), bb);
	ff := fsub(dz, cc);
	gg := fadd(dz, cc);
	hh := fsub(bb, aa);
	return Point(fmul(ee, ff), fmul(gg, hh), fmul(ff, gg), fmul(ee, hh));
}

bit(s: ref IPint, i: int): int
{
	return s.shr(i).and(one).eq(one);
}

edscale(s: ref IPint, pt: Point): Point
{
	res := pointid();
	if(bit(s, 0))
		res = pt;
	dbl := pt;
	for(i := 1; i < PAKSLEN * 8; i++){
		dbl = edadd(dbl, dbl);
		sum := edadd(dbl, res);
		if(bit(s, i))
			res = sum;
	}
	return res;
}

legendre(a: ref IPint): int
{
	r := fpow(a, legexp);
	if(r.eq(p.sub(one)))
		return -1;
	if(r.eq(one))
		return 1;
	return 0;
}

msqrt(a: ref IPint): ref IPint
{
	if(legendre(a) == 1)
		return fpow(a, sqrtexp);
	return zero;
}

misqrt(a: ref IPint): ref IPint
{
	return fpow(a, misqrtexp);
}

negifhigh(n, r: ref IPint): ref IPint
{
	if(n.cmp(halfp) > 0)
		return fneg(r);
	return r;
}

elligator2(r0: ref IPint): Point
{
	n := IPint.inttoip(7);
	aminus2d := fsub(one, fadd(d, d));
	r := fmul(fmul(n, r0), r0);
	dr := fmul(d, r);
	den := fmul(fsub(fadd(dr, one), d), fsub(fsub(dr, r), d));
	num := fmul(fadd(r, one), aminus2d);
	nd := fmul(num, den);
	c, e: ref IPint;
	if(fiszero(nd)){
		c = one;
		e = zero;
	}else{
		e = msqrt(nd);
		if(!fiszero(e)){
			c = one;
			e = finv(e);
		}else{
			c = fneg(one);
			e = fmul(fmul(n, r0), misqrt(fmul(n, nd)));
		}
	}
	s := fmul(fmul(c, num), e);
	tmp := fmul(fmul(c, num), fsub(r, one));
	tmp = fmul(tmp, fsqr(fmul(aminus2d, e)));
	t := fsub(fneg(tmp), one);
	ss := fsqr(s);
	return Point(fmul(fadd(s, s), t),
	             fmul(fsub(one, ss), fadd(one, ss)),
	             fmul(fadd(one, ss), t),
	             fmul(fadd(s, s), fsub(one, ss)));
}

decafencode(pt: Point): array of byte
{
	aminusd := fsub(one, d);
	r := misqrt(fmul(fmul(aminusd, fadd(pt.z, pt.y)), fsub(pt.z, pt.y)));
	u := fmul(aminusd, r);
	twouz := fmul(u, pt.z);
	r = negifhigh(fneg(fadd(twouz, twouz)), r);
	tmp := fsub(fmul(pt.z, pt.x), fmul(fmul(d, pt.y), pt.t));
	s := fmul(u, fadd(fmul(r, tmp), pt.y));
	return to56(negifhigh(s, s));
}

decafdecode(enc: array of byte): (int, Point)
{
	if(len enc != PAKYLEN)
		return (0, pointid());
	v := betoint(enc);
	if(v.cmp(halfp) > 0)
		return (0, pointid());
	ss := fsqr(v);
	z := fadd(one, ss);
	u := fsub(fsqr(z), fmul(fmul(IPint.inttoip(4), d), ss));
	vv := fmul(u, ss);
	if(!fiszero(vv)){
		root := msqrt(vv);
		if(fiszero(root))
			return (0, pointid());
		vv = finv(root);
	}
	vv = negifhigh(fmul(u, vv), vv);
	w := fmul(fmul(vv, v), fsub(IPint.inttoip(2), z));
	if(fiszero(v))
		w = one;
	x := fadd(v, v);
	return (1, Point(x, fmul(w, z), z, fmul(w, x)));
}

pointbytes(pt: Point): array of byte
{
	return cat4(to56(pt.x), to56(pt.y), to56(pt.z), to56(pt.t));
}

pointfrom(b: array of byte): Point
{
	return Point(betoint(b[0:PAKSLEN]),
	             betoint(b[PAKSLEN:2*PAKSLEN]),
	             betoint(b[2*PAKSLEN:3*PAKSLEN]),
	             betoint(b[3*PAKSLEN:4*PAKSLEN]));
}

randomscalar(): ref IPint
{
	for(;;){
		x := IPint.random(448, 448);
		if(x.cmp(p) < 0)
			return x;
	}
}

hash(aes: array of byte, user: string): array of byte
{
	init();
	if(!inited || len aes != 16)
		return nil;
	salt := sha256b(array of byte user);
	h := hkdf(salt, array of byte "Plan 9 AuthPAK hash", aes, PAKHASHLEN);
	pm := elligator2(betoint(h[0:PAKSLEN]));
	pn := elligator2(betoint(h[PAKSLEN:2*PAKSLEN]));
	return cat(pointbytes(pm), pointbytes(pn));
}

paknew(pakhash: array of byte, isclient: int): (ref PAKstate, array of byte)
{
	init();
	if(!inited || len pakhash != PAKHASHLEN)
		return (nil, nil);
	off := 0;
	if(isclient == 0)
		off = PAKPLEN;
	pm := pointfrom(pakhash[off:off+PAKPLEN]);
	x := randomscalar();
	g := Point(gx, gy, one, fmul(gx, gy));
	y := decafencode(edadd(edscale(x, g), pm));
	st := ref PAKstate(to56(x), y, pakhash, isclient);
	return (st, y);
}

pakfinish(state: ref PAKstate, peer: array of byte): array of byte
{
	init();
	if(!inited || state == nil || len peer != PAKYLEN)
		return nil;
	off := 0;
	if(state.isclient != 0)
		off = PAKPLEN;
	pm := pointfrom(state.pakhash[off:off+PAKPLEN]);
	(ok, y) := decafdecode(peer);
	if(ok == 0)
		return nil;
	z := decafencode(edscale(betoint(state.x), edadd(y, pointneg(pm))));
	first, second: array of byte;
	if(state.isclient != 0){
		first = state.y;
		second = peer;
	}else{
		first = peer;
		second = state.y;
	}
	salt := sha256cat(first, second);
	return hkdf(salt, array of byte "Plan 9 AuthPAK key", z, PAKKEYLEN);
}
