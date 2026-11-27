implement Form1;

#
# form1 ticket/authenticator protection: ChaCha20-Poly1305 with a
# 12-byte nonce made from an 8-byte message signature and a 4-byte
# little-endian counter.  This is the 9front form1 format.
#

include "sys.m";
	sys: Sys;

include "form1.m";

form1counter := 0;

sigfor(num: int): string
{
	if(num == AuthPass) return "form1 PR";
	if(num == AuthTs) return "form1 Ts";
	if(num == AuthTc) return "form1 Tc";
	if(num == AuthAs) return "form1 As";
	if(num == AuthAc) return "form1 Ac";
	if(num == AuthTp) return "form1 Tp";
	if(num == AuthHr) return "form1 Hr";
	return nil;
}

numfor(sig: string): int
{
	if(sig == "form1 PR") return AuthPass;
	if(sig == "form1 Ts") return AuthTs;
	if(sig == "form1 Tc") return AuthTc;
	if(sig == "form1 As") return AuthAs;
	if(sig == "form1 Ac") return AuthAc;
	if(sig == "form1 Tp") return AuthTp;
	if(sig == "form1 Hr") return AuthHr;
	return -1;
}

le32(n: int): array of byte
{
	b := array[4] of byte;
	b[0] = byte n;
	b[1] = byte (n >> 8);
	b[2] = byte (n >> 16);
	b[3] = byte (n >> 24);
	return b;
}

le64(n: int): array of byte
{
	b := array[8] of {* => byte 0};
	b[0] = byte n;
	b[1] = byte (n >> 8);
	b[2] = byte (n >> 16);
	b[3] = byte (n >> 24);
	return b;
}

zeros(n: int): array of byte
{
	return array[n] of {* => byte 0};
}

cat(a, b: array of byte): array of byte
{
	r := array[len a + len b] of byte;
	r[0:] = a;
	r[len a:] = b;
	return r;
}

u8to32le(b: array of byte, off: int): int
{
	return int b[off] | int b[off+1] << 8 |
	       int b[off+2] << 16 | int b[off+3] << 24;
}

rotl(x, n: int): int
{
	return (x << n) | ((x >> (32-n)) & ((1 << n) - 1));
}

qr(w: array of int, a, b, c, d: int)
{
	w[a] += w[b]; w[d] ^= w[a]; w[d] = rotl(w[d], 16);
	w[c] += w[d]; w[b] ^= w[c]; w[b] = rotl(w[b], 12);
	w[a] += w[b]; w[d] ^= w[a]; w[d] = rotl(w[d], 8);
	w[c] += w[d]; w[b] ^= w[c]; w[b] = rotl(w[b], 7);
}

chacha_block(key, nonce: array of byte, counter: int): array of int
{
	x := array[16] of int;
	w := array[16] of int;

	x[0] = 16r61707865;
	x[1] = 16r3320646e;
	x[2] = 16r79622d32;
	x[3] = 16r6b206574;
	for(i := 0; i < 8; i++)
		x[4+i] = u8to32le(key, 4*i);
	x[12] = counter;
	x[13] = u8to32le(nonce, 0);
	x[14] = u8to32le(nonce, 4);
	x[15] = u8to32le(nonce, 8);
	for(i = 0; i < 16; i++)
		w[i] = x[i];
	for(i = 0; i < 10; i++){
		qr(w, 0, 4, 8, 12);
		qr(w, 1, 5, 9, 13);
		qr(w, 2, 6, 10, 14);
		qr(w, 3, 7, 11, 15);
		qr(w, 0, 5, 10, 15);
		qr(w, 1, 6, 11, 12);
		qr(w, 2, 7, 8, 13);
		qr(w, 3, 4, 9, 14);
	}
	for(i = 0; i < 16; i++)
		w[i] += x[i];
	return w;
}

chacha_xor(data, key, nonce: array of byte, counter: int): array of byte
{
	out := array[len data] of byte;
	for(off := 0; off < len data; off += 64){
		blk := chacha_block(key, nonce, counter++);
		for(i := 0; i < 64 && off+i < len data; i++){
			v := (blk[i/4] >> (8*(i%4))) & 16rff;
			out[off+i] = byte (int data[off+i] ^ v);
		}
	}
	return out;
}

polymul(h0, h1, h2, h3, h4, r0, r1, r2, r3, r4,
        s1, s2, s3, s4: int): (int, int, int, int, int)
{
	d0 := big h0 * big r0 + big h1 * big s4 + big h2 * big s3 +
	      big h3 * big s2 + big h4 * big s1;
	d1 := big h0 * big r1 + big h1 * big r0 + big h2 * big s4 +
	      big h3 * big s3 + big h4 * big s2;
	d2 := big h0 * big r2 + big h1 * big r1 + big h2 * big r0 +
	      big h3 * big s4 + big h4 * big s3;
	d3 := big h0 * big r3 + big h1 * big r2 + big h2 * big r1 +
	      big h3 * big r0 + big h4 * big s4;
	d4 := big h0 * big r4 + big h1 * big r3 + big h2 * big r2 +
	      big h3 * big r1 + big h4 * big r0;

	c := int((d0 >> 26) & big 16rffffffff); h0 = int(d0 & big 16r3ffffff);
	d1 += big c; c = int((d1 >> 26) & big 16rffffffff);
	h1 = int(d1 & big 16r3ffffff);
	d2 += big c; c = int((d2 >> 26) & big 16rffffffff);
	h2 = int(d2 & big 16r3ffffff);
	d3 += big c; c = int((d3 >> 26) & big 16rffffffff);
	h3 = int(d3 & big 16r3ffffff);
	d4 += big c; c = int((d4 >> 26) & big 16rffffffff);
	h4 = int(d4 & big 16r3ffffff);
	h0 += c * 5; c = h0 >> 26; h0 &= 16r3ffffff; h1 += c;
	return (h0, h1, h2, h3, h4);
}

poly1305(key, m: array of byte): array of byte
{
	mask := 16r3ffffff;
	r0 := u8to32le(key, 0) & mask;
	r1 := (u8to32le(key, 3) >> 2) & 16r3ffff03;
	r2 := (u8to32le(key, 6) >> 4) & 16r3ffc0ff;
	r3 := (u8to32le(key, 9) >> 6) & 16r3f03fff;
	r4 := (u8to32le(key, 12) >> 8) & 16r00fffff;
	s1 := r1 * 5;
	s2 := r2 * 5;
	s3 := r3 * 5;
	s4 := r4 * 5;
	h0 := h1 := h2 := h3 := h4 := 0;
	pad0 := big u8to32le(key, 16) & big 16rffffffff;
	pad1 := big u8to32le(key, 20) & big 16rffffffff;
	pad2 := big u8to32le(key, 24) & big 16rffffffff;
	pad3 := big u8to32le(key, 28) & big 16rffffffff;
	hibit := 1 << 24;

	n := (len m + 15) / 16;
	for(b := 0; b < n; b++){
		buf := array[16] of {* => byte 0};
		off := b * 16;
		cnt := len m - off;
		if(cnt > 16)
			cnt = 16;
		buf[0:] = m[off:off+cnt];
		partial := cnt < 16;
		if(partial)
			buf[cnt] = byte 1;
		h0 += u8to32le(buf, 0) & mask;
		h1 += (u8to32le(buf, 3) >> 2) & mask;
		h2 += (u8to32le(buf, 6) >> 4) & mask;
		h3 += (u8to32le(buf, 9) >> 6) & mask;
		# Limbo >> on int sign-extends, so mask after shifting byte 15
		if(partial)
			h4 += (u8to32le(buf, 12) >> 8) & 16rffffff;
		else
			h4 += ((u8to32le(buf, 12) >> 8) & 16rffffff) | hibit;
		(h0, h1, h2, h3, h4) = polymul(h0, h1, h2, h3, h4,
		                               r0, r1, r2, r3, r4,
		                               s1, s2, s3, s4);
	}

	c := h1 >> 26; h1 &= mask;
	h2 += c; c = h2 >> 26; h2 &= mask;
	h3 += c; c = h3 >> 26; h3 &= mask;
	h4 += c; c = h4 >> 26; h4 &= mask;
	h0 += c * 5; c = h0 >> 26; h0 &= mask;
	h1 += c;

	g0 := h0 + 5; c = g0 >> 26; g0 &= mask;
	g1 := h1 + c; c = g1 >> 26; g1 &= mask;
	g2 := h2 + c; c = g2 >> 26; g2 &= mask;
	g3 := h3 + c; c = g3 >> 26; g3 &= mask;
	g4 := h4 + c - (1 << 26);

	sel := 0;
	if(g4 >= 0)
		sel = -1;
	g0 &= sel; g1 &= sel; g2 &= sel; g3 &= sel; g4 &= sel;
	sel = ~sel;
	h0 = (h0 & sel) | g0;
	h1 = (h1 & sel) | g1;
	h2 = (h2 & sel) | g2;
	h3 = (h3 & sel) | g3;
	h4 = (h4 & sel) | g4;

	h0 = h0 | (h1 << 26);
	h1 = (h1 >> 6) | (h2 << 20);
	h2 = (h2 >> 12) | (h3 << 14);
	h3 = (h3 >> 18) | (h4 << 8);

	f := (big h0 & big 16rffffffff) + pad0;
	h0 = int(f & big 16rffffffff);
	f = (big h1 & big 16rffffffff) + pad1 + (f >> 32);
	h1 = int(f & big 16rffffffff);
	f = (big h2 & big 16rffffffff) + pad2 + (f >> 32);
	h2 = int(f & big 16rffffffff);
	f = (big h3 & big 16rffffffff) + pad3 + (f >> 32);
	h3 = int(f & big 16rffffffff);

	tag := array[16] of byte;
	t := le32(h0); tag[0:] = t;
	t = le32(h1); tag[4:] = t;
	t = le32(h2); tag[8:] = t;
	t = le32(h3); tag[12:] = t;
	return tag;
}

ccmac(key, nonce, aad, cipher: array of byte): array of byte
{
	pb := chacha_block(key, nonce, 0);
	pk := array[32] of byte;
	for(i := 0; i < 32; i++)
		pk[i] = byte ((pb[i/4] >> (8*(i%4))) & 16rff);
	m := array[0] of byte;
	if(len aad > 0){
		m = cat(m, aad);
		m = cat(m, zeros((16 - len aad % 16) % 16));
	}
	m = cat(m, cipher);
	m = cat(m, zeros((16 - len cipher % 16) % 16));
	m = cat(m, le64(len aad));
	m = cat(m, le64(len cipher));
	return poly1305(pk, m);
}

ccenc(key, nonce, aad, plain: array of byte): array of byte
{
	cipher := chacha_xor(plain, key, nonce, 1);
	return cat(cipher, ccmac(key, nonce, aad, cipher));
}

ccdec(key, nonce, aad, cipher: array of byte): array of byte
{
	if(len cipher < 16)
		return nil;
	body := cipher[0:len cipher-16];
	tag := cipher[len cipher-16:];
	want := ccmac(key, nonce, aad, body);
	ok := 1;
	for(i := 0; i < 16; i++)
		if(want[i] != tag[i])
			ok = 0;
	if(!ok)
		return nil;
	return chacha_xor(body, key, nonce, 1);
}

ccencrypt(key, nonce, aad, plain: array of byte): array of byte
{
	return ccenc(key, nonce, aad, plain);
}

ccdecrypt(key, nonce, aad, cipher: array of byte): array of byte
{
	return ccdec(key, nonce, aad, cipher);
}

encrypt(num: int, key: array of byte, plain: array of byte): array of byte
{
	sig := sigfor(num);
	if(sig == nil || len key != 32)
		return nil;
	ctr := form1counter;
	form1counter = ctr + 1;
	nonce := cat(array of byte sig, le32(ctr));
	body := ccenc(key, nonce, nil, plain);
	if(body == nil)
		return nil;
	return cat(nonce, body);
}

decrypt(key: array of byte, frame: array of byte): (int, array of byte)
{
	if(len key != 32 || len frame < 12+16+1)
		return (-1, nil);
	num := numfor(string frame[0:8]);
	if(num < 0)
		return (-1, nil);
	plain := ccdec(key, frame[0:12], nil, frame[12:]);
	if(plain == nil)
		return (-1, nil);
	return (num, plain);
}
