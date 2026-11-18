# mcheck -- independently verify a monoca epoch
#
# Reads /keydb/monoca/{leaves,epoch,roots} and /keydb/mono-signer, then:
#   - checks the epoch signature with $Mono against the signer's public half
#   - recomputes the Merkle root from the leaves
#   - verifies an inclusion path for every leaf
#   - proves a name absent (the revocation primitive)
#   - verifies the retained previous epoch, if there is one
#
# With arguments "name pkhex exp" it also proves that leaf absent, which
# is how a revoked key is checked.
#
# This shares no code with monoca except the merkle module and the
# documented byte layout, so agreement is evidence rather than tautology.

implement Mcheck;

include "sys.m";
	sys: Sys;
include "draw.m";
include "mono.m";
	mono: Mono;
include "merkle.m";
include "daytime.m";
	daytime: Daytime;

Mcheck: module
{
	init:	fn(nil: ref Draw->Context, argv: list of string);
};

DIR:	con "/keydb/monoca";
SIGNER:	con "/keydb/mono-signer";

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	mono = load Mono Mono->PATH;
	daytime = load Daytime Daytime->PATH;
	mk := load Merkle "/dis/lib/merkle.dis";
	if(mono == nil || mk == nil){
		sys->print("mcheck: cannot load mono or merkle\n");
		return;
	}

	ep := readfile(DIR+"/epoch");
	if(ep == ""){
		sys->print("mcheck: no epoch record\n");
		return;
	}
	(n, t, w, rroot, sig) := parseepoch(ep);
	if(rroot == nil || sig == nil){
		sys->print("mcheck: epoch record incomplete\n");
		return;
	}

	sk := signerkey();
	if(sk == nil){
		sys->print("mcheck: no signer key\n");
		return;
	}
	pub := sk[32:64];

	now := 0;
	if(daytime != nil)
		now = daytime->now();
	sys->print("epoch %d time %d window %d now %d (fresh %d)\n",
		n, t, w, now, t <= now && now <= t+w);
	sys->print("epoch signature: %d (want 1)\n",
		mono->edcheck(sig, pub, epochmsg(n, t, w, rroot)));

	# Recompute the root from the leaves, with the same sort order.
	leaves := readfile(DIR+"/leaves");
	l: list of array of byte;
	for(ls := leaves; len ls > 0;){
		(rest, line) := nextline(ls);
		ls = rest;
		(fa, nf) := split(line, 3);
		if(nf < 3)
			continue;
		h := mk->leaf(fa[0], hex2bytes(fa[1]), int fa[2]);
		if(h == nil){
			sys->print("mcheck: leaf failed\n");
			return;
		}
		l = h :: l;
	}
	sl := sorted(l);
	rr := mk->root(sl);
	sys->print("root recomputed: %d (want 1)\n", mono->equal(rr, rroot));

	arr := toarray(sl);
	all := 1;
	for(j := 0; j < len arr; j++){
		p := mk->path(sl, j);
		if(!mk->verify(arr[j], p, j, rroot))
			all = 0;
	}
	sys->print("inclusion (%d leaves): %d (want 1)\n", len arr, all);

	# Absence of a name that was never enrolled.
	cl := mk->leaf("carol", array[32] of byte, 0);
	idx := mk->insert(sl, cl);
	left, right: array of byte;
	lpath, rpath: list of array of byte;
	if(idx-1 >= 0){
		left = arr[idx-1];
		lpath = mk->path(sl, idx-1);
	}
	if(idx < len arr){
		right = arr[idx];
		rpath = mk->path(sl, idx);
	}
	ab := mk->verifyabsent(cl, left, lpath, idx-1, right, rpath, idx, rroot);
	sys->print("absence carol: %d (want 1)\n", ab);

	# The previous epoch is retained for the grace window; its signature
	# must verify with the same signer.
	prev := readfile(DIR+"/roots/"+string (n-1));
	if(prev != ""){
		(pn, pt, pw, pr, ps) := parseepoch(prev);
		if(pr != nil && ps != nil)
			sys->print("previous epoch %d signature: %d (want 1)\n",
				pn, mono->edcheck(ps, pub, epochmsg(pn, pt, pw, pr)));
	}else
		sys->print("previous epoch: none\n");

	# Negative controls: a corrupted signature must fail, and a leaf
	# that is present must not prove absent.
	bad := array[len sig] of byte;
	for(k := 0; k < len sig; k++)
		bad[k] = sig[k];
	bad[0] = byte (int bad[0] ^ 1);
	sys->print("tampered signature: %d (want 0)\n",
		mono->edcheck(bad, pub, epochmsg(n, t, w, rroot)));

	present := arr[0];
	pi := mk->insert(sl, present);
	pl, pr2: array of byte;
	plp, prp: list of array of byte;
	if(pi-1 >= 0){
		pl = arr[pi-1];
		plp = mk->path(sl, pi-1);
	}
	if(pi < len arr){
		pr2 = arr[pi];
		prp = mk->path(sl, pi);
	}
	sys->print("present as absent: %d (want 0)\n",
		mk->verifyabsent(present, pl, plp, pi-1, pr2, prp, pi, rroot));

	# Optional: prove a named leaf absent (a revoked key).
	if(args != nil && tl args != nil){
		rest := tl args;
		if(rest != nil && tl rest != nil && tl tl rest != nil){
			an := hd rest;
			apk := hex2bytes(hd tl rest);
			ae := int hd tl tl rest;
			ah := mk->leaf(an, apk, ae);
			ai := mk->insert(sl, ah);
			ol, orr: array of byte;
			olp, orp: list of array of byte;
			if(ai-1 >= 0){
				ol = arr[ai-1];
				olp = mk->path(sl, ai-1);
			}
			if(ai < len arr){
				orr = arr[ai];
				orp = mk->path(sl, ai);
			}
			sys->print("absence %s: %d (want 1)\n", an,
				mk->verifyabsent(ah, ol, olp, ai-1, orr, orp, ai, rroot));
		}
	}
}

# ---- helpers ---------------------------------------------------------

parseepoch(rec: string): (int, int, int, array of byte, array of byte)
{
	n, t, w: int;
	r, sg: array of byte;
	for(s := rec; len s > 0;){
		(rest, line) := nextline(s);
		s = rest;
		(fa, nf) := split(line, 2);
		if(nf < 2)
			continue;
		case fa[0] {
		"epoch" =>	n = int fa[1];
		"time" =>	t = int fa[1];
		"window" =>	w = int fa[1];
		"root" =>	r = hex2bytes(fa[1]);
		"sig" =>	sg = hex2bytes(fa[1]);
		}
	}
	return (n, t, w, r, sg);
}

epochmsg(n, t, w: int, r: array of byte): array of byte
{
	msg := array[6+8+8+8+len r] of byte;
	for(i := 0; i < 6; i++)
		msg[i] = byte "epoch1"[i];
	put8(msg, 6, n);
	put8(msg, 14, t);
	put8(msg, 22, w);
	for(i = 0; i < len r; i++)
		msg[30+i] = r[i];
	return msg;
}

signerkey(): array of byte
{
	s := readfile(SIGNER);
	for(; len s > 0;){
		(rest, line) := nextline(s);
		s = rest;
		(fa, nf) := split(line, 2);
		if(nf >= 2 && fa[0] == "sk"){
			sk := hex2bytes(fa[1]);
			if(len sk == 64)
				return sk;
		}
	}
	return nil;
}

sorted(l: list of array of byte): list of array of byte
{
	n := 0;
	for(t := l; t != nil; t = tl t)
		n++;
	a := array[n] of array of byte;
	i := 0;
	for(t = l; t != nil; t = tl t){
		a[i] = hd t;
		i++;
	}
	for(i = 1; i < n; i++){
		x := a[i];
		j := i - 1;
		while(j >= 0 && cmp(a[j], x) > 0){
			a[j+1] = a[j];
			j--;
		}
		a[j+1] = x;
	}
	r: list of array of byte;
	for(i = n-1; i >= 0; i--)
		r = a[i] :: r;
	return r;
}

toarray(l: list of array of byte): array of array of byte
{
	n := 0;
	for(t := l; t != nil; t = tl t)
		n++;
	a := array[n] of array of byte;
	i := 0;
	for(t = l; t != nil; t = tl t){
		a[i] = hd t;
		i++;
	}
	return a;
}

cmp(a, b: array of byte): int
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

put8(b: array of byte, off, v: int)
{
	# Shifts of 32 or more are undefined on a 32-bit int; write the
	# high half as zero and the low half explicitly.
	b[off] = byte 0;
	b[off+1] = byte 0;
	b[off+2] = byte 0;
	b[off+3] = byte 0;
	b[off+4] = byte ((v >> 24) & 16rff);
	b[off+5] = byte ((v >> 16) & 16rff);
	b[off+6] = byte ((v >> 8) & 16rff);
	b[off+7] = byte (v & 16rff);
}

nextline(s: string): (string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] == '\n')
			return (s[i+1:], s[0:i]);
	return ("", s);
}

split(s: string, n: int): (array of string, int)
{
	a := array[n] of string;
	k := 0;
	i := 0;
	for(; i < len s && k < n;){
		while(i < len s && (s[i] == ' ' || s[i] == '\t'))
			i++;
		j := i;
		while(j < len s && s[j] != ' ' && s[j] != '\t')
			j++;
		if(j > i){
			a[k] = s[i:j];
			k++;
		}
		i = j;
	}
	return (a, k);
}

readfile(path: string): string
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return "";
	buf := array[65536] of byte;
	n := sys->read(fd, buf, len buf);
	fd = nil;
	if(n <= 0)
		return "";
	return string buf[0:n];
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
