implement Monoca;

#
# monoca -- issue and publish the identity set as a Merkle root
#
#	monoca enroll name [pkhex [exp]]	publish a new epoch with this leaf
#					(pk and exp default to the user's keyring)
#	monoca epoch			print the signed epoch record
#	monoca root			print the current root
#
# The authorised set is /keydb/monoca/leaves, one "name pkhex exp" per
# line.  Each change sorts the leaves by hash, computes the root and
# signs an epoch record with /keydb/mono-signer (tpm9p later).
#
# The signature domain is "epoch1\0" || epoch || time || window || root,
# so an epoch signature can never be confused with an identity one.
#

include "sys.m";
	sys: Sys;
include "draw.m";
include "mono.m";
	mono: Mono;
include "merkle.m";
	merkle: Merkle;
include "daytime.m";
	daytime: Daytime;

Monoca: module
{
	init:	fn(nil: ref Draw->Context, argv: list of string);
};

DIR:	con "/keydb/monoca";
SIGNER:	con "/keydb/mono-signer";
WINDOW:	con 3600;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	mono = load Mono Mono->PATH;
	merkle = load Merkle Merkle->PATH;
	daytime = load Daytime Daytime->PATH;
	if(mono == nil || merkle == nil || daytime == nil){
		sys->fprint(sys->fildes(2), "monoca: cannot load a module: %r\n");
		return;
	}
	if(args == nil || tl args == nil){
		usage();
		return;
	}
	cmd := hd tl args;
	rest := tl tl args;
	case cmd {
	"enroll" =>
		enroll(rest);
	"revoke" =>
		revoke(rest);
	"epoch" =>
		cat(DIR + "/epoch");
	"root" =>
		cat(DIR + "/root");
	* =>
		usage();
	}
}

usage()
{
	sys->fprint(sys->fildes(2), "usage: monoca enroll name [pkhex [exp]] | revoke name | epoch | root\n");
}

# enroll adds a leaf and publishes a new epoch.  Re-enrolling a name
# replaces its old leaf, so key rotation removes the old key from the
# authorised set instead of leaving both valid.
enroll(args: list of string): int
{
	if(len args < 1){
		usage();
		return -1;
	}
	name := hd args;
	pkhex := "";
	exp := 0;
	if(tl args != nil){
		pkhex = hd tl args;
		if(tl tl args != nil)
			exp = int hd tl tl args;
	}else
		pkhex = keyringpk(name);
	if(len hex2bytes(pkhex) != 32){
		sys->fprint(sys->fildes(2), "monoca: pk must be 32 bytes of hex\n");
		return -1;
	}
	mkdir(DIR);
	old := readfile(DIR + "/leaves");
	writefile(DIR + "/leaves",
		dropname(old, name) + name + " " + pkhex + " " + string exp + "\n");
	return publish();
}

# The public half of the identity key is bytes 32 to 64 of the sk line
# in /usr/<name>/keyring/mono, which is what certify(8) writes.
keyringpk(name: string): string
{
	s := readfile("/usr/" + name + "/keyring/mono");
	for(; len s > 0;){
		(nl, line) := nextline(s);
		s = nl;
		(fa, nf) := split(line, 3);
		if(nf >= 2 && fa[0] == "sk"){
			sk := hex2bytes(fa[1]);
			if(len sk == 64){
				h := "";
				for(i := 32; i < 64; i++)
					h += sys->sprint("%.2x", int sk[i]);
				return h;
			}
		}
	}
	return "";
}

# revoke removes every leaf for a name.  The next root no longer
# includes it, so a neighbour proof shows the key absent.
revoke(args: list of string): int
{
	if(len args < 1){
		usage();
		return -1;
	}
	name := hd args;
	mkdir(DIR);
	old := readfile(DIR + "/leaves");
	writefile(DIR + "/leaves", dropname(old, name));
	return publish();
}

# publish sorts the leaves, computes the root and signs a new epoch.
publish(): int
{
	lines := readfile(DIR + "/leaves");
	l: list of array of byte;
	for(s := lines; len s > 0;){
		(nl, i) := nextline(s);
		s = nl;
		if(i == "")
			continue;
		(fa, nf) := split(i, 3);
		if(nf < 3)
			continue;
		h := merkle->leaf(fa[0], hex2bytes(fa[1]), int fa[2]);
		if(h == nil){
			sys->fprint(sys->fildes(2), "monoca: leaf failed: %r\n");
			return -1;
		}
		l = h :: l;
	}
	sl := sorted(l);
	r := merkle->root(sl);
	if(r == nil){
		sys->fprint(sys->fildes(2), "monoca: no root\n");
		return -1;
	}
	sk := signer();
	if(sk == nil){
		sys->fprint(sys->fildes(2), "monoca: cannot read %s\n", SIGNER);
		return -1;
	}
	n := epochno() + 1;
	t := daytime->now();
	b := array[8 + 8 + 8 + 32] of byte;
	put8(b, 0, n);
	put8(b, 8, t);
	put8(b, 16, WINDOW);
	for(i := 0; i < 32; i++)
		b[24+i] = r[i];
	sig := mono->edsign(sk, cat2(array of byte "epoch1", b));
	if(sig == nil){
		sys->fprint(sys->fildes(2), "monoca: sign failed\n");
		return -1;
	}
	rh := bytes2hex(r);
	rec := "epoch " + string n + "\n" + "time " + string t + "\n" +
		"window " + string WINDOW + "\n" + "root " + rh + "\n" +
		"sig " + bytes2hex(sig) + "\n";
	# Keep the record this one replaces, so a verifier can still check a
	# token minted in the previous epoch during the grace window.
	mkdir(DIR + "/roots");
	on := epochno();
	if(on > 0){
		orec := readfile(DIR + "/epoch");
		if(orec != "")
			writefile(DIR + "/roots/" + string on, orec);
	}
	writefile(DIR + "/epoch", rec);
	writefile(DIR + "/root", rh + "\n");
	sys->print("monoca: epoch %d root %s\n", n, rh);
	return 0;
}

epochno(): int
{
	s := readfile(DIR + "/epoch");
	if(s == "")
		return 0;
	(nil, line) := nextline(s);
	(fa, nf) := split(line, 2);
	if(nf < 2 || fa[0] != "epoch")
		return 0;
	return int fa[1];
}

signer(): array of byte
{
	s := readfile(SIGNER);
	for(; len s > 0;){
		(nl, i) := nextline(s);
		s = nl;
		(fa, nf) := split(i, 2);
		if(nf >= 2 && fa[0] == "sk"){
			sk := hex2bytes(fa[1]);
			if(len sk == 64)
				return sk;
		}
	}
	return nil;
}

# ---- helpers ---------------------------------------------------------

# dropname returns the leaves file without any line whose first field
# is name.
dropname(s, name: string): string
{
	out := "";
	for(; len s > 0;){
		(rest, line) := nextline(s);
		s = rest;
		(fa, nf) := split(line, 3);
		if(nf >= 1 && fa[0] == name)
			continue;
		if(line != "")
			out += line + "\n";
	}
	return out;
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

# split into at most n whitespace-separated fields
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

prefix(s, p: string): int
{
	if(len s < len p)
		return 0;
	for(i := 0; i < len p; i++)
		if(s[i] != p[i])
			return 0;
	return 1;
}

cat(path: string)
{
	s := readfile(path);
	if(s == "")
		sys->fprint(sys->fildes(2), "monoca: cannot read %s\n", path);
	else
		sys->print("%s", s);
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

writefile(path, s: string): int
{
	fd := sys->create(path, Sys->OWRITE, 8r600);
	if(fd == nil)
		return -1;
	if(sys->write(fd, array of byte s, len s) != len s){
		fd = nil;
		return -1;
	}
	fd = nil;
	return 0;
}

mkdir(path: string)
{
	if(sys->create(path, Sys->OREAD, Sys->DMDIR|8r755) == nil)
		;	# already there
}

cat2(a, b: array of byte): array of byte
{
	c := array[len a + len b] of byte;
	for(i := 0; i < len a; i++)
		c[i] = a[i];
	for(i = 0; i < len b; i++)
		c[len a + i] = b[i];
	return c;
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

bytes2hex(a: array of byte): string
{
	s := "";
	for(i := 0; i < len a; i++)
		s += sys->sprint("%.2x", int a[i]);
	return s;
}
