#
#  gemserve -- a Gemini server driven by a 9P control file.
#
#  The control plane is an append-only file on /n/host (a 9P mount of
#  the host tree).  This program follows the file, applies title/text/
#  set/del/clear commands, and serves the synthesized page over TLS
#  1.2 using $TLS.  The certificate and key are kept in /keydb.
#
implement Gemserve;

include "sys.m";
	sys: Sys;
include "draw.m";
include "daytime.m";
	daytime: Daytime;
include "dial.m";
	dial: Dial;
include "tls.m";
	tls: TLS;

Gemserve: module
{
	init:	fn(nil: ref Draw->Context, args: list of string);
};

CTL:	con "/n/host/gem/ctl";
CERT:	con "/keydb/gemini.cert";
KEY:	con "/keydb/gemini.key";
MAXKEYS:	con 64;

State: adt
{
	title:	string;
	text:	string;
	keys:	array of string;
	vals:	array of string;
	nkeys:	int;
	nctl:	int;
};

st: ref State;
cert: array of byte;
key: array of byte;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	if(sys == nil)
		return;
	daytime = load Daytime Daytime->PATH;
	dial = load Dial Dial->PATH;
	tls = load TLS TLS->PATH;
	if(daytime == nil || dial == nil || tls == nil){
		sys->fprint(sys->fildes(2), "gemserve: cannot load a module: %r\n");
		return;
	}

	st = ref State("gemd", "", nil, nil, 0, 0);
	st.keys = array[MAXKEYS] of string;
	st.vals = array[MAXKEYS] of string;
	for(i := 0; i < MAXKEYS; i++){
		st.keys[i] = "";
		st.vals[i] = "";
	}

	err := loadcert();
	if(err != nil){
		sys->fprint(sys->fildes(2), "gemserve: %s\n", err);
		return;
	}
	sys->print("gemserve: cert %d bytes, key %d bytes\n",
		len cert, len key);

	c := dial->announce("tcp!*!1965");
	if(c == nil){
		sys->fprint(sys->fildes(2), "gemserve: announce: %r\n");
		return;
	}
	sys->print("gemserve: listening on tcp!*!1965\n");

	spawn control(CTL);
	for(;;){
		srv := dial->listen(c);
		if(srv == nil)
			continue;
		fd := dial->accept(srv);
		if(fd == nil)
			continue;
		serve(fd);
		fd = nil;
	}

}

# ---- certificate ------------------------------------------------------

loadcert(): string
{
	cfd := sys->open(CERT, Sys->OREAD);
	if(cfd != nil){
		cert = readfile(CERT);
		key = readfile(KEY);
		if(cert == nil || key == nil || len key != 32)
			return "bad certificate in /keydb";
		return nil;
	}

	now := daytime->now();
	c: array of byte;
	k: array of byte;
	e: string;
	(c, k, e) = tls->certgen("gemd",
		utc(now - 3600),
		utc(now + 10*365*24*3600));
	if(e != nil)
		return e;
	if(writefile(CERT, c, 8r600) < 0 ||
	   writefile(KEY, k, 8r600) < 0)
		return "cannot write /keydb certificate";
	cert = c;
	key = k;
	return nil;
}

utc(t: int): string
{
	tm := daytime->gmt(t);
	return sys->sprint("%02d%02d%02d%02d%02d%02dZ",
		tm.year % 100, tm.mon + 1, tm.mday,
		tm.hour, tm.min, tm.sec);
}

readfile(path: string): array of byte
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return nil;
	buf := array[4096] of byte;
	n := sys->read(fd, buf, len buf);
	fd = nil;
	if(n <= 0)
		return nil;
	return buf[0:n];
}

writefile(path: string, data: array of byte, perm: int): int
{
	fd := sys->create(path, Sys->OWRITE, perm);
	if(fd == nil)
		return -1;
	if(sys->write(fd, data, len data) != len data){
		fd = nil;
		return -1;
	}
	fd = nil;
	return 0;
}

# ---- control file -----------------------------------------------------

control(path: string)
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil){
		sys->fprint(sys->fildes(2), "gemserve: open %s: %r\n", path);
		return;
	}
	off := big 0;
	partial := "";
	for(;;){
		buf := array[4096] of byte;
		n := sys->pread(fd, buf, len buf, off);
		if(n > 0){
			off += big n;
			partial += string buf[0:n];
			(ls, np) := lines(partial);
			partial = np;
			for(; ls != nil; ls = tl ls)
				apply(hd ls);
		}
		sys->sleep(250);
	}
}

# Split complete lines, returning them and the trailing partial line.
lines(s: string): (list of string, string)
{
	out: list of string;
	start := 0;
	for(i := 0; i < len s; i++){
		if(s[i] == '\n'){
			line := s[start:i];
			if(len line > 0 && line[len line - 1] == '\r')
				line = line[0:len line - 1];
			out = line :: out;
			start = i + 1;
		}
	}
	rev: list of string;
	for(; out != nil; out = tl out)
		rev = hd out :: rev;
	return (rev, s[start:]);
}

apply(line: string)
{
	if(line == "")
		return;
	cmd := line;
	rest := "";
	for(i := 0; i < len line; i++)
		if(line[i] == ' '){
			cmd = line[0:i];
			rest = line[i+1:];
			break;
		}
	while(len rest > 0 && (rest[0] == ' ' || rest[0] == '\t'))
		rest = rest[1:];

	case cmd {
	"title" =>
		st.title = rest;
	"text" =>
		st.text += rest + "\n";
	"set" =>
		(k, v) := split2(rest);
		if(k != "")
			setkey(k, v);
	"del" =>
		delkey(rest);
	"clear" =>
		clear();
	}
	st.nctl++;
}

split2(s: string): (string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] == ' '){
			v := s[i+1:];
			while(len v > 0 && (v[0] == ' ' || v[0] == '\t'))
				v = v[1:];
			return (s[0:i], v);
		}
	return (s, "");
}

setkey(k, v: string)
{
	for(i := 0; i < st.nkeys; i++)
		if(st.keys[i] == k){
			st.vals[i] = v;
			return;
		}
	if(st.nkeys < MAXKEYS){
		st.keys[st.nkeys] = k;
		st.vals[st.nkeys] = v;
		st.nkeys++;
	}
}

delkey(k: string)
{
	for(i := 0; i < st.nkeys; i++)
		if(st.keys[i] == k){
			for(j := i; j < st.nkeys - 1; j++){
				st.keys[j] = st.keys[j+1];
				st.vals[j] = st.vals[j+1];
			}
			st.nkeys--;
			return;
		}
}

clear()
{
	st.title = "gemd";
	st.text = "";
	st.nkeys = 0;
}

# ---- page -------------------------------------------------------------

page(): string
{
	s := "# " + st.title + "\n\n";
	if(st.text != "")
		s += st.text + "\n";
	s += "## data\n\n";
	if(st.nkeys == 0)
		s += "no data\n";
	for(i := 0; i < st.nkeys; i++)
		s += st.keys[i] + ": " + st.vals[i] + "\n";
	s += "\n## server\n\nctl writes " + string st.nctl + "\n";
	return s;
}

serve(fd: ref Sys->FD)
{
	(h, err) := tls->accept(fd.fd, cert, key);
	if(h < 0){
		sys->fprint(sys->fildes(2), "gemserve: tls: %s\n", err);
		return;
	}
	buf := array[1024] of byte;
	n := tls->read(h, buf);
	if(n > 0)
		sys->print("gemserve: request %s\n", string buf[0:n]);
	resp := "20 text/gemini\r\n" + page();
	tls->write(h, array of byte resp);
	tls->close(h);
}
