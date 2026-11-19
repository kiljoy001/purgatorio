#
#  gemserve -- a Gemini server driven by a 9P control file.
#
#  The control plane is an append-only file on /n/host (a 9P mount of
#  the host tree).  This program follows the file, applies title/text/
#  set/del/clear commands, and serves the synthesized page over TLS.
#
#  Each connection is peeked at before the handshake: TLS 1.3
#  (supported_versions 0x0304) is handled in Dis using $TLS's
#  gcmseal/gcmopen/sign primitives and $Mono's X25519, while anything
#  else is replayed into the kernel's BearSSL TLS 1.2 session via
#  $TLS->acceptpre.  The certificate and key are kept in /keydb.
#
#  Connections are handled one process each, with a fixed number of
#  slots: when every slot is busy the listener stops accepting, so the
#  kernel backlog provides backpressure instead of unbounded memory.
#  A watchdog per connection hangs it up after CONNTIMEOUT, which also
#  bounds a client that connects and never finishes the handshake.
#  The control state is updated by its own process and read under a
#  one-token channel lock, so a page cannot be built from a half-applied
#  ctl line.
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
include "ipints.m";
include "crypt.m";
	crypt: Crypt;
include "mono.m";
	mono: Mono;

Gemserve: module
{
	init:	fn(nil: ref Draw->Context, args: list of string);
};

Mount: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

CTL:	con "/n/host/gem/ctl";
CERT:	con "/keydb/gemini.cert";
KEY:	con "/keydb/gemini.key";
DROP:	con "/n/host/dis";	# host drop directory for .dis files
LOCAL:	con "/dislocal";	# writable overlay bound after /dis
STORE:	con "/n/store";		# default 9P mount point
SCALE:	con "#g/scale";		# display scale device
NSLOT:	con 32;			# concurrent connections, including the accept
HSTIMEOUT:	con 10000;	# milliseconds for the handshake
REQTIMEOUT:	con 10000;	# milliseconds for request and response
MAXPEER:	con 64;		# tracked peer addresses
PEERLIMIT:	con 8;		# concurrent connections from one address

State: adt
{
	msg:	string;
	scale:	int;
	mountsrc:	string;
	mountpath:	string;
};

st: ref State;
cert: array of byte;
key: array of byte;
Peek: adt
{
	raw:	array of byte;		# bytes read while peeking
	hs:	array of byte;		# handshake payload from them
};

Watch: adt
{
	done:	int;
	deadline: int;		# absolute millisecond deadline, movable
};

sem: chan of int;		# connection slots
slock: chan of int;		# one-token lock for st
plock: chan of int;		# one-token lock for the peer table
paddr:	array of string;
pcnt:	array of int;		# connections currently open per address
plast:	array of int;		# last accepted, for eviction
plog:	array of int;		# last "too many" message

# Byte readers and builders used by the TLS 1.3 path.
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

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	if(sys == nil)
		return;
	daytime = load Daytime Daytime->PATH;
	dial = load Dial Dial->PATH;
	tls = load TLS TLS->PATH;
	crypt = load Crypt Crypt->PATH;
	mono = load Mono Mono->PATH;
	if(daytime == nil || dial == nil || tls == nil ||
	   crypt == nil || mono == nil){
		sys->fprint(sys->fildes(2), "gemserve: cannot load a module: %r\n");
		return;
	}

	st = ref State("", 100, "", "");
	st.scale = readscale();
	i: int;
	sem = chan[NSLOT] of int;
	for(i = 0; i < NSLOT; i++)
		sem <-= 1;
	slock = chan[1] of int;
	slock <-= 1;
	plock = chan[1] of int;
	plock <-= 1;
	paddr = array[MAXPEER] of string;
	pcnt = array[MAXPEER] of int;
	plast = array[MAXPEER] of int;
	plog = array[MAXPEER] of int;
	# A fresh Limbo array is not guaranteed to be zeroed.
	for(i = 0; i < MAXPEER; i++){
		paddr[i] = "";
		pcnt[i] = 0;
		plast[i] = 0;
		plog[i] = 0;
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
		# Take a slot before waiting for a call.  When all are busy
		# no accept is posted, which leaves the queue in the kernel.
		<-sem;
		srv := dial->listen(c);
		if(srv == nil){
			sem <-= 1;
			sys->sleep(100);
			continue;
		}
		fd := dial->accept(srv);
		if(fd == nil){
			sem <-= 1;
			sys->sleep(100);
			continue;
		}
		path := sys->fd2path(fd);
		peer := "";
		if(path != nil)
			peer = remoteof(path);
		key := peerhost(peer);
		if(!peeradd(key)){
			sys->fprint(sys->fildes(2),
				"gemserve: too many connections from %s\n", peer);
			fd = nil;
			sem <-= 1;
			continue;
		}
		spawn handle(fd, path, key);
	}

}

# handle owns one connection.  The watchdog is told when the work is
# done, and the worker waits for its acknowledgement before closing the
# descriptor, so the watchdog can never hang up a reused conversation.
handle(fd: ref Sys->FD, path: string, peer: string)
{
	w := ref Watch;
	w.done = 0;
	w.deadline = sys->millisec() + HSTIMEOUT;
	ack := chan[1] of int;
	timed := 0;
	if(path != nil){
		spawn watchdog(path, w, ack);
		timed = 1;
	}
	{
		p := ref Peek;
		p.raw = nil;
		p.hs = nil;
		k := peekhello(fd, p);
		if(k == 1)
			serve13(fd, p.hs, w);
		else if(k == 0)
			serve12(fd, p.raw, w);
	} exception e {
	"*" =>
		sys->fprint(sys->fildes(2), "gemserve: connection: %s\n", e);
	}
	w.done = 1;
	if(timed)
		<-ack;
	fd = nil;
	peerdel(peer);
	sem <-= 1;
}

# The deadline is read every pass so the worker can shorten it to the
# request budget once the handshake is done.
watchdog(path: string, w: ref Watch, ack: chan of int)
{
	for(;;){
		now := sys->millisec();
		if(w.done || now >= w.deadline)
			break;
		left := w.deadline - now;
		s := 100;
		if(left < s)
			s = left;
		sys->sleep(s);
	}
	if(w.done == 0){
		peer := remoteof(path);
		if(peer == "")
			sys->fprint(sys->fildes(2), "gemserve: timeout\n");
		else
			sys->fprint(sys->fildes(2),
				"gemserve: timeout from %s\n", peer);
		hangupctl(path);
	}
	ack <-= 1;
}

# ---- peer limits ------------------------------------------------------

# peeradd accounts for one connection from a.  A peer that already has
# PEERLIMIT connections is refused, and so is a new address when the
# table has no free or evictable slot.  The check is concurrency, not a
# rate, so a client that reconnects after closing is not penalised.
peeradd(a: string): int
{
	if(a == "")
		return 1;
	<-plock;
	now := sys->millisec();
	slot := -1;
	for(i := 0; i < MAXPEER; i++){
		if(paddr[i] == a){
			slot = i;
			break;
		}
		if(slot < 0 && pcnt[i] == 0)
			slot = i;
	}
	if(slot < 0){
		plock <-= 1;
		return 0;
	}
	if(pcnt[slot] >= PEERLIMIT){
		logit := 0;
		if(now - plog[slot] > 5000){
			plog[slot] = now;
			logit = 1;
		}
		plock <-= 1;
		if(logit)
			sys->fprint(sys->fildes(2),
				"gemserve: peer limit reached for %s\n", a);
		return 0;
	}
	paddr[slot] = a;
	pcnt[slot]++;
	plast[slot] = now;
	plock <-= 1;
	return 1;
}

peerdel(a: string)
{
	if(a == "")
		return;
	<-plock;
	for(i := 0; i < MAXPEER; i++)
		if(paddr[i] == a){
			if(pcnt[i] > 0)
				pcnt[i]--;
			break;
		}
	plock <-= 1;
}

# The conversation directory is /net/tcp/N; ctl and remote live there.
dirpath(p: string): string
{
	i := len p - 1;
	while(i > 0 && p[i] != '/')
		i--;
	if(i <= 0)
		return "";
	return p[0:i];
}

hangupctl(path: string)
{
	d := dirpath(path);
	if(d == "")
		return;
	fd := sys->open(d + "/ctl", Sys->OWRITE);
	if(fd == nil)
		return;
	sys->fprint(fd, "hangup");
	fd = nil;
}

# The remote file is addr!port; limits are per address, not per
# connection, so drop the port.
peerhost(s: string): string
{
	for(i := 0; i < len s; i++)
		if(s[i] == '!')
			return s[0:i];
	return s;
}

remoteof(path: string): string
{
	d := dirpath(path);
	if(d == "")
		return "";
	b := readfile(d + "/remote");
	if(b == nil)
		return "";
	s := string b;
	while(len s > 0 && (s[len s-1] == '\n' || s[len s-1] == ' '))
		s = s[0:len s-1];
	return s;
}

# One token in slock serialises the control state.
lock()
{
	<-slock;
}

unlock()
{
	slock <-= 1;
}

# ---- certificate ------------------------------------------------------

loadcert(): string
{
	cfd := sys->open(CERT, Sys->OREAD);
	if(cfd != nil){
		cfd = nil;
		cert = readfile(CERT);
		key = readfile(KEY);
		if(cert != nil && key != nil && len key == 32)
			return nil;
		# An interrupted first start can leave half a pair behind;
		# mint a fresh one instead of staying down.
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
	# Key first: a certificate without its key is unusable, and the
	# check above re-mints the pair.
	if(writefile(KEY, k, 8r600) < 0 ||
	   writefile(CERT, c, 8r600) < 0)
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
	(ok, d) := sys->stat(path);
	if(ok < 0 || d.length <= big 0 || d.length > big (16<<20))
		return nil;
	data := array[int d.length] of byte;
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return nil;
	off := 0;
	while(off < len data){
		n := sys->read(fd, data[off:], len data - off);
		if(n <= 0)
			break;
		off += n;
	}
	fd = nil;
	if(off != len data)
		return nil;
	return data;
}

writefile(path: string, data: array of byte, perm: int): int
{
	fd := sys->create(path, Sys->OWRITE, perm);
	if(fd == nil)
		return -1;
	off := 0;
	while(off < len data){
		n := sys->write(fd, data[off:], len data - off);
		if(n <= 0){
			fd = nil;
			return -1;
		}
		off += n;
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
		if(line[i] == ' ' || line[i] == '\t'){
			cmd = line[0:i];
			rest = line[i+1:];
			break;
		}
	while(len rest > 0 && (rest[0] == ' ' || rest[0] == '\t'))
		rest = rest[1:];

	msg := "";
	case cmd {
	"scale" =>
		v := int trimnl(rest);
		e := "";
		if(v < 25 || v > 400)
			e = "scale: want 25..400";
		else
			e = setscale(v);
		if(e != "")
			msg = e;
		else{
			lock();
			st.scale = v;
			unlock();
		}
	"install" =>
		# Installing and mounting can wait on another file server;
		# keep the page available while they do.
		msg = install(rest);
	"mount" =>
		(src, path) := split2(rest);
		msg = mountone(src, path);
	"unmount" =>
		msg = unmountone(rest);
	"clear" =>
		msg = "";
	}
	lock();
	st.msg = msg;
	unlock();
}

split2(s: string): (string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] == ' ' || s[i] == '\t'){
			v := s[i+1:];
			while(len v > 0 && (v[0] == ' ' || v[0] == '\t'))
				v = v[1:];
			return (s[0:i], v);
		}
	return (s, "");
}

# ---- display scale ----------------------------------------------------

readscale(): int
{
	fd := sys->open(SCALE, Sys->OREAD);
	if(fd == nil)
		return 100;
	b := array[32] of byte;
	n := sys->read(fd, b, len b);
	fd = nil;
	if(n <= 0)
		return 100;
	s := string b[0:n];
	v := 0;
	for(i := 0; i < len s; i++){
		if(s[i] < '0' || s[i] > '9')
			break;
		v = v * 10 + (s[i] - '0');
	}
	if(v < 25 || v > 400)
		return 100;
	return v;
}

setscale(v: int): string
{
	fd := sys->open(SCALE, Sys->OWRITE);
	if(fd == nil)
		return sys->sprint("scale: %r");
	if(sys->fprint(fd, "scale %d", v) < 0){
		fd = nil;
		return sys->sprint("scale: %r");
	}
	fd = nil;
	return "";
}

# ---- programs ---------------------------------------------------------

install(name: string): string
{
	name = trimnl(name);
	if(name == "" || contains(name, "/") || name == "." || name == "..")
		return "install: bad name";
	data := readfile(DROP + "/" + name);
	if(data == nil)
		return "install: " + DROP + "/" + name + ": not found";
	if(writefile(LOCAL + "/" + name, data, 8r755) < 0)
		return sys->sprint("install: %r");
	return "";
}

# ---- storage ----------------------------------------------------------

mountone(src, path: string): string
{
	src = trimnl(src);
	path = trimnl(path);
	if(src == "")
		return "mount: no source";
	if(path == "")
		path = STORE;
	if(!prefix(src, "tcp!") && !prefix(src, "udp!") &&
	   !prefix(src, "unix!") && src[0] != '#' && src[0] != '/')
		src = "tcp!" + src;
	if(mkdirp(path) < 0)
		return "mount: cannot create " + path;
	sys->unmount(nil, path);	# replace an existing mount
	m := load Mount "/dis/mount.dis";
	if(m == nil)
		return "mount: cannot load /dis/mount.dis";
	{
		m->init(nil, "mount" :: "-A" :: src :: path :: nil);
	} exception e {
	"*" =>
		return "mount: " + e;
	}
	lock();
	st.mountsrc = src;
	st.mountpath = path;
	unlock();
	return "";
}

unmountone(path: string): string
{
	path = trimnl(path);
	lock();
	if(path == "")
		path = st.mountpath;
	unlock();
	if(path == "")
		path = STORE;
	if(sys->unmount(nil, path) < 0)
		return sys->sprint("unmount: %r");
	lock();
	if(path == st.mountpath){
		st.mountsrc = "";
		st.mountpath = "";
	}
	unlock();
	return "";
}

# ---- page -------------------------------------------------------------

page(): string
{
	lock();
	s := "# 9vm\n";
	if(st.msg != "")
		s += "\n" + st.msg + "\n";
	s += "\n=> /scale scale " + string st.scale + "%\n";

	s += "\n## programs\n";
	fd := sys->open(DROP, Sys->OREAD);
	found := 0;
	if(fd != nil){
		for(;;){
			(n, d) := sys->dirread(fd);
			if(n <= 0)
				break;
			for(i := 0; i < n; i++){
				nm := d[i].name;
				if(!hassuffix(nm, ".dis"))
					continue;
				found++;
				label := nm + " (" + sys->sprint("%bd", d[i].length) + "B";
				(ok, nil) := sys->stat(LOCAL + "/" + nm);
				if(ok >= 0)
					label += ", installed";
				s += "=> /dis/" + nm + " " + label + ")\n";
			}
		}
		fd = nil;
	}
	if(found == 0)
		s += "none\n";

	s += "\n## storage\n";
	if(st.mountpath == "")
		s += "none\n";
	else
		s += st.mountsrc + " on " + st.mountpath + "\n";
	unlock();
	return s;
}

# ---- content ----------------------------------------------------------

requestpath(req: string): string
{
	s := trimnl(req);
	if(prefix(s, "gemini://")){
		s = s[9:];
		i := 0;
		while(i < len s && s[i] != '/' && s[i] != '?' && s[i] != '\r')
			i++;
		if(i >= len s || s[i] != '/')
			return "/";
		s = s[i:];
	}
	if(!prefix(s, "/"))
		s = "/" + s;
	for(i := 0; i < len s; i++)
		if(s[i] == '\r' || s[i] == '\n'){
			s = s[0:i];
			break;
		}
	return s;
}

# Split a request target into its path and query.
splitquery(s: string): (string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] == '?')
			return (s[0:i], s[i+1:]);
	return (s, "");
}

# A Gemini input reply is usually just the query, but some clients send
# the whole URL back, so accept both.
scalevalue(q: string): int
{
	s := trimnl(q);
	if(prefix(s, "/scale?"))
		s = s[7:];
	else if(prefix(s, "scale?"))
		s = s[6:];
	if(prefix(s, "scale="))
		s = s[6:];
	v := 0;
	if(s == "")
		return 0;
	for(i := 0; i < len s; i++){
		if(s[i] < '0' || s[i] > '9')
			break;
		v = v * 10 + (s[i] - '0');
		if(v > 10000)
			return 0;
	}
	return v;
}

# /dis/NAME is a drop file, for distribution to another node; /scale is
# the one interactive control; anything else is the status page.
content(req: string): (string, array of byte)
{
	(path, q) := splitquery(requestpath(req));

	if(path == "/scale"){
		if(q == ""){
			lock();
			now := st.scale;
			unlock();
			return ("10 " + sys->sprint("scale %d%%", now) + "\r\n", nil);
		}
		v := scalevalue(q);
		if(v < 25 || v > 400)
			return ("59 want 25..400\r\n", nil);
		if((e := setscale(v)) != ""){
			lock();
			st.msg = e;
			unlock();
			return ("40 " + e + "\r\n", nil);
		}
		lock();
		st.scale = v;
		st.msg = "";
		unlock();
		return ("30 /\r\n", nil);
	}

	if(prefix(path, "/dis/")){
		name := path[5:];
		if(name == "" || contains(name, "/") || name == "." || name == "..")
			return ("51 bad request\r\n", nil);
		data := readfile(DROP + "/" + name);
		if(data == nil)
			return ("51 not found\r\n", nil);
		return ("20 application/octet-stream\r\n", data);
	}
	return ("20 text/gemini\r\n", array of byte page());
}

# ---- helpers ----------------------------------------------------------

trimnl(s: string): string
{
	while(len s > 0 && (s[len s-1] == '\n' || s[len s-1] == '\r' ||
			    s[len s-1] == ' ' || s[len s-1] == '\t'))
		s = s[0:len s-1];
	while(len s > 0 && (s[0] == ' ' || s[0] == '\t'))
		s = s[1:];
	return s;
}

prefix(s, p: string): int
{
	if(len s < len p)
		return 0;
	return s[0:len p] == p;
}

hassuffix(s, p: string): int
{
	if(len s < len p)
		return 0;
	return s[len s-len p:] == p;
}

contains(s, sub: string): int
{
	if(len sub == 0)
		return 1;
	for(i := 0; i + len sub <= len s; i++)
		if(s[i:i+len sub] == sub)
			return 1;
	return 0;
}

statok(path: string): int
{
	(ok, nil) := sys->stat(path);
	return ok >= 0;
}

mkdirp(path: string): int
{
	if(path == "" || path == "/")
		return 0;
	if(statok(path))
		return 0;
	i := len path - 1;
	while(i > 0 && path[i] == '/')
		i--;
	while(i > 0 && path[i] != '/')
		i--;
	if(i > 0)
		mkdirp(path[0:i]);
	if(sys->create(path, Sys->OREAD, Sys->DMDIR|8r777) == nil)
		return -1;
	return 0;
}

serve12(fd: ref Sys->FD, pre: array of byte, w: ref Watch)
{
	(h, err) := tls->acceptpre(fd.fd, cert, key, pre);
	if(h < 0){
		sys->fprint(sys->fildes(2), "gemserve: tls: %s\n", err);
		return;
	}
	w.deadline = sys->millisec() + REQTIMEOUT;
	buf := array[1024] of byte;
	n := tls->read(h, buf);
	req := "";
	if(n > 0){
		req = string buf[0:n];
		sys->print("gemserve: (tls1.2) request %s\n", req);
	}
	(hdr, body) := content(requestpath(req));
	resp := cat(array of byte hdr, body);
	tls->write(h, resp);
	tls->close(h);
}

# ---- version peek -----------------------------------------------------

# Read just enough of the connection to tell 1.3 from 1.2, keeping the
# bytes in p.raw (record stream) and p.hs (handshake payload).  Returns
# 1 for TLS 1.3, 0 for anything else, -1 on a broken connection.
peekhello(fd: ref Sys->FD, p: ref Peek): int
{
	raw := array[8192] of byte;
	hs := array[8192] of byte;
	rawn := 0;
	hsn := 0;
	for(rec := 0; rec < 4; rec++){
		h := array[5] of byte;
		if(readn(fd, h, 5) != 5)
			return -1;
		rl := (int h[3] << 8) | int h[4];
		if(rl <= 0 || rl > 4096 || rawn + 5 + rl > len raw || hsn + rl > len hs)
			break;
		d := array[rl] of byte;
		if(readn(fd, d, rl) != rl)
			return -1;
		for(i := 0; i < 5; i++){
			raw[rawn] = h[i];
			rawn++;
		}
		for(i = 0; i < rl; i++){
			raw[rawn] = d[i];
			rawn++;
		}
		if(int h[0] != 22)
			break;
		for(i = 0; i < rl; i++){
			hs[hsn] = d[i];
			hsn++;
		}
		if(hsn >= 4){
			if(int hs[0] != 1)
				break;
			ml := (int hs[1] << 16) | (int hs[2] << 8) | int hs[3];
			if(4 + ml <= hsn)
				break;
		}
	}
	if(rawn == 0)
		return -1;
	p.raw = raw[0:rawn];
	p.hs = hs[0:hsn];
	if(is13(p.hs))
		return 1;
	return 0;
}

# Does this ClientHello offer TLS 1.3?
is13(hs: array of byte): int
{
	if(len hs < 4 || int hs[0] != 1)
		return 0;
	ml := (int hs[1] << 16) | (int hs[2] << 8) | int hs[3];
	if(4 + ml > len hs)
		return 0;
	r := ref Rd(hs, 4 + ml, 4);
	rd16(r);			# legacy_version
	rdbytes(r, 32);			# random
	sl := rd8(r);
	if(sl < 0)
		return 0;
	rdbytes(r, sl);
	cl := rd16(r);
	if(cl < 0)
		return 0;
	rdbytes(r, cl);
	cm := rd8(r);
	if(cm < 0)
		return 0;
	rdbytes(r, cm);
	el := rd16(r);
	if(el < 0)
		return 0;
	exts := rdbytes(r, el);
	if(exts == nil)
		return 0;
	er := ref Rd(exts, len exts, 0);
	while(er.o + 4 <= er.n){
		et := rd16(er);
		eln := rd16(er);
		ed := rdbytes(er, eln);
		if(ed == nil)
			break;
		if(et == 43){
			if(len ed < 1)
				return 0;
			n := int ed[0];
			for(i := 1; i + 1 < 1 + n && i + 1 < len ed; i += 2)
				if((int ed[i] << 8 | int ed[i+1]) == 16r0304)
					return 1;
			return 0;
		}
	}
	return 0;
}

# ---- TLS 1.3 ---------------------------------------------------------

serve13(fd: ref Sys->FD, hello: array of byte, w: ref Watch)
{
	# ---- ClientHello (already read by peekhello) ----
	r := ref Rd(hello, len hello, 0);
	if(rd8(r) != 1){
		sys->print("tls13: no ClientHello\n");
		return;
	}
	ln := rd24(r);
	body := rdbytes(r, ln);
	if(body == nil){
		sys->print("tls13: short ClientHello\n");
		return;
	}
	ch := ref Rd(body, len body, 0);
	rd16(ch);			# legacy_version
	rdbytes(ch, 32);		# random
	sess := rdbytes(ch, rd8(ch));
	cs := rdbytes(ch, rd16(ch));
	rdbytes(ch, rd8(ch));		# compression
	extlen := rd16(ch);
	exts := rdbytes(ch, extlen);

	if(!has1301(cs)){
		alert(fd, 40);
		return;
	}
	clientpub: array of byte;
	gotver := 0;
	gotecdsa := 0;
	er := ref Rd(exts, len exts, 0);
	while(er.o < er.n){
		et := rd16(er);
		el := rd16(er);
		ed := rdbytes(er, el);
		if(ed == nil)
			break;
		case et {
		43 =>	# supported_versions
			gotver = hasver(ed, 16r0304);
		51 =>	# key_share
			clientpub = findgroup(ed, 29);
		13 =>	# signature_algorithms
			gotecdsa = hassig(ed, 16r0403);
		}
	}
	if(!gotver || !gotecdsa || clientpub == nil){
		sys->print("tls13: no 1.3/x25519/ecdsa\n");
		alert(fd, 40);
		return;
	}

	# ---- ServerHello ----
	sk := randombytes(32);
	if(sk == nil){
		alert(fd, 80);
		return;
	}
	spub := mono->xpublic(sk);
	if(spub == nil){
		alert(fd, 80);
		return;
	}

	shb := ref Bo(array[256] of byte, 0);
	b16(shb, 16r0303);
	bpa(shb, randombytes(32));
	bp(shb, len sess);
	bpa(shb, sess);
	b16(shb, 16r1301);
	bp(shb, 0);
	ext := ref Bo(array[128] of byte, 0);
	b16(ext, 43); b16(ext, 2); b16(ext, 16r0304);
	b16(ext, 51); b16(ext, 36); b16(ext, 29); b16(ext, 32); bpa(ext, spub);
	b16(shb, ext.n);
	bpa(shb, ext.d[0:ext.n]);
	sh := hsmsg(2, shb.d[0:shb.n]);

	# transcript = ClientHello message (type+len+body) || ServerHello
	chmsg := hsmsg(1, body);
	tr := array[16384] of byte;
	tlen := 0;
	tlen = tapp(tr, tlen, chmsg);
	tlen = tapp(tr, tlen, sh);

	if(writeall(fd, hsrec(sh)) < 0){
		sys->print("tls13: write SH: %r\n");
		return;
	}
	ccs := array[6] of byte;
	ccs[0] = byte 20; ccs[1] = byte 3; ccs[2] = byte 3;
	ccs[3] = byte 0; ccs[4] = byte 1; ccs[5] = byte 1;
	writeall(fd, ccs);

	# ---- key schedule ----
	shared := mono->x25519(sk, clientpub);
	if(shared == nil){
		alert(fd, 40);
		return;
	}
	for(i := 0; i < 32; i++)
		if(shared[i] != byte 0)
			break;
	if(i == 32){
		alert(fd, 40);
		return;
	}
	empty := array[0] of byte;
	zeros := array[32] of byte;
	for(i = 0; i < 32; i++)
		zeros[i] = byte 0;
	emptyhash := sha256(empty);
	early := hkdfextract(zeros, zeros);
	derived := derivsec(early, "derived", emptyhash);
	hssec := hkdfextract(derived, shared);
	th := sha256(tr[0:tlen]);
	chs := derivsec(hssec, "c hs traffic", th);
	shs := derivsec(hssec, "s hs traffic", th);
	chsk := hkexp(chs, "key", empty, 16);
	chsiv := hkexp(chs, "iv", empty, 12);
	shsk := hkexp(shs, "key", empty, 16);
	shsiv := hkexp(shs, "iv", empty, 12);

	# ---- encrypted flight ----
	eeb := ref Bo(array[8] of byte, 0);
	b16(eeb, 0);
	ee := hsmsg(8, eeb.d[0:eeb.n]);
	tlen = tapp(tr, tlen, ee);

	certb := ref Bo(array[1024] of byte, 0);
	bp(certb, 0);
	entry := ref Bo(array[1024] of byte, 0);
	b24(entry, len cert);
	bpa(entry, cert);
	b16(entry, 0);
	b24(certb, entry.n);
	bpa(certb, entry.d[0:entry.n]);
	cm := hsmsg(11, certb.d[0:certb.n]);
	tlen = tapp(tr, tlen, cm);

	thcv := sha256(tr[0:tlen]);
	ctx := "TLS 1.3, server CertificateVerify";
	cvmsg := ref Bo(array[512] of byte, 0);
	for(i = 0; i < 64; i++)
		bp(cvmsg, 16r20);
	bpa(cvmsg, array of byte ctx);
	bp(cvmsg, 0);
	bpa(cvmsg, thcv);
	sig := tls->sign(key, cvmsg.d[0:cvmsg.n]);
	if(sig == nil){
		alert(fd, 80);
		return;
	}
	cvb := ref Bo(array[512] of byte, 0);
	b16(cvb, 16r0403);
	b16(cvb, len sig);
	bpa(cvb, sig);
	cv := hsmsg(15, cvb.d[0:cvb.n]);
	tlen = tapp(tr, tlen, cv);

	thfin := sha256(tr[0:tlen]);
	fk := hkexp(shs, "finished", empty, 32);
	fv := hmac(fk, thfin);
	fin := hsmsg(20, fv);
	tlen = tapp(tr, tlen, fin);

	flight := cat(cat(ee, cm), cat(cv, fin));

	# application secrets use the transcript through server Finished
	derived2 := derivsec(hssec, "derived", emptyhash);
	master := hkdfextract(derived2, zeros);
	thapp := sha256(tr[0:tlen]);
	(rec, err) := sealrec(fd, 22, flight, shsk, shsiv, 0);
	if(err != nil){
		sys->print("tls13: seal flight: %s\n", err);
		return;
	}
	if(writeall(fd, rec) < 0)
		return;

	# ---- client Finished ----
	ctyp: int;
	cdata: array of byte;
	e: string;
	(ctyp, cdata, e) = readenc(fd, chsk, chsiv, 0);
	if(e != nil){
		sys->print("tls13: client finished: %s\n", e);
		return;
	}
	if(ctyp != 22){
		sys->print("tls13: client sent type %d, want handshake\n", ctyp);
		return;
	}
	cr := ref Rd(cdata, len cdata, 0);
	if(rd8(cr) != 20){
		sys->print("tls13: no client Finished\n");
		return;
	}
	cln := rd24(cr);
	cfin := rdbytes(cr, cln);
	if(cfin == nil){
		sys->print("tls13: short client Finished\n");
		return;
	}
	cfk := hkexp(chs, "finished", empty, 32);
	want := hmac(cfk, sha256(tr[0:tlen]));
	if(!eq(want, cfin)){
		sys->print("tls13: bad client Finished\n");
		alert(fd, 20);
		return;
	}
	tlen = tapp(tr, tlen, hsmsg(20, cfin));

	# The handshake is done; from here the request and response get
	# their own budget.
	w.deadline = sys->millisec() + REQTIMEOUT;

	# ---- application keys ----
	capp := derivsec(master, "c ap traffic", thapp);
	sapp := derivsec(master, "s ap traffic", thapp);
	cakk := hkexp(capp, "key", empty, 16);
	caiv := hkexp(capp, "iv", empty, 12);
	sakk := hkexp(sapp, "key", empty, 16);
	saiv := hkexp(sapp, "iv", empty, 12);

	atyp: int;
	adata: array of byte;
	(atyp, adata, e) = readenc(fd, cakk, caiv, 0);
	if(e != nil){
		sys->print("tls13: app read: %s\n", e);
		return;
	}
	if(atyp != 23){
		sys->print("tls13: inner type %d, want app\n", atyp);
		return;
	}
	if(len adata > 0)
		sys->print("gemserve: (tls1.3) request %s\n", string adata);
	(hdr, cbody) := content(requestpath(string adata));
	resp := cat(array of byte hdr, cbody);
	rrec: array of byte;
	(rrec, err) = sealrec(fd, 23, resp, sakk, saiv, 0);
	if(err != nil)
		return;
	writeall(fd, rrec);

	# close_notify, so the client sees a clean end of stream
	cn := array[2] of byte;
	cn[0] = byte 1;
	cn[1] = byte 0;
	(rrec, err) = sealrec(fd, 21, cn, sakk, saiv, 1);
	if(err == nil)
		writeall(fd, rrec);
}


# ---- records ---------------------------------------------------------

hsrec(msg: array of byte): array of byte
{
	b := ref Bo(array[16384] of byte, 0);
	bp(b, 22);
	b16(b, 16r0303);
	b16(b, len msg);
	bpa(b, msg);
	return b.d[0:b.n];
}

sealrec(fd: ref Sys->FD, inner: int, data: array of byte,
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


readenc(fd: ref Sys->FD, key, iv: array of byte, seq: int): (int, array of byte, string)
{
	h := array[5] of byte;
	for(;;){
		if(readn(fd, h, 5) != 5)
			return (-1, nil, "short record header");
		n := (int h[3] << 8) | int h[4];
		if(n <= 0 || n > 16384)
			return (-1, nil, "bad record length");
		d := array[n] of byte;
		if(readn(fd, d, n) != n)
			return (-1, nil, "short record");
		if(int h[0] == 20)	# compatibility CCS
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
	# XOR the sequence number, big-endian, into the last four
	# bytes.  Shifts of 32 or more are undefined here, so a session
	# would have to send 2^32 records before this wraps.
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

has1301(cs: array of byte): int
{
	for(i := 0; i + 1 < len cs; i += 2)
		if(int cs[i] == 16r13 && int cs[i+1] == 1)
			return 1;
	return 0;
}

hasver(d: array of byte, v: int): int
{
	if(len d < 3)
		return 0;
	n := int d[0];
	for(i := 0; i < n; i += 2)
		if(i + 1 < len d && ((int d[1+i] << 8) | int d[2+i]) == v)
			return 1;
	return 0;
}

hassig(d: array of byte, s: int): int
{
	if(len d < 2)
		return 0;
	n := (int d[0] << 8) | int d[1];
	for(i := 0; i + 1 < n && i + 3 < len d; i += 2)
		if(((int d[2+i] << 8) | int d[3+i]) == s)
			return 1;
	return 0;
}

findgroup(d: array of byte, g: int): array of byte
{
	if(len d < 2)
		return nil;
	n := (int d[0] << 8) | int d[1];
	o := 2;
	while(o + 4 <= n + 2 && o + 4 <= len d){
		grp := (int d[o] << 8) | int d[o+1];
		kl := (int d[o+2] << 8) | int d[o+3];
		if(o + 4 + kl > len d)
			break;
		if(grp == g)
			return d[o+4:o+4+kl];
		o += 4 + kl;
	}
	return nil;
}

alert(fd: ref Sys->FD, desc: int)
{
	a := array[7] of byte;
	a[0] = byte 21;
	a[1] = byte 3;
	a[2] = byte 3;
	a[3] = byte 0;
	a[4] = byte 2;
	a[5] = byte 2;
	a[6] = byte desc;
	writeall(fd, a);
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

# /dev/random accumulates a byte every few clock ticks (about 52 ms
# here), so a 32-byte read per handshake would cost seconds.  Ephemeral
# keys and paddings come from the kernel's fast X9.17 generator, which
# is seeded once from /dev/random; long-term keys still use /dev/random.
randombytes(n: int): array of byte
{
	fd := sys->open("/dev/notquiterandom", Sys->OREAD);
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
