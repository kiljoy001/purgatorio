#
#  timed -- wall-clock service: boot source, SNTP discipline, status.
#
#  Two clocks:
#    wall      /dev/time, microseconds since the epoch, settable
#    monotonic sys->millisec(), milliseconds since boot, never set
#
#  timed reads a coarse time at boot (the host's epoch on 9vm), then
#  queries SNTP servers: -s options, /lib/ndb/time, or the public
#  anycast defaults.  It steps /dev/time when the offset is large.  It publishes ordinary files in a directory (default
#  /n/time):
#
#    status   source, sync state, offset, delay, stratum, last sync,
#             and a "now" snapshot taken when it was written
#
#  Files rather than file2chan on purpose: a file2chan directory does not
#  survive the shell's FORKNS, while a plain file is visible in every
#  namespace that shares the root.
#
implement Timed;

include "sys.m";
	sys: Sys;
include "draw.m";
include "dial.m";
	dial: Dial;

Timed: module
{
	init:	fn(nil: ref Draw->Context, args: list of string);
};

DIR:	con "/n/time";
NDB:	con "/lib/ndb/time";
HOSTTIME: con "/n/host/time";
FLOOR:	con big 1577836800000000;	# 2020-01-01, unix us
STEP:	con big 1000000;		# step when |offset| exceeds 1s
NTPDELTA: con big 2208988800;		# 1900 -> 1970, seconds

St: adt
{
	dir:	string;
	servers: list of string;
	server:	string;
	interval: int;		# seconds
	synced: int;
	source:	string;
	offset:	big;		# last measured, microseconds
	delay:	big;
	stratum: int;
	last:	big;		# unix seconds of last good sync
};

st: ref St;
busy: int;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	dial = load Dial Dial->PATH;
	if(dial == nil){
		sys->print("timed: cannot load dial: %r\n");
		return;
	}
	st = ref St(DIR, nil, "", 900, 0, "", big 0, big 0, 0, big 0);
	if(args != nil)
		args = tl args;
	for(; args != nil; args = tl args){
		a := hd args;
		case a {
		"-d" =>
			args = tl args;
			if(args != nil)
				st.dir = hd args;
		"-s" =>
			args = tl args;
			if(args != nil)
				addserver(hd args);
		"-i" =>
			args = tl args;
			if(args != nil)
				st.interval = int hd args;
		}
	}
	if(st.servers == nil)
		readndb();
	if(st.servers == nil){
		# Public anycast servers, by address: the guest may not have a
		# resolver yet.  Cloudflare, Google (leap-smeared) and NIST.
		addserver("162.159.200.1");
		addserver("216.239.35.0");
		addserver("132.163.96.1");
	}
	if(mkdir(st.dir) < 0){
		sys->print("timed: cannot create %s: %r\n", st.dir);
		return;
	}

	# A coarse source first: on 9vm the host writes its epoch into the
	# 9P tree, and the kernel has no RTC.
	cur := readtime();
	if(cur >= FLOOR){
		st.source = "host";
		st.synced = 1;
		st.last = cur / big 1000000;
	}else{
		h := hosttime();
		if(h > big 1577836800){
			if(settime(h * big 1000000) == nil){
				st.source = "host";
				st.synced = 1;
				st.last = h;
				sys->print("timed: clock set from host to %bd\n", h);
			}
		}
	}

	for(;;){
		if(st.servers != nil && !busy)
			spawn dosync();
		publish();
		sys->sleep(st.interval * 1000);
	}
}

# ---- state ------------------------------------------------------------

addserver(s: string)
{
	if(s == "")
		return;
	for(l := st.servers; l != nil; l = tl l)
		if(hd l == s)
			return;
	st.servers = s :: st.servers;
	if(st.server == "")
		st.server = s;
}

readndb()
{
	fd := sys->open(NDB, Sys->OREAD);
	if(fd == nil)
		return;
	buf := array[4096] of byte;
	n := sys->read(fd, buf, len buf);
	fd = nil;
	if(n <= 0)
		return;
	(nil, lines) := sys->tokenize(string buf[0:n], "\n");
	for(l := lines; l != nil; l = tl l){
		line := hd l;
		if(len line > 5 && line[0:5] == "sntp=")
			addserver(line[5:]);
	}
}

status(): string
{
	cur := readtime();
	return sys->sprint("source=%s\nsynced=%d\nverified=%d\nserver=%s\noffset_us=%bd\ndelay_us=%bd\nstratum=%d\nlast=%bd\nnow=%bd\nmono=%d\n",
		st.source, st.synced, (st.source == "sntp"), st.server,
		st.offset, st.delay, st.stratum, st.last, cur, sys->millisec());
}

# ---- SNTP -------------------------------------------------------------


# The query runs in its own process so a blackholed server cannot
# stall the service.  A read that never returns leaves this process
# blocked, busy set, and no further attempts until restart: the host
# clock remains and status keeps being published.
dosync()
{
	if(busy)
		return;
	busy = 1;
	for(l := st.servers; l != nil; l = tl l){
		srv := hd l;
		(off, del, stratum, e) := sntp1(srv);
		if(e != nil){
			sys->print("timed: %s: %s\n", srv, e);
			continue;
		}
		cur := readtime();
		st.offset = off;
		st.delay = del;
		st.stratum = stratum;
		st.server = srv;
		if(cur < FLOOR || abs(off) > STEP ||
		   !st.synced || st.source != "sntp"){
			e = settime(cur + off);
			if(e != nil){
				sys->print("timed: set: %s\n", e);
				continue;
			}
			st.source = "sntp";
			st.synced = 1;
			sys->print("timed: %s: stepped %bd us (delay %bd)\n",
				srv, off, del);
		}else{
			sys->print("timed: %s: offset %bd us below step threshold\n",
				srv, off);
		}
		st.last = (cur + off) / big 1000000;
		break;
	}
	busy = 0;
}

sntp1(server: string): (big, big, int, string)
{
	c := dial->dial("udp!" + server + "!123", nil);
	if(c == nil)
		return (big 0, big 0, 0, sys->sprint("dial: %r"));
	fd := c.dfd;
	if(fd == nil)
		fd = sys->open(c.dir + "/data", Sys->ORDWR);
	if(fd == nil)
		return (big 0, big 0, 0, sys->sprint("open: %r"));
	t1 := readtime();
	req := array[48] of byte;
	req[0] = byte 16r23;		# LI 0, version 4, client
	putntp(req, 40, t1);
	if(sys->write(fd, req, len req) != len req)
		return (big 0, big 0, 0, sys->sprint("write: %r"));
	rsp := array[48] of byte;
	if(sys->read(fd, rsp, len rsp) != len rsp)
		return (big 0, big 0, 0, "short reply");
	t4 := readtime();

	if((int rsp[0] & 7) != 4)
		return (big 0, big 0, 0, "not a server reply");
	stratum := int rsp[1];
	if(stratum == 0 || stratum > 15)
		return (big 0, big 0, 0, "kiss-o'-death or bad stratum");
	# origin timestamp must echo ours
	for(i := 24; i < 32; i++)
		if(rsp[i] != req[40 + (i - 24)])
			return (big 0, big 0, 0, "origin timestamp mismatch");
	t2 := getntp(rsp, 32);
	t3 := getntp(rsp, 40);
	off := ((t2 - t1) + (t3 - t4)) / big 2;
	del := (t4 - t1) - (t3 - t2);
	return (off, del, stratum, nil);
}

# NTP timestamps are seconds since 1900 in a 32.32 fixed point.
putntp(b: array of byte, off: int, us: big)
{
	sec := us / big 1000000 + NTPDELTA;
	frac := ((us % big 1000000) << 32) / big 1000000;
	for(i := 0; i < 4; i++)
		b[off + i] = byte (sec >> (24 - 8 * i));
	for(i = 0; i < 4; i++)
		b[off + 4 + i] = byte (frac >> (24 - 8 * i));
}

getntp(b: array of byte, off: int): big
{
	sec := big 0;
	frac := big 0;
	for(i := 0; i < 4; i++)
		sec = (sec << 8) | big (int b[off + i]);
	for(i = 0; i < 4; i++)
		frac = (frac << 8) | big (int b[off + 4 + i]);
	if(sec == big 0 && frac == big 0)
		return big 0;
	return (sec - NTPDELTA) * big 1000000 + ((frac * big 1000000) >> 32);
}

# ---- clock files ------------------------------------------------------

readtime(): big
{
	fd := sys->open("/dev/time", Sys->OREAD);
	if(fd == nil)
		return big 0;
	b := array[64] of byte;
	n := sys->read(fd, b, len b);
	fd = nil;
	if(n <= 0)
		return big 0;
	s := string b[0:n];
	e := big 0;
	for(i := 0; i < len s; i++){
		if(s[i] < '0' || s[i] > '9')
			break;
		e = e * big 10 + big (s[i] - '0');
	}
	return e;
}

settime(us: big): string
{
	fd := sys->open("/dev/time", Sys->OWRITE);
	if(fd == nil)
		return sys->sprint("%r");
	n := sys->fprint(fd, "%bd", us);
	fd = nil;
	if(n < 0)
		return sys->sprint("%r");
	return nil;
}

hosttime(): big
{
	fd := sys->open(HOSTTIME, Sys->OREAD);
	if(fd == nil)
		return big 0;
	b := array[64] of byte;
	n := sys->read(fd, b, len b);
	fd = nil;
	if(n <= 0)
		return big 0;
	s := string b[0:n];
	e := big 0;
	for(i := 0; i < len s; i++){
		if(s[i] < '0' || s[i] > '9')
			break;
		e = e * big 10 + big (s[i] - '0');
	}
	return e;
}

abs(v: big): big
{
	if(v < big 0)
		return -v;
	return v;
}

# ---- namespace --------------------------------------------------------

mkdir(dir: string): int
{
	fd := sys->create(dir, Sys->OREAD, 8r777 | Sys->DMDIR);
	if(fd != nil)
		return 0;
	fd = sys->open(dir, Sys->OREAD);
	if(fd != nil)
		return 0;
	return -1;
}

publish()
{
	writefile(st.dir + "/status", status());
}

writefile(path, s: string)
{
	fd := sys->create(path, Sys->OWRITE, 8r666);
	if(fd == nil)
		return;
	sys->write(fd, array of byte s, len s);
	fd = nil;
}
