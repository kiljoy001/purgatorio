#
#  timed -- wall-clock service: host clock, SNTP discipline, status.
#
#  Two clocks:
#    wall      /dev/time, microseconds since the epoch, settable
#    monotonic sys->millisec(), milliseconds since boot, never set
#
#  On 9vm the host serves its own clock at /n/host/time, read at the
#  moment of the request (the guest has no RTC); timed sets /dev/time
#  from it at start and holds the clock to it every second, stepping a
#  large error and slewing a small one.  Without a host clock it queries
#  SNTP servers instead: -s options, /lib/ndb/time, or the public
#  anycast defaults.  It publishes ordinary files in a directory (default
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
SLEW:	con big 100000;		# most the clock may move in one second
MINSLEW: con big 2000;		# below this, leave the clock alone
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
	pend:	big;		# microseconds left to slew
	nextsync: int;		# monotonic ms of the next attempt
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
	st = ref St(DIR, nil, "", 900, 0, "", big 0, big 0, 0, big 0, big 0, 0);
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

	# The clock source on 9vm is the host's own: the hypervisor serves
	# /n/host/time, read at the moment of the request, and the kernel has
	# no RTC.  Take it now so services start with a real date, and hold
	# the clock to it every second below.  SNTP is the fallback when no
	# host clock is published.
	hostsync();
	if(st.source != "host" && readtime() < FLOOR)
		sys->print("timed: no host clock; waiting for SNTP\n");

	for(;;){
		hostsync();
		if(st.source != "host" && st.servers != nil && !busy &&
		   sys->millisec() >= st.nextsync)
			spawn dosync();
		slewstep();
		publish();
		sys->sleep(1000);
	}
}

# ---- state ------------------------------------------------------------

# Read the host clock and hold the guest to it.  A large error is stepped
# (a wrong date is worse than a jump); a small one is left to slewstep(),
# a fraction per second, so the wall clock stays monotonic.
hostsync()
{
	t1 := readtime();
	h := hosttime();
	t4 := readtime();
	if(h < FLOOR){
		# The host stopped publishing (or never did): let SNTP take over.
		if(st.source == "host"){
			st.source = "";
			st.synced = 0;
			st.pend = big 0;
		}
		return;
	}
	# The host formats its clock somewhere inside the round trip, which
	# goes through the shared ring and can take a tick; the midpoint of
	# the two guest readings is when it was taken.
	cur := (t1 + t4) / big 2;
	off := h - cur;
	st.source = "host";
	st.synced = 1;
	st.server = "host";
	st.stratum = 0;
	st.delay = t4 - t1;
	st.offset = off;
	st.last = h / big 1000000;
	if(cur < FLOOR || abs(off) > STEP){
		if(settime(h) == nil)
			st.pend = big 0;
	}else if(abs(off) > MINSLEW)
		st.pend = off;
	else
		st.pend = big 0;
}

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
	return sys->sprint("source=%s\nsynced=%d\nverified=%d\nserver=%s\noffset_us=%bd\ndelay_us=%bd\nstratum=%d\nlast=%bd\nnow=%bd\nmono=%d\npending_us=%bd\n",
		st.source, st.synced, (st.source == "sntp"), st.server,
		st.offset, st.delay, st.stratum, st.last, cur, sys->millisec(),
		st.pend);
}

# Move the wall clock a fraction of the remaining error.  Cap the
# change per second so the clock is monotonic at second resolution even
# when the correction is large.
slewstep()
{
	if(st.pend == big 0)
		return;
	d := st.pend / big 8;
	if(d == big 0){
		if(st.pend > big 0)
			d = big 1;
		else
			d = big -1;
	}
	if(d > SLEW)
		d = SLEW;
	if(d < -SLEW)
		d = -SLEW;
	cur := readtime();
	if(settime(cur + d) == nil){
		st.pend -= d;
		if(abs(st.pend) < big 1000)
			st.pend = big 0;
	}
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
			st.pend = big 0;
			st.source = "sntp";
			st.synced = 1;
			sys->print("timed: %s: stepped %bd us (delay %bd)\n",
				srv, off, del);
		}else if(abs(off) > MINSLEW){
			# Small errors are removed a fraction per second, so
			# the wall clock never jumps backwards or forwards.
			st.pend = off;
			sys->print("timed: %s: slew %bd us (delay %bd)\n",
				srv, off, del);
		}else{
			st.pend = big 0;
			sys->print("timed: %s: within %bd us\n", srv, MINSLEW);
		}
		st.last = (cur + off) / big 1000000;
		break;
	}
	# Keep the attempt rate at interval even when every server fails.
	st.nextsync = sys->millisec() + st.interval * 1000;
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

# The host serves microseconds since the epoch, read at the moment of the
# request.  An older host published seconds; anything below 1e11 is taken
# as seconds.
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
	if(e > big 0 && e < big 100000000000)
		e *= big 1000000;
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
