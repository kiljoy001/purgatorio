implement InitShell;

include "sys.m";
include "draw.m";

sys: Sys;

InitShell: module
{
	init:	fn(nil: ref Draw->Context, nil: list of string);
};

Sh: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

Mount: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

init(drawcontext: ref Draw->Context, nil: list of string)
{
	shell := load Sh "/dis/sh.dis";

	sys = load Sys Sys->PATH;

	if(sys != nil)
		sys->print("init: starting shell\n");

	# Replace the embedded bootstrap root with the persistent kfs64
	# filesystem on the virtio-blk disk.  If the disk is missing or
	# blank the mount fails and we stay on the embedded root.
	rootmount(drawcontext);

	# The 9vm host shares its filesystem over a 9P ring (#~/host).
	# Best effort: kernels without the ring simply keep going.
	hostmount(drawcontext);

#	sys->bind("#I", "/net", sys->MAFTER);	# IP
	sys->bind("#p", "/prog", sys->MREPL);	# prog device
	sys->bind("#d", "/fd", Sys->MREPL);
	sys->bind("#s", "/chan", sys->MREPL);	# srv (file2chan)
	sys->bind("#i", "/dev", sys->MREPL); 	# draw device
	sys->bind("#t", "/dev", sys->MAFTER);	# serial line
	sys->bind("#c", "/dev", sys->MAFTER); 	# console device
	sys->bind("#W","/dev",sys->MAFTER);	# Flash
#	sys->bind("#O", "/dev", sys->MAFTER);	# Modem
#	sys->bind("#T","/dev",sys->MAFTER);	# Touchscreen

	srv();

	spawn shell->init(nil, nil);
}

# Mount the kfs64 on the virtio-blk disk as the root filesystem.
# Done in the init process so that the shell is created with the new
# root already in place (and so the device binds below land on it).
rootmount(ctxt: ref Draw->Context)
{
	mount := load Mount "/dis/mount.dis";
	if(mount == nil){
		sys->print("init: cannot load mount: %r; using embedded root\n");
		return;
	}
	mounted := 0;
	{
		mount->init(ctxt, "mount" :: "-c" :: "{disk/kfs64 '#S/sd00/data'}" :: "/" :: nil);
		mounted = 1;
	} exception {
	"*" =>
		mounted = 0;
	}
	if(mounted)
		sys->print("init: mounted kfs64 root from #S/sd00/data\n");
	else
		sys->print("init: root mount failed; using embedded root\n");
}

# Mount the 9vm host filesystem served on the shared 9P ring at /n/host.
hostmount(ctxt: ref Draw->Context)
{
	mount := load Mount "/dis/mount.dis";
	fd: ref Sys->FD;

	if(mount == nil){
		sys->print("init: cannot load mount: %r\n");
		return;
	}
	fd = sys->open("#~/host", Sys->ORDWR);
	if(fd == nil){
		sys->print("init: no 9ring host transport: %r\n");
		return;
	}
	fd = nil;
	if(sys->create("/n/host", Sys->OREAD, Sys->DMDIR|8r777) == nil)
		;	# already there
	{
		mount->init(ctxt, "mount" :: "-A" :: "#~/host" :: "/n/host" :: nil);
		sys->print("init: mounted 9ring host at /n/host\n");
	} exception {
	"*" =>
		sys->print("init: 9ring host mount failed: %r\n");
	}
}

srv()
{
	remotedebug := sysenv("remotedebug");
	if(remotedebug != "1")
		return;

	sys->print("srv...");
	if(echoto("#t/eia0ctl", "b38400") < 0)
		return;

	fd := sys->open("/dev/eia0", Sys->ORDWR);
	if (fd == nil) {
		sys->print("eia data open: %r\n");
		return;
	}
	if (sys->export(fd, "/", Sys->EXPASYNC) < 0) {
		sys->print("export: %r\n");
		return;
	}
	sys->print("ok\n");
}

sysenv(param: string): string
{
	fd := sys->open("#c/sysenv", sys->OREAD);
	if (fd == nil)
		return(nil);
	buf := array[4096] of byte;
	nb := sys->read(fd, buf, len buf);
	(nfl,fl) := sys->tokenize(string buf, "\n");
	while (fl != nil) {
		pair := hd fl;
		(npl, pl) := sys->tokenize(pair, "=");
		if (npl > 1) {
			if ((hd pl) == param)
				return hd tl pl;
		}
		fl = tl fl;
	}
	return nil ;
}

echoto(fname, str: string): int
{
	fd := sys->open(fname, Sys->OWRITE);
	if(fd == nil) {
		sys->print("%s: %r\n", fname);
		return -1;
	}
	x := array of byte str;
	if(sys->write(fd, x, len x) == -1) {
		sys->print("write: %r\n");
		return -1;
	}
	return 0;
}
