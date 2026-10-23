/*
 * devhostring.c - mountable client for 9vm's host 9P shared ring (#~).
 *
 * 9vm reserves the top 2 MiB of guest RAM, publishes it as a Multiboot
 * memory-map entry of type 0x9009, and serves 9P2000 requests from a host
 * thread.  This device maps that region and exposes it as a plain 9P byte
 * stream:
 *
 *	#~/host		the host filesystem, ready for mount(2)
 *	#~/client	alias for host
 *	#~/ctl		ring status
 *
 * The stream is duplex: writes submit one complete T-message, reads return
 * one complete R-message.  A gdb-free kernel cannot be woken by the host,
 * so reads spin briefly and then sleep.
 */

#include	"u.h"
#include	"../port/lib.h"
#include	"mem.h"
#include	"dat.h"
#include	"fns.h"
#include	"../port/error.h"

#include	"9ring.h"

extern ulong multibootptr;

enum
{
	Qdir,
	Qhost,
	Qctl,
};

static Dirtab hostringdir[] =
{
	".",		{Qdir, 0, QTDIR},	0,	DMDIR|0555,
	"host",		{Qhost},		0,	0600,
	"client",	{Qhost},		0,	0600,
	"ctl",		{Qctl},			0,	0444,
};

static P9HostShared *hostshared;
static ulong hostpa;

static QLock	hosttx;		/* one writer at a time */
static QLock	hostrx;		/* one reader at a time */
static Lock	hostlk;
static Rendez	hostrd;
static ulong	hostfree;	/* buffer slots available */
static int	hostcur = -1;	/* response being drained */
static long	hostlen;
static long	hostrp;
static ulong	hostnreq;
static ulong	hostnrep;
static int	hostopens;

static int
p9submit(P9TRing *r, P9Slot *s)
{
	ulong head, tail;

	head = r->head;
	tail = r->tail;
	if(head - tail >= P9_RING_SIZE)
		return -1;
	r->slots[head & P9_RING_MASK] = *s;
	coherence();
	r->head = head + 1;
	coherence();
	return 0;
}

static int
p9poll(P9RRing *r, P9Comp *c)
{
	ulong head, tail;

	tail = r->tail;
	coherence();
	head = r->head;
	if(tail == head)
		return 0;
	*c = r->comps[tail & P9_RING_MASK];
	coherence();
	r->tail = tail + 1;
	coherence();
	return 1;
}

static void
hostpause(int spins)
{
	if(spins < 50){
		microdelay(2);
		return;
	}
	tsleep(&hostrd, return0, nil, 1);
}

static ulong
gbit32(uchar *p)
{
	return (ulong)p[0] | ((ulong)p[1]<<8) |
		((ulong)p[2]<<16) | ((ulong)p[3]<<24);
}

static void
hostringinit(void)
{
	ulong *mb, *mm, l, base, size, type;
	P9HostShared *hs;

	base = 0;
	size = 0;
	if(multibootptr != 0 && multibootptr < 16*MB){
		mb = (ulong*)KADDR(multibootptr);
		if(mb[0] & (1<<6)){
			mm = (ulong*)KADDR(mb[12]);
			l = mb[11];
			while(mm[0] >= 20 && mm[0]+4 <= l){
				mm++;
				type = mm[4];
				if(type == 0x9009){
					base = mm[0];
					size = mm[2];
					break;
				}
				l -= mm[-1]+4;
				mm = (ulong*)((char*)mm + mm[-1]);
			}
		}
	}
	if(base == 0 || size < sizeof(P9HostShared)){
		print("hostring: no shared region in the memory map\n");
		return;
	}
	if(mmukmap(base, 0, size) == 0){
		print("hostring: cannot map %#lux\n", base);
		return;
	}
	hs = (P9HostShared*)KADDR(base);
	if(hs->magic != P9_HOST_MAGIC || hs->version != P9_HOST_VERSION){
		print("hostring: bad header magic %#lux version %lud\n",
			hs->magic, hs->version);
		return;
	}
	if(sizeof(P9Slot) != 32 || sizeof(P9Comp) != 16 ||
	   sizeof(P9TRing) != 8320 || sizeof(P9RRing) != 4224 ||
	   (uchar*)&hs->channel - (uchar*)hs != 64){
		print("hostring: structure layout mismatch\n");
		return;
	}
	hostshared = hs;
	hostpa = base;
	hostfree = (1UL<<P9_HOST_SLOTS) - 1;
	print("hostring: host transport at %#lux\n", base);
}

static Chan*
hostringattach(char *spec)
{
	return devattach('~', spec);
}

static Walkqid*
hostringwalk(Chan *c, Chan *nc, char **name, int nname)
{
	return devwalk(c, nc, name, nname, hostringdir,
		nelem(hostringdir), devgen);
}

static int
hostringstat(Chan *c, uchar *db, int n)
{
	return devstat(c, db, n, hostringdir, nelem(hostringdir), devgen);
}

static Chan*
hostringopen(Chan *c, int omode)
{
	if(c->qid.type & QTDIR){
		if(omode != OREAD)
			error(Ebadarg);
		c->mode = omode;
		c->flag |= COPEN;
		c->offset = 0;
		return c;
	}
	if(hostshared == nil)
		error("9ring: no host transport");
	if(c->qid.path == Qctl && (omode & OWRITE))
		error(Eperm);
	if(c->qid.path == Qhost){
		lock(&hostlk);
		if(hostopens > 0){
			unlock(&hostlk);
			error("9ring: host channel busy");
		}
		hostopens++;
		unlock(&hostlk);
	}
	c->mode = openmode(omode);
	c->flag |= COPEN;
	c->offset = 0;
	c->iounit = P9_HOST_MSIZE;
	return c;
}

static void
hostringclose(Chan *c)
{
	if(c->qid.path != Qhost || !(c->flag & COPEN))
		return;
	qlock(&hostrx);
	lock(&hostlk);
	if(hostcur >= 0){
		hostfree |= 1UL<<hostcur;
		hostcur = -1;
	}
	if(hostopens > 0)
		hostopens--;
	unlock(&hostlk);
	qunlock(&hostrx);
}

static long
hostread(void *va, long n)
{
	P9Comp comp;
	P9HostBuffer *b;
	ulong wirelen;
	long count;
	int spins;

	if(n <= 0)
		return 0;
	qlock(&hostrx);
	if(waserror()){
		qunlock(&hostrx);
		nexterror();
	}
	spins = 0;
	while(hostcur < 0){
		if(p9poll(&hostshared->channel.r, &comp)){
			if(comp.result >= P9_HOST_SLOTS || comp.status != 0 ||
			   comp.count < 7 || comp.count > P9_HOST_MSIZE){
				if(comp.result < P9_HOST_SLOTS){
					lock(&hostlk);
					hostfree |= 1UL<<comp.result;
					unlock(&hostlk);
				}
				error("9ring: host request failed");
			}
			b = &hostshared->buffer[comp.result];
			wirelen = gbit32(b->response);
			if(wirelen != comp.count ||
			   b->response[5] != (uchar)comp.tag ||
			   b->response[6] != (uchar)(comp.tag>>8)){
				lock(&hostlk);
				hostfree |= 1UL<<comp.result;
				unlock(&hostlk);
				error("9ring: invalid host response");
			}
			hostcur = comp.result;
			hostlen = comp.count;
			hostrp = 0;
			hostnrep++;
			break;
		}
		hostpause(spins++);
	}
	count = hostlen - hostrp;
	if(count > n)
		count = n;
	memmove(va, hostshared->buffer[hostcur].response + hostrp, count);
	hostrp += count;
	if(hostrp == hostlen){
		lock(&hostlk);
		hostfree |= 1UL<<hostcur;
		unlock(&hostlk);
		hostcur = -1;
	}
	poperror();
	qunlock(&hostrx);
	return count;
}

static long
hostwrite(void *va, long n)
{
	P9Slot slot;
	uchar *m;
	ulong wirelen;
	int i, spins;

	if(n < 7 || n > P9_HOST_MSIZE)
		error("9ring: invalid 9P message length");
	m = va;
	wirelen = gbit32(m);
	if(wirelen != n)
		error("9ring: 9P length does not match write");
	qlock(&hosttx);
	if(waserror()){
		qunlock(&hosttx);
		nexterror();
	}
	spins = 0;
	for(;;){
		lock(&hostlk);
		for(i = 0; i < P9_HOST_SLOTS; i++)
			if(hostfree & (1UL<<i))
				break;
		if(i < P9_HOST_SLOTS)
			hostfree &= ~(1UL<<i);
		unlock(&hostlk);
		if(i < P9_HOST_SLOTS)
			break;
		hostpause(spins++);
	}
	memmove(hostshared->buffer[i].request, m, n);
	memset(&slot, 0, sizeof(slot));
	slot.tag = m[5] | (m[6]<<8);
	slot.type = m[4];
	slot.count = n;
	slot.buf_addr = i;
	spins = 0;
	while(p9submit(&hostshared->channel.t, &slot) < 0)
		hostpause(spins++);
	wakeup(&hostrd);
	hostnreq++;
	poperror();
	qunlock(&hosttx);
	return n;
}

static long
hostctlread(void *va, long n, vlong off)
{
	char buf[256];
	int len;

	if(off < 0)
		return 0;
	len = snprint(buf, sizeof(buf),
		"addr %#lux magic %#lux version %lud slots %d free %#lux "
		"requests %lud replies %lud\n",
		hostpa, hostshared ? hostshared->magic : 0,
		hostshared ? hostshared->version : 0, P9_HOST_SLOTS,
		hostfree, hostnreq, hostnrep);
	if(off >= len)
		return 0;
	if(n > len - off)
		n = len - off;
	memmove(va, buf + off, n);
	return n;
}

static long
hostringread(Chan *c, void *va, long n, vlong off)
{
	switch(c->qid.path){
	case Qhost:
		return hostread(va, n);
	case Qctl:
		return hostctlread(va, n, off);
	}
	return 0;
}

static long
hostringwrite(Chan *c, void *va, long n, vlong off)
{
	USED(off);
	if(c->qid.path != Qhost)
		error(Eperm);
	return hostwrite(va, n);
}

Dev hostringdevtab = {
	'~',
	"hostring",

	devreset,
	hostringinit,
	devshutdown,
	hostringattach,
	hostringwalk,
	hostringstat,
	hostringopen,
	devcreate,
	hostringclose,
	hostringread,
	devbread,
	hostringwrite,
	devbwrite,
	devremove,
	devwstat,
};
