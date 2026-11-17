/*
 * devhostring.c - mountable client for 9vm's host 9P shared rings (#~).
 *
 * 9vm reserves the top 2 MiB of guest RAM, publishes it as a Multiboot
 * memory-map entry of type 0x9009, and serves 9P2000 requests from host
 * threads.  This device maps that region and exposes each ring as a plain
 * 9P byte stream:
 *
 *	#~/host		the host filesystem, ready for mount(2)
 *	#~/client	alias for host
 *	#~/ns		a 9P server the host relays to (9vm -ns), when offered
 *	#~/ctl		ring status
 *
 * A stream is duplex: writes submit one complete T-message, reads return
 * one complete R-message, in the order the host completes them, which
 * for ns is the order the server answers.  A gdb-free kernel cannot be
 * woken by the host, so reads spin briefly and then sleep.
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
	Qns,
	Qctl,
};

static Dirtab hostringdir[] =
{
	".",		{Qdir, 0, QTDIR},	0,	DMDIR|0555,
	"host",		{Qhost},		0,	0600,
	"client",	{Qhost},		0,	0600,
	"ns",		{Qns},			0,	0600,
	"ctl",		{Qctl},			0,	0444,
};

/* one ring: a channel of the shared region and its buffers */
typedef struct Ring Ring;
struct Ring
{
	char	*name;
	P9Channel	*ch;		/* nil until the host offers it */
	P9HostBuffer	*buf;
	QLock	tx;		/* one writer at a time */
	QLock	rx;		/* one reader at a time */
	Lock	lk;
	Rendez	rd;
	ulong	free;		/* buffer slots available */
	int	cur;		/* response being drained */
	long	len;
	long	rp;
	ulong	nreq;
	ulong	nrep;
	int	opens;
};

enum
{
	Rhost,
	Rns,
	Nring,
};

static P9HostShared *hostshared;
static ulong hostpa;
static Ring rings[Nring] = {
	{ "host" },
	{ "ns" },
};

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
hostpause(Ring *r, int spins)
{
	if(spins < 50){
		microdelay(2);
		return;
	}
	tsleep(&r->rd, return0, nil, 1);
}

static ulong
gbit32(uchar *p)
{
	return (ulong)p[0] | ((ulong)p[1]<<8) |
		((ulong)p[2]<<16) | ((ulong)p[3]<<24);
}

static void
ringinit(Ring *r, P9Channel *ch, P9HostBuffer *buf)
{
	r->ch = ch;
	r->buf = buf;
	r->free = (1UL<<P9_HOST_SLOTS) - 1;
	r->cur = -1;
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
	   (uchar*)&hs->channel - (uchar*)hs != 64 ||
	   (uchar*)&hs->ns - (uchar*)hs != 64 + 12544 + P9_HOST_SLOTS*2*P9_HOST_MSIZE){
		print("hostring: structure layout mismatch\n");
		return;
	}
	hostshared = hs;
	hostpa = base;
	ringinit(&rings[Rhost], &hs->channel, hs->buffer);
	if(hs->features & P9_HOST_FEAT_NS)
		ringinit(&rings[Rns], &hs->ns, hs->nsbuffer);
	print("hostring: host transport at %#lux%s\n", base,
		rings[Rns].ch != nil ? ", ns relayed" : "");
}

/* the ring behind a file, or an error when the host does not offer it */
static Ring*
ringof(Chan *c)
{
	Ring *r;

	if(hostshared == nil)
		error("9ring: no host transport");
	switch((int)c->qid.path){
	case Qhost:
		r = &rings[Rhost];
		break;
	case Qns:
		r = &rings[Rns];
		break;
	default:
		error(Eperm);
		return nil;
	}
	if(r->ch == nil)
		error("9ring: channel not offered by the host");
	return r;
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
	Ring *r;

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
	if(c->qid.path == Qctl){
		if(omode & OWRITE)
			error(Eperm);
	}else{
		r = ringof(c);
		lock(&r->lk);
		if(r->opens > 0){
			unlock(&r->lk);
			error("9ring: channel busy");
		}
		r->opens++;
		unlock(&r->lk);
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
	Ring *r;

	if(c->qid.path == Qctl || (c->qid.type & QTDIR) || !(c->flag & COPEN))
		return;
	r = ringof(c);
	qlock(&r->rx);
	lock(&r->lk);
	if(r->cur >= 0){
		r->free |= 1UL<<r->cur;
		r->cur = -1;
	}
	if(r->opens > 0)
		r->opens--;
	unlock(&r->lk);
	qunlock(&r->rx);
}

static long
hostread(Ring *r, void *va, long n)
{
	P9Comp comp;
	P9HostBuffer *b;
	ulong wirelen;
	long count;
	int spins;

	if(n <= 0)
		return 0;
	qlock(&r->rx);
	if(waserror()){
		qunlock(&r->rx);
		nexterror();
	}
	spins = 0;
	while(r->cur < 0){
		if(p9poll(&r->ch->r, &comp)){
			if(comp.result >= P9_HOST_SLOTS || comp.status != 0 ||
			   comp.count < 7 || comp.count > P9_HOST_MSIZE){
				if(comp.result < P9_HOST_SLOTS){
					lock(&r->lk);
					r->free |= 1UL<<comp.result;
					unlock(&r->lk);
				}
				error("9ring: host request failed");
			}
			b = &r->buf[comp.result];
			wirelen = gbit32(b->response);
			if(wirelen != comp.count ||
			   b->response[5] != (uchar)comp.tag ||
			   b->response[6] != (uchar)(comp.tag>>8)){
				lock(&r->lk);
				r->free |= 1UL<<comp.result;
				unlock(&r->lk);
				error("9ring: invalid host response");
			}
			r->cur = comp.result;
			r->len = comp.count;
			r->rp = 0;
			r->nrep++;
			break;
		}
		hostpause(r, spins++);
	}
	count = r->len - r->rp;
	if(count > n)
		count = n;
	memmove(va, r->buf[r->cur].response + r->rp, count);
	r->rp += count;
	if(r->rp == r->len){
		lock(&r->lk);
		r->free |= 1UL<<r->cur;
		unlock(&r->lk);
		r->cur = -1;
	}
	poperror();
	qunlock(&r->rx);
	return count;
}

static long
hostwrite(Ring *r, void *va, long n)
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
	qlock(&r->tx);
	if(waserror()){
		qunlock(&r->tx);
		nexterror();
	}
	spins = 0;
	for(;;){
		lock(&r->lk);
		for(i = 0; i < P9_HOST_SLOTS; i++)
			if(r->free & (1UL<<i))
				break;
		if(i < P9_HOST_SLOTS)
			r->free &= ~(1UL<<i);
		unlock(&r->lk);
		if(i < P9_HOST_SLOTS)
			break;
		hostpause(r, spins++);
	}
	memmove(r->buf[i].request, m, n);
	memset(&slot, 0, sizeof(slot));
	slot.tag = m[5] | (m[6]<<8);
	slot.type = m[4];
	slot.count = n;
	slot.buf_addr = i;
	spins = 0;
	while(p9submit(&r->ch->t, &slot) < 0)
		hostpause(r, spins++);
	wakeup(&r->rd);
	r->nreq++;
	poperror();
	qunlock(&r->tx);
	return n;
}

static long
hostctlread(void *va, long n, vlong off)
{
	char buf[512];
	Ring *r;
	int len, i;

	if(off < 0)
		return 0;
	len = snprint(buf, sizeof(buf),
		"addr %#lux magic %#lux version %lud features %#lux slots %d\n",
		hostpa, hostshared ? hostshared->magic : 0,
		hostshared ? hostshared->version : 0,
		hostshared ? hostshared->features : 0, P9_HOST_SLOTS);
	for(i = 0; i < Nring; i++){
		r = &rings[i];
		if(r->ch == nil)
			continue;
		len += snprint(buf + len, sizeof(buf) - len,
			"%s free %#lux requests %lud replies %lud\n",
			r->name, r->free, r->nreq, r->nrep);
	}
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
	switch((int)c->qid.path){
	case Qhost:
	case Qns:
		return hostread(ringof(c), va, n);
	case Qctl:
		return hostctlread(va, n, off);
	}
	return 0;
}

static long
hostringwrite(Chan *c, void *va, long n, vlong off)
{
	USED(off);
	if(c->qid.path != Qhost && c->qid.path != Qns)
		error(Eperm);
	return hostwrite(ringof(c), va, n);
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
