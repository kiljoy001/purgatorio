/*
 * virtio 1.0 ethernet for the 9vm hypervisor.
 *
 * 9vm exposes a simplified modern virtio device in one memory BAR:
 *
 *   0x000  common config (device/queue registers)
 *   0x100  queue notify
 *   0x200  ISR
 *   0x300  network config (MAC, link, MTU)
 *
 * Two split virtqueues are used: queue 0 receives, queue 1 transmits.
 * The receive queue is refilled from the interrupt handler; transmit is
 * synchronous and copies the packet into a per-slot buffer.
 */
#include "u.h"
#include "../port/lib.h"
#include "mem.h"
#include "dat.h"
#include "fns.h"
#include "io.h"
#include "../port/error.h"
#include "../port/netif.h"

#include "etherif.h"

enum {
	QSZ		= 64,
	NPKT		= QSZ/2,
	Hdrsz		= 12,		/* virtio_net_hdr */
	Bufsz		= 2048,

	/* common config */
	VDevFeatSel	= 0x000,
	VDevFeat	= 0x004,
	VDrvFeatSel	= 0x008,
	VDrvFeat	= 0x00C,
	VDevStatus	= 0x014,
	VQueueSel	= 0x016,
	VQueueSize	= 0x018,
	VQueueEnable	= 0x01C,
	VQueueDesc	= 0x020,
	VQueueAvail	= 0x028,
	VQueueUsed	= 0x030,
	VQueueNotify	= 0x100,
	VISR		= 0x200,
	VDevConfig	= 0x300,

	/* device status */
	VSack		= 1,
	VSdriver	= 2,
	VSdriverok	= 4,
	VSfeaturesok	= 8,

	/* feature bits */
	Fmac		= 1<<5,
	Fstatus		= 1<<16,
	Fversion1	= 1<<0,	/* feature word 1 */

	/* descriptor flags */
	Dnext		= 1,
	Dwrite		= 2,

	Rxq		= 0,
	Txq		= 1,
};

typedef struct Vconfig Vconfig;
typedef struct Vnetcfg Vnetcfg;
typedef struct Vdesc Vdesc;
typedef struct Vavail Vavail;
typedef struct Vusede Vusede;
typedef struct Vused Vused;
typedef struct Vqueue Vqueue;
typedef struct Buf Buf;
typedef struct Ctlr Ctlr;

struct Vconfig {
	ulong	devfeatsel;
	ulong	devfeat;
	ulong	drvfeatsel;
	ulong	drvfeat;

	ushort	msixcfg;
	ushort	nqueues;

	uchar	status;
	uchar	cfggen;
	ushort	queuesel;

	ushort	queuesize;
	ushort	queuemsixvect;

	ushort	queueenable;
	ushort	queuenotifyoff;

	uvlong	queuedesc;
	uvlong	queueavail;
	uvlong	queueused;
};

struct Vnetcfg {
	ushort	mac0;
	ushort	mac1;
	ushort	mac2;
	ushort	status;
	ushort	maxpairs;
	ushort	mtu;
};

struct Vdesc {
	uvlong	addr;
	ulong	len;
	ushort	flags;
	ushort	next;
};

struct Vavail {
	ushort	flags;
	ushort	idx;
	ushort	ring[QSZ];
};

struct Vusede {
	ulong	id;
	ulong	len;
};

struct Vused {
	ushort	flags;
	ushort	idx;
	Vusede	ring[QSZ];
};

struct Vqueue {
	Vdesc	desc[QSZ];
	Vavail	avail;
	Vused	used;
};

struct Buf {
	uchar	hdr[Hdrsz];
	uchar	data[Bufsz];
};

struct Ctlr {
	Lock;

	Pcidev*	pcidev;
	uchar*	mmio;
	volatile Vconfig* cfg;
	volatile Vnetcfg* dev;
	volatile uchar*	isr;
	volatile ushort* notify;

	Vqueue*	rxq;
	Vqueue*	txq;
	Buf*	rxbuf;
	Buf*	txbuf;
	Block*	rxblock[NPKT];
	int	txbusy[NPKT];
	int	txhead;
	int	txfree;
	int	txdone;
	int	rxdone;

	uchar	rxhdr[Hdrsz];
	uchar	txhdr[Hdrsz];

	int	active;
	int	attached;
	int	polling;
	ulong	pa;
	Ctlr*	next;
};

static Ctlr* ctlrhead;

static void
virtiopci(void)
{
	Pcidev *p;
	Ctlr *c, *t;

	t = ctlrhead;
	for(p = nil; (p = pcimatch(p, 0x1AF4, 0x1041)) != nil;){
		if(p->rid == 0)
			continue;
		c = malloc(sizeof(Ctlr));
		if(c == nil)
			break;
		memset(c, 0, sizeof(*c));
		c->pcidev = p;
		/* 9vm does not assign a PCI class, so the generic scan
		 * leaves mem[0] empty; read BAR0 from config space. */
		c->pa = pcicfgr32(p, PciBAR0) & 0xFFFFFFF0;
		if(t == nil)
			ctlrhead = c;
		else
			t->next = c;
		t = c;
	}
}

static void
vqnotify(Ctlr *c, int q)
{
	coherence();
	*c->notify = q;
}

static void
txreclaim(Ctlr *c)
{
	Vused *u;
	Vusede *e;
	int i;

	if(c->txq == nil)
		return;
	u = &c->txq->used;
	while(c->txdone != u->idx){
		e = &u->ring[c->txdone % QSZ];
		i = e->id >> 1;
		if(i < NPKT && c->txbusy[i]){
			c->txbusy[i] = 0;
			c->txfree++;
		}
		c->txdone++;
	}
}

static void
rxreclaim(Ether *edev)
{
	Ctlr *c;
	Vused *u;
	Vusede *e;
	Block *bp;
	int i, n;

	c = edev->ctlr;
	if(c->rxq == nil)
		return;
	u = &c->rxq->used;
	while(c->rxdone != u->idx){
		e = &u->ring[c->rxdone % QSZ];
		i = e->id >> 1;
		n = e->len;
		if(i >= NPKT){
			c->rxdone++;
			continue;
		}
		bp = c->rxblock[i];
		c->rxblock[i] = nil;
		if(bp != nil && n > Hdrsz){
			n -= Hdrsz;
			if(n > BALLOC(bp))
				n = BALLOC(bp);
			bp->wp = bp->rp + n;
			etheriq(edev, bp, 1);
		}else if(bp != nil)
			freeb(bp);

		/* Repost the chain with a fresh buffer. */
		bp = iallocb(Bufsz);
		if(bp != nil){
			c->rxblock[i] = bp;
			c->rxq->desc[2*i+1].addr = PADDR(bp->rp);
			c->rxq->desc[2*i+1].len = BALLOC(bp);
			c->rxq->avail.ring[c->rxq->avail.idx % QSZ] = 2*i;
			coherence();
			c->rxq->avail.idx++;
		}
		c->rxdone++;
	}
	vqnotify(c, Rxq);
}

static void
txstart(Ether *edev)
{
	Ctlr *c;
	Vqueue *q;
	Block *bp;
	int i, n;

	c = edev->ctlr;
	if(c->txq == nil)
		return;
	q = c->txq;

	for(;;){
		txreclaim(c);
		if(c->txfree <= 0)
			break;
		bp = qget(edev->oq);
		if(bp == nil)
			break;
		n = BLEN(bp);
		if(n <= 0 || n > Bufsz){
			freeb(bp);
			edev->oerrs++;
			continue;
		}
		i = c->txhead;
		if(c->txbusy[i]){
			freeb(bp);
			break;
		}
		memmove(c->txbuf[i].data, bp->rp, n);
		freeb(bp);

		c->txbusy[i] = 1;
		c->txfree--;
		c->txhead = NEXT(i, NPKT);

		q->desc[2*i].addr = PADDR(&c->txhdr[0]);
		q->desc[2*i].len = Hdrsz;
		q->desc[2*i].flags = Dnext;
		q->desc[2*i].next = 2*i + 1;

		q->desc[2*i+1].addr = PADDR(&c->txbuf[i].data[0]);
		q->desc[2*i+1].len = n;
		q->desc[2*i+1].flags = 0;
		q->desc[2*i+1].next = 0;

		q->avail.ring[q->avail.idx % QSZ] = 2*i;
		coherence();
		q->avail.idx++;
		vqnotify(c, Txq);
	}
}

static void
transmit(Ether *edev)
{
	Ctlr *c;

	c = edev->ctlr;
	ilock(c);
	txstart(edev);
	iunlock(c);
}

static void
interrupt(Ureg*, void* arg)
{
	Ether *edev;
	Ctlr *c;

	edev = arg;
	c = edev->ctlr;
	if((*c->isr & 1) == 0)
		return;

	ilock(c);
	txreclaim(c);
	rxreclaim(edev);
	iunlock(c);

	/* Packets queued by the receive path go out now. */
	transmit(edev);
}

static long
ifstat(Ether *edev, void *a, long n, ulong offset)
{
	Ctlr *c;
	char *p;
	int len;

	c = edev->ctlr;
	if(n == 0)
		return 0;
	p = malloc(READSTR);
	len = snprint(p, READSTR, "txfree %d\n", c->txfree);
	len += snprint(p+len, READSTR-len, "txdone %d\n", c->txdone);
	len += snprint(p+len, READSTR-len, "rxdone %d\n", c->rxdone);
	len += snprint(p+len, READSTR-len, "rxavail %d\n", c->rxq->avail.idx);
	len += snprint(p+len, READSTR-len, "rxused %d\n", c->rxq->used.idx);
	len += snprint(p+len, READSTR-len, "txavail %d\n", c->txq->avail.idx);
	snprint(p+len, READSTR-len, "txused %d\n", c->txq->used.idx);
	n = readstr(offset, a, n, p);
	free(p);
	return n;
}

static void
pollproc(void *arg)
{
	Ether *edev;
	Ctlr *c;

	edev = arg;
	c = edev->ctlr;
	for(;;){
		ilock(c);
		if(*c->isr & 1){		/* read clears and deasserts */
			txreclaim(c);
			rxreclaim(edev);
		}
		iunlock(c);
		transmit(edev);
		tsleep(&up->sleep, return0, nil, 10);
	}
}

static void
attach(Ether *edev)
{
	Ctlr *c;
	Block *bp;
	int i;

	c = edev->ctlr;
	ilock(c);
	if(c->attached){
		iunlock(c);
		return;
	}
	c->attached = 1;

	/* Post the receive ring. */
	for(i = 0; i < NPKT; i++){
		bp = allocb(Bufsz);
		if(bp == nil)
			break;
		c->rxblock[i] = bp;
		c->rxq->desc[2*i+1].addr = PADDR(bp->rp);
		c->rxq->desc[2*i+1].len = BALLOC(bp);
		c->rxq->avail.ring[c->rxq->avail.idx % QSZ] = 2*i;
		c->rxq->avail.idx++;
	}
	coherence();

	/* Enable both queues and tell the device the driver is ready. */
	c->cfg->queuesel = Rxq;
	c->cfg->queueenable = 1;
	c->cfg->queuesel = Txq;
	c->cfg->queueenable = 1;
	coherence();
	c->cfg->status |= VSdriverok;
	coherence();

	vqnotify(c, Rxq);
	if(!c->polling){
		c->polling = 1;
		kproc("virtionet", pollproc, edev, 0);
	}
	iunlock(c);
}

static void
shutdown(Ether *edev)
{
	Ctlr *c;

	c = edev->ctlr;
	coherence();
	c->cfg->status = 0;
	coherence();
	pciclrbme(c->pcidev);
}

static int
reset(Ether *edev)
{
	Ctlr *c;
	Pcidev *p;
	Vqueue *q;
	ulong feat0, feat1;
	int i;

	if(ctlrhead == nil)
		virtiopci();

	for(c = ctlrhead; c != nil; c = c->next){
		if(c->active)
			continue;
		if(edev->port == 0 || edev->port == c->pa){
			c->active = 1;
			break;
		}
	}
	if(c == nil)
		return -1;

	p = c->pcidev;
	if(mmukmap(c->pa, 0, 4096) == 0)
		return -1;
	c->mmio = (uchar*)KADDR(c->pa);

	c->cfg = (Vconfig*)c->mmio;
	c->notify = (ushort*)(c->mmio + VQueueNotify);
	c->isr = c->mmio + VISR;
	c->dev = (Vnetcfg*)(c->mmio + VDevConfig);

	/* Reset and acknowledge. */
	coherence();
	c->cfg->status = 0;
	for(i = 0; i < 1000 && c->cfg->status != 0; i++)
		delay(1);
	c->cfg->status = VSack | VSdriver;

	/* Feature negotiation: accept MAC/STATUS and VIRTIO 1.0. */
	c->cfg->devfeatsel = 0;
	feat0 = c->cfg->devfeat;
	c->cfg->devfeatsel = 1;
	feat1 = c->cfg->devfeat;
	c->cfg->drvfeatsel = 0;
	c->cfg->drvfeat = feat0 & (Fmac | Fstatus);
	c->cfg->drvfeatsel = 1;
	c->cfg->drvfeat = feat1 & Fversion1;
	c->cfg->status |= VSfeaturesok;
	coherence();

	/* Allocate the queues and their buffers. */
	c->rxq = xspanalloc(sizeof(Vqueue), 16, 0);
	c->txq = xspanalloc(sizeof(Vqueue), 16, 0);
	c->rxbuf = xspanalloc(sizeof(Buf)*NPKT, 16, 0);
	c->txbuf = xspanalloc(sizeof(Buf)*NPKT, 16, 0);
	if(c->rxq == nil || c->txq == nil ||
	   c->rxbuf == nil || c->txbuf == nil)
		return -1;
	memset(c->rxq, 0, sizeof(Vqueue));
	memset(c->txq, 0, sizeof(Vqueue));
	memset(c->rxbuf, 0, sizeof(Buf)*NPKT);
	memset(c->txbuf, 0, sizeof(Buf)*NPKT);

	for(i = 0; i < NPKT; i++){
		/* Receive: 12-byte header then the frame. */
		c->rxq->desc[2*i].addr = PADDR(&c->rxhdr[0]);
		c->rxq->desc[2*i].len = Hdrsz;
		c->rxq->desc[2*i].flags = Dwrite | Dnext;
		c->rxq->desc[2*i].next = 2*i + 1;

		c->rxq->desc[2*i+1].addr = PADDR(&c->rxbuf[i].data[0]);
		c->rxq->desc[2*i+1].len = Bufsz;
		c->rxq->desc[2*i+1].flags = Dwrite;
		c->rxq->desc[2*i+1].next = 0;

		/* Transmit: 12-byte header then the copied frame. */
		c->txq->desc[2*i].addr = PADDR(&c->txhdr[0]);
		c->txq->desc[2*i].len = Hdrsz;
		c->txq->desc[2*i].flags = Dnext;
		c->txq->desc[2*i].next = 2*i + 1;

		c->txq->desc[2*i+1].addr = PADDR(&c->txbuf[i].data[0]);
		c->txq->desc[2*i+1].len = 0;
		c->txq->desc[2*i+1].flags = 0;
		c->txq->desc[2*i+1].next = 0;

		c->txbusy[i] = 0;
	}
	c->txfree = NPKT;

	/* Program queue 0 (receive). */
	q = c->rxq;
	c->cfg->queuesel = Rxq;
	c->cfg->queuesize = QSZ;
	c->cfg->queuedesc = PADDR(q->desc);
	c->cfg->queueavail = PADDR(&q->avail);
	c->cfg->queueused = PADDR(&q->used);

	/* Program queue 1 (transmit). */
	q = c->txq;
	c->cfg->queuesel = Txq;
	c->cfg->queuesize = QSZ;
	c->cfg->queuedesc = PADDR(q->desc);
	c->cfg->queueavail = PADDR(&q->avail);
	c->cfg->queueused = PADDR(&q->used);
	coherence();

	/* MAC address and link state. */
	for(i = 0; i < Eaddrlen; i++){
		if(i < 2)
			edev->ea[i] = i == 0 ? c->dev->mac0 : c->dev->mac0 >> 8;
		else if(i < 4)
			edev->ea[i] = i == 2 ? c->dev->mac1 : c->dev->mac1 >> 8;
		else
			edev->ea[i] = i == 4 ? c->dev->mac2 : c->dev->mac2 >> 8;
	}

	edev->ctlr = c;
	edev->port = c->pa;
	edev->irq = -1;	/* 9vm does not route the PCI INTx line */
	edev->tbdf = p->tbdf;
	edev->mbps = 1000;
	edev->link = 1;
	edev->arg = edev;
	edev->attach = attach;
	edev->transmit = transmit;
	edev->interrupt = interrupt;
	edev->ifstat = ifstat;
	edev->shutdown = shutdown;

	pcisetbme(p);

	return 0;
}

void
ethervirtiolink(void)
{
	addethercard("virtio", reset);
}
