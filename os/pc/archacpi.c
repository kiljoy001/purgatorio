#include "u.h"
#include "../port/lib.h"
#include "mem.h"
#include "dat.h"
#include "fns.h"
#include "io.h"
#include "mp.h"

/*
 * ACPI (MADT) detection of the local APIC and I/O APICs, replacing the
 * legacy MP configuration table search which modern firmware (and 9vm)
 * no longer provide.
 *
 * The MADT lives in the reserved BIOS area (0xE0000-0xFFFFF) which the
 * kernel only maps early (before mmuinit). We therefore walk it during
 * identify() and remember the APIC MMIO addresses for acpiinit().
 */

typedef struct Rsd Rsd;
typedef struct Tbl Tbl;

struct Rsd {
	uchar	sig[8];
	uchar	csum;
	uchar	oemid[6];
	uchar	rev;
	uchar	raddr[4];
	uchar	len[4];
	uchar	xaddr[8];
	uchar	xcsum;
	uchar	reserved[3];
};

struct Tbl {
	uchar	sig[4];
	uchar	len[4];
	uchar	rev;
	uchar	csum;
	uchar	oemid[6];
	uchar	oemtid[8];
	uchar	oemrev[4];
	uchar	cid[4];
	uchar	crev[4];
	uchar	data[];
};

enum {
	Tblsz	= 4+4+1+1+6+8+4+4+4,	/* 36 byte ACPI table header */
};

static Rsd *rsd;
static ulong acpilapic;				/* local APIC MMIO address */
static ulong acpiioapic[MaxAPICNO+1];		/* I/O APIC MMIO addresses */
static int acpiioapicno[MaxAPICNO+1];		/* I/O APIC ids */
static int nacpiioapic;

static ushort
get16(uchar *p)
{
	return p[1]<<8 | p[0];
}

static ulong
get32(uchar *p)
{
	return p[3]<<24 | p[2]<<16 | p[1]<<8 | p[0];
}

static uvlong
get64(uchar *p)
{
	return (uvlong)get32(p+4)<<32 | get32(p);
}

static int
acpichecksum(void *v, int len)
{
	uchar *p;
	int sum;

	sum = 0;
	for(p = v; len-- > 0; p++)
		sum += *p;
	return sum & 0xFF;
}

static Rsd*
rsdsearch(void)
{
	uchar *p;
	Rsd *r;

	/*
	 * Scan the BIOS area for the "RSD PTR " signature, 16-byte aligned.
	 */
	for(p = KADDR(0xE0000); p < KADDR(0x100000); p += 16){
		if(memcmp(p, "RSD PTR ", 8) == 0){
			r = (Rsd*)p;
			if(acpichecksum(r, 20) == 0)
				return r;
		}
	}
	return nil;
}

/*
 * Find an ACPI table by signature, walking the RSDT (and XSDT if the
 * RSDP revision is >= 2 and the 64-bit address is provided).
 */
static Tbl*
findtable(char *sig)
{
	Tbl *t;
	uchar *p, *e;
	ulong l, pa;

	if(rsd == nil)
		return nil;

	/* RSDT (32-bit pointers) */
	pa = get32(rsd->raddr);
	if(pa != 0){
		t = KADDR(pa);
		if(acpichecksum(t, get32(t->len)) == 0){
			l = get32(t->len) - Tblsz;
			p = t->data;
			e = p + l;
			for(; p+4 <= e; p += 4){
				Tbl *x = KADDR(get32(p));
				if(memcmp(x->sig, sig, 4) == 0
				&& acpichecksum(x, get32(x->len)) == 0)
					return x;
			}
		}
	}

	/* XSDT (64-bit pointers), if present */
	if(rsd->rev >= 2 && get64(rsd->xaddr) != 0){
		t = KADDR(get64(rsd->xaddr));
		if(acpichecksum(t, get32(t->len)) == 0){
			l = get32(t->len) - Tblsz;
			p = t->data;
			e = p + l;
			for(; p+8 <= e; p += 8){
				Tbl *x = KADDR(get64(p));
				if(memcmp(x->sig, sig, 4) == 0
				&& acpichecksum(x, get32(x->len)) == 0)
					return x;
			}
		}
	}

	return nil;
}

/*
 * Walk the MADT and remember the local APIC and I/O APIC addresses.
 * Called from identify(), before mmuinit() unmaps the BIOS area.
 */
static void
parsemadt(Tbl *t)
{
	uchar *s, *p, *e;
	int c;

	s = t->data;
	e = s + get32(t->len) - Tblsz;
	if(s + 8 > e)
		return;
	acpilapic = get32(s);
	s += 8;

	for(p = s; p < e; p += c){
		c = p[1];
		if(c < 2 || p+c > e)
			break;
		switch(*p){
		case 0x01:	/* I/O APIC */
			if(p[2] > MaxAPICNO || nacpiioapic >= MaxAPICNO)
				break;
			acpiioapicno[nacpiioapic] = p[2];
			acpiioapic[nacpiioapic] = get32(p+4);
			nacpiioapic++;
			break;
		}
	}
}

static void
acpiinit(void)
{
	Apic *apic, bp;
	int i;

	if(acpilapic == 0)
		return;
	if(mmukmap(acpilapic, 0, 1024) == 0)
		return;

	/* I/O APICs */
	for(i = 0; i < nacpiioapic; i++){
		if(mmukmap(acpiioapic[i], 0, 1024) == 0)
			continue;
		apic = &mpapic[acpiioapicno[i]];
		apic->type = PcmpIOAPIC;
		apic->apicno = acpiioapicno[i];
		apic->addr = KADDR(acpiioapic[i]);
		apic->flags = PcmpEN;
		ioapicinit(apic, acpiioapicno[i]);
	}

	/*
	 * Default ISA interrupt routing: the MADT only overrides the
	 * non-standard mappings; the legacy IRQs 0-15 default to I/O APIC
	 * inputs 0-15 (edge-triggered, active-high). Build the bus and
	 * assignment entries so mpintrenable can route them (e.g. the UART
	 * on IRQ 4).
	 */
	if(nacpiioapic > 0){
		PCMPbus b;
		PCMPintr *ip;
		int n;

		memset(&b, 0, sizeof(b));
		b.type = PcmpBUS;
		b.busno = 0;
		memcpy(b.string, "ISA   ", sizeof(b.string));
		mkbus(&b);

		for(n = 0; n <= MaxIrqPIC; n++){
			ip = xalloc(sizeof(PCMPintr));
			ip->type = PcmpIOINTR;
			ip->intr = PcmpINT;
			ip->flags = PcmpEDGE|PcmpHIGH;
			ip->busno = 0;
			ip->irq = n;
			ip->apicno = acpiioapicno[0];
			ip->intin = n;
			mkiointr(ip);
		}
	}

	/* Local APIC: the boot processor is apic id 0 */
	memset(&bp, 0, sizeof(bp));
	bp.type = PcmpPROCESSOR;
	bp.apicno = 0;
	bp.addr = KADDR(acpilapic);
	bp.flags = PcmpBP|PcmpEN;
	mpapic[0].type = PcmpPROCESSOR;
	mpapic[0].apicno = 0;
	mpapic[0].addr = KADDR(acpilapic);
	mpapic[0].flags = PcmpBP|PcmpEN;
	mpapic[0].machno = 0;
	machno2apicno[0] = 0;

	lapicinit(&bp);

	intrenable(IrqTIMER, lapicclock, 0, BUSUNKNOWN, "clock");
	intrenable(IrqERROR, lapicerror, 0, BUSUNKNOWN, "lapicerror");
	intrenable(IrqSPURIOUS, lapicspurious, 0, BUSUNKNOWN, "lapicspurious");
	lapiconline();
}

static int
identify(void)
{
	Tbl *t;

	rsd = rsdsearch();
	if(rsd == nil)
		return 1;
	if((t = findtable("APIC")) == nil)
		return 1;
	parsemadt(t);
	return 0;
}

PCArch archacpi = {
	.id=		"ACPI",
	.ident=		identify,
	.reset=		mpshutdown,
	.intrinit=	acpiinit,
	.intrenable=	mpintrenable,
	.fastclock=	i8253read,
	.timerset=	lapictimerset,
};
