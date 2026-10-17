# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Compile the actual watchdog, receive owner/pass and power lifecycle.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, json, re, subprocess
from driver_sources import _functions
import importlib.util
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tx', ROOT / 'tests/test-wdi-transmit.py')
tx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tx)
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#define NOMINMAX
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <vector>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#undef _IRQL_requires_max_
#undef _Use_decl_annotations_
#define _IRQL_requires_max_(x)
#define _Use_decl_annotations_
#define MAXULONG 0xffffffffu
#define NT_SUCCESS(s) (((LONG)(s))>=0)
typedef LONG NTSTATUS;
#define min(a,b) (((a)<(b))?(a):(b))
#define TraceError(...) ((void)0)
#define TraceWarn(...) ((void)0)
#define TraceInfo(...) ((void)0)
#define TraceVerbose(...) ((void)0)
#define TraceDiag(...) ((void)0)
#define TRACE_NETADAPTER 64
#define TRACE_SDIO 4
#define AP6256_RX_BUFFER_SIZE 65536u
#define AP6256_TX_BUFFER_SIZE 40960u
#define AP6256_POOL_TAG 1u
#define POOL_FLAG_NON_PAGED 0u
#define AP6256_RX_EMPTY_POLLS 5u
#define AP6256_RX_PASS_LIMIT 128u
#define AP6256_RXSKIP_LIMIT_MS 2000u
#define SDIO_CCCR_IEN_FUNC1 2u
#define SDIO_CCCR_IEN_FUNC2 4u
typedef UCHAR KIRQL;
typedef int AP6256_LOCK;
typedef VOID AP6256_WORKITEM_ROUTINE(PVOID);
struct AP6256_WORKITEM {
    bool Item=false; volatile LONG Pending=0,Outstanding=0;
    AP6256_WORKITEM_ROUTINE* Routine=nullptr; PVOID Context=nullptr;
};
struct AP6256_TIMER { AP6256_WORKITEM Work; bool Armed=false; ULONG Due=0; };
static ULONGLONG fixture_time=100000000;
static KIRQL current_irql=0;
static unsigned pending_reads,core_reads,core_writes,acks,headers,controls,events,data,gloms;
static unsigned starts,stops,creates,destroys,wl_stops,wl_destroys,flushes,tx_kicks,halted;
static bool create_failure,late_tick,irq_during_read;
static NTSTATUS pending_status=STATUS_SUCCESS;
static UCHAR pending_byte;
static UINT32 core_status,mailbox_data;
static std::vector<ULONG> reasons;
static std::vector<char> order;
static void KeInitializeSpinLock(KSPIN_LOCK* p) { *p=0; }
static void KeAcquireSpinLock(KSPIN_LOCK* p,KIRQL* old) {
    assert(*p==0);*old=current_irql;current_irql=2;*p=1;
}
static void KeReleaseSpinLock(KSPIN_LOCK* p,KIRQL old) {
    assert(*p==1);*p=0;current_irql=old;
}
static ULONGLONG KeQueryInterruptTime() { return fixture_time; }
static void Ap6256LockAcquire(AP6256_LOCK* p) { assert(current_irql==0);++*p; }
static void Ap6256LockRelease(AP6256_LOCK* p) { assert(*p>0);--*p; }
static bool Ap6256WorkItemValid(const AP6256_WORKITEM* p) { return p->Item; }
static bool Ap6256TimerValid(const AP6256_TIMER* p) { return p->Work.Item; }
static NTSTATUS Ap6256WorkItemCreate(AP6256_WORKITEM* p,PVOID,
    AP6256_WORKITEM_ROUTINE* f,PVOID c) {p->Item=true;p->Routine=f;p->Context=c;return 0;}
static void Ap6256WorkItemMakeCritical(AP6256_WORKITEM*) {}
static void Ap6256WorkItemEnqueue(AP6256_WORKITEM* p) {
    if(!p->Item || InterlockedExchange(&p->Pending,1)) return;
    InterlockedIncrement(&p->Outstanding);
}
static void run_work(AP6256_WORKITEM* p) {
    assert(p->Pending && p->Outstanding && current_irql==0);
    InterlockedExchange(&p->Pending,0);p->Routine(p->Context);
    InterlockedDecrement(&p->Outstanding);
}
static void Ap6256WorkItemFlush(AP6256_WORKITEM* p) {
    assert(current_irql==0);++flushes;order.push_back('F');
    while(p->Pending) run_work(p);
    assert(p->Outstanding==0);
}
static void Ap6256WorkItemDestroy(AP6256_WORKITEM* p) {
    Ap6256WorkItemFlush(p);p->Item=false;order.push_back('D');
}
static NTSTATUS Ap6256TimerCreate(AP6256_TIMER* p,PVOID d,
    AP6256_WORKITEM_ROUTINE* f,PVOID c) {
    ++creates;if(create_failure)return STATUS_INSUFFICIENT_RESOURCES;
    return Ap6256WorkItemCreate(&p->Work,d,f,c);
}
static void Ap6256TimerStart(AP6256_TIMER* p,ULONG due) {
    assert(p->Work.Item);++starts;p->Armed=true;p->Due=due;
}
static void Ap6256TimerStop(AP6256_TIMER* p,BOOLEAN wait) {
    if(!p->Work.Item)return;
    ++stops;p->Armed=false;order.push_back(wait?'W':'C');
    if(wait) {
        assert(current_irql==0);
        if(late_tick) {late_tick=false;p->Work.Routine(p->Work.Context);}
        Ap6256WorkItemFlush(&p->Work);assert(!p->Armed);
    }
}
static void Ap6256TimerDestroy(AP6256_TIMER* p) {
    if(!p->Work.Item)return;
    Ap6256TimerStop(p,TRUE);p->Work.Item=false;++destroys;order.push_back('T');
}
static PVOID ExAllocatePool2(ULONG,ULONG n,ULONG) { return calloc(1,n); }
static void ExFreePoolWithTag(PVOID p,ULONG) {free(p);order.push_back('B');}
static void Ap6256TraceWatchdog(ULONG,ULONG reason,NTSTATUS,ULONG,ULONG,
    ULONGLONG,ULONGLONG,ULONGLONG) {reasons.push_back(reason);}
'''
DEVICE = r'''
enum { Ap6256FwNotLoaded,Ap6256FwRunning,Ap6256FwError };
struct Core { UINT32 Base=0x18002000; };
struct _AP6256_DEVICE_CONTEXT {
    PVOID Fdo=(PVOID)1;
    bool DatapathRunning=false,RxSkip=false,RxBatching=false;
    ULONG GlomCount=0,GlomTotalLength=0,GlomErrors=0,RxNextLength=0,RxBatched=0;
    ULONGLONG RxSkipSince=0;
    UCHAR* RxScratch=nullptr;ULONG RxScratchSize=0;
    UCHAR* TxScratch=nullptr;ULONG TxScratchSize=0;
    AP6256_WORKITEM FrameWorker;AP6256_WATCHDOG Watchdog={};
    volatile LONG FrameDraining=0,FrameRerun=0,IsrHeldOff=0,FirmwareHalted=0;
    int FirmwareState=Ap6256FwRunning;
    struct {Core* SdiodCore=nullptr;} Chip;
    struct {
        volatile LONG IsrCount=0;
        bool Sleeping=false,ClockOn=true,TxFlowStopped=false,TxGlom=false;
        PVOID BusInterface=(PVOID)1;AP6256_LOCK Lock=0,TxLock=0;
        KSPIN_LOCK TxStateLock=0;
        UCHAR TxSeq=0,RxSeq=0,MaxTxSeq=0,FlowControl=0;ULONG TxGlomBytes=0;
        volatile LONGLONG StatPasses=0,StatEmptyPolls=0,StatRxFrames=0;
        ULONGLONG StatPrintedAt=0;
    } Sdio;
};
typedef _AP6256_DEVICE_CONTEXT* PAP6256_DEVICE_CONTEXT;
typedef _AP6256_DEVICE_CONTEXT Device;
struct Frame { UCHAR Channel;std::vector<UCHAR> Bytes; };
static std::vector<Frame> fifo;static Frame serving;
static void Ap6256FrameWorker(PVOID);
static NTSTATUS Ap6256WlfcCreate(Device*) {return STATUS_SUCCESS;}
static void Ap6256WlfcStop(Device*) {++wl_stops;}
static void Ap6256WlfcDestroy(Device*) {++wl_destroys;}
static void Ap6256NetTxKick(Device*) {++tx_kicks;}
static void Ap6256NetRxFlush(Device*) {}
static void Ap6256SdioTraceBusStats(Device*) {}
static void Ap6256SdBusAckInterrupt(Device*) {++acks;}
static void Ap6256FirmwareHalt(Device* c,UINT32,UINT32) {
    ++halted;c->FirmwareHalted=1;c->FirmwareState=Ap6256FwError;
}
static NTSTATUS Ap6256SdioReadF0(Device* c,ULONG address,UCHAR* b) {
    assert(current_irql==0 && !c->Sdio.Sleeping && c->DatapathRunning);
    assert(address==5);++pending_reads;*b=pending_byte;
    if(irq_during_read) {
        irq_during_read=false;InterlockedIncrement(&c->Sdio.IsrCount);
        Ap6256FrameWorker(c);assert(c->FrameRerun);
    }
    return pending_status;
}
static NTSTATUS Ap6256SdioReadBackplane32(Device* c,UINT32 address,UINT32* b) {
    assert(current_irql==0 && !c->Sdio.Sleeping && c->DatapathRunning);
    ++core_reads;
    *b=(address==c->Chip.SdiodCore->Base+SD_REG_TOHOSTMAILBOXDATA)?mailbox_data:core_status;
    return STATUS_SUCCESS;
}
static NTSTATUS Ap6256SdioWriteBackplane32(Device* c,UINT32 address,UINT32 value) {
    assert(!c->Sdio.Sleeping);++core_writes;
    if(address==c->Chip.SdiodCore->Base+SD_REG_INTSTATUS) core_status &= ~value;
    return STATUS_SUCCESS;
}
static NTSTATUS Ap6256ReadSdpcmFrame(Device* c,PUCHAR* b,ULONG* n,UCHAR* channel,
    ULONG* transfer,ULONG* offset) {
    assert(c->Sdio.Lock==1 && c->FrameDraining && !c->Sdio.Sleeping);++headers;
    if(fifo.empty()) return STATUS_NO_MORE_ENTRIES;
    serving=fifo.front();fifo.erase(fifo.begin());*b=serving.Bytes.data();
    *n=ULONG(serving.Bytes.size());*channel=serving.Channel;*transfer=*n;*offset=0;
    return STATUS_SUCCESS;
}
static void Ap6256BcdcProcessControlFrame(Device*,PUCHAR b,ULONG n) {
    assert(n==4 && b[0]==0xc0);++controls;
}
static void Ap6256DispatchBcdcFrame(Device*,UCHAR channel,PUCHAR b,ULONG n) {
    assert(n==4);if(channel==SDPCM_EVENT_CHANNEL){assert(b[0]==0xe0);++events;}
    else{assert(channel==SDPCM_DATA_CHANNEL && b[0]==0xd0);++data;}
}
static NTSTATUS Ap6256StoreGlomDescriptor(Device*,PUCHAR,ULONG) {++gloms;return 0;}
static NTSTATUS Ap6256HandleGlomSuperframe(Device*,ULONG,ULONG) {++gloms;return 0;}
'''
TEST = r'''
static Core core;
static void reset() {
    pending_reads=core_reads=core_writes=acks=headers=controls=events=data=gloms=0;
    starts=stops=creates=destroys=wl_stops=wl_destroys=flushes=tx_kicks=halted=0;
    create_failure=late_tick=irq_during_read=false;pending_status=0;
    pending_byte=0;core_status=mailbox_data=0;reasons.clear();order.clear();fifo.clear();
    current_irql=0;fixture_time=100000000;
}
static void start(Device* c) {
    c->Chip.SdiodCore=&core;assert(Ap6256DatapathInit(c)==0);
    c->Sdio.StatPrintedAt=123;
    Ap6256DatapathStart(c);assert(c->Sdio.StatPrintedAt==0);run_work(&c->FrameWorker);reset();
}
static void tick(Device* c) {
    if(!c->Watchdog.Timer.Armed)return;
    fixture_time+=ULONGLONG(c->Watchdog.Timer.Due)*10000;
    c->Watchdog.Timer.Armed=false;c->Watchdog.Timer.Work.Routine(c);
}
static void drain(Device* c) {while(c->FrameWorker.Pending)run_work(&c->FrameWorker);}
static void packets() {
    pending_byte=4;core_status=I_HMB_FRAME_IND;
    fifo.push_back({SDPCM_CONTROL_CHANNEL,{0xc0,1,2,3}});
    fifo.push_back({SDPCM_EVENT_CHANNEL,{0xe0,1,2,3}});
    fifo.push_back({SDPCM_DATA_CHANNEL,{0xd0,1,2,3}});
}
int main(int argc,char** argv) {
    bool negative=argc>1 && strcmp(argv[1],"negative")==0;
    reset();Device c;start(&c);
    packets();tick(&c);drain(&c);

    assert(controls==1 && events==1 && data==1 && fifo.empty());
    if(negative)return 0;
    assert(c.Sdio.IsrCount==0 && c.Watchdog.Recoveries==1 && acks==1);
    assert(reasons.back()==2);
    reset();tick(&c);drain(&c);assert(pending_reads==1 && !core_reads && !acks);
    assert(c.Watchdog.Timer.Due==AP6256_WATCHDOG_ACTIVE_MS);
    fixture_time+=AP6256_WATCHDOG_ACTIVE_WINDOW;tick(&c);drain(&c);
    tick(&c);assert(c.Watchdog.Timer.Due==AP6256_WATCHDOG_IDLE_MS);drain(&c);

    reset();InterlockedIncrement(&c.Sdio.IsrCount);tick(&c);
    assert(!c.FrameWorker.Pending && !pending_reads);
    c.FrameDraining=1;tick(&c);assert(!c.FrameWorker.Pending);c.FrameDraining=0;
    Ap6256WorkItemEnqueue(&c.FrameWorker);tick(&c);assert(!c.Watchdog.PollRequested);drain(&c);

    reset();tick(&c);InterlockedIncrement(&c.Sdio.IsrCount);packets();drain(&c);
    assert(!pending_reads && controls==1 && acks==1);
    reset();tick(&c);drain(&c);
    reset();tick(&c);packets();pending_byte=0;irq_during_read=true;drain(&c);
    assert(controls==1 && events==1 && data==1 && acks==1 && c.FrameDraining==0);

    reset();Ap6256WatchdogStart(&c);reasons.clear();pending_status=STATUS_CRC_ERROR;
    for(unsigned i=0;i<130;i++){tick(&c);drain(&c);}
    assert(pending_reads==130 && !core_reads && !acks);
    assert(std::count(reasons.begin(),reasons.end(),ULONG(4))==3);
    assert(c.Watchdog.ReadFailures==130);
    pending_status=0;pending_byte=8;tick(&c);drain(&c);assert(!core_reads && !acks);
    packets();tick(&c);drain(&c);assert(controls==1 && acks==1);

    reset();Ap6256WatchdogStart(&c);c.RxSkip=true;c.RxSkipSince=fixture_time;
    tick(&c);drain(&c);
    assert(c.RxSkip && pending_reads==1 && !headers && !core_reads && !acks);
    c.RxSkip=false;


    reset();c.Sdio.IsrCount=MAXLONG;c.Watchdog.LastIsr=MAXLONG;
    InterlockedIncrement(&c.Sdio.IsrCount);tick(&c);
    assert(!c.FrameWorker.Pending && !pending_reads && c.Watchdog.LastIsr==MINLONG);


    reset();pending_byte=4;core_status=I_HMB_FRAME_IND;
    for(unsigned i=0;i<AP6256_RX_PASS_LIMIT+1;++i)
        fifo.push_back({SDPCM_DATA_CHANNEL,{0xd0,1,2,3}});
    tick(&c);drain(&c);assert(data==AP6256_RX_PASS_LIMIT && fifo.size()==1);
    core_status=I_HMB_FRAME_IND;tick(&c);drain(&c);
    assert(data==AP6256_RX_PASS_LIMIT+1 && fifo.empty() && acks==2);

    reset();Ap6256WatchdogStart(&c);c.RxSkip=true;c.RxSkipSince=fixture_time;
    fixture_time+=1750ull*10000ull;tick(&c);
    fifo.push_back({SDPCM_CONTROL_CHANNEL,{0xc0,1,2,3}});drain(&c);
    assert(controls==1 && !c.RxSkip && reasons.back()==3 && acks==1);

    reset();c.Sdio.MaxTxSeq=19;c.Sdio.TxSeq=7;
    tick(&c);late_tick=true;Ap6256DatapathSuspend(&c);
    c.Sdio.Sleeping=true;LONG queued=c.FrameWorker.Outstanding;
    c.Watchdog.Timer.Work.Routine(&c);drain(&c);
    assert(!pending_reads && !core_reads && !c.Watchdog.Timer.Armed);
    assert(c.FrameWorker.Outstanding==queued && !wl_stops);
    assert(c.Sdio.MaxTxSeq==19 && c.Sdio.TxSeq==7);
    c.Sdio.Sleeping=false;Ap6256DatapathResume(&c);drain(&c);
    assert(c.Watchdog.Timer.Armed && c.Watchdog.Enabled);

    reset();pending_byte=2;core_status=I_HMB_HOST_INT;mailbox_data=HMB_DATA_FWHALT;
    tick(&c);drain(&c);assert(halted==1 && !c.Watchdog.Timer.Armed);
    c.Watchdog.Timer.Work.Routine(&c);assert(!c.FrameWorker.Pending);
    Ap6256DatapathStop(&c);Ap6256DatapathDestroy(&c);
    assert(!c.Watchdog.Timer.Work.Item && !c.FrameWorker.Item && !c.RxScratch && !c.TxScratch);
    auto timer=std::find(order.begin(),order.end(),'T');
    auto frame=std::find(order.begin(),order.end(),'D');assert(timer<frame);
    Ap6256DatapathDestroy(&c);

    reset();Device failure;failure.Chip.SdiodCore=&core;create_failure=true;
    assert(Ap6256DatapathInit(&failure)==STATUS_INSUFFICIENT_RESOURCES);
    Ap6256DatapathStop(&failure);Ap6256DatapathDestroy(&failure);
    assert(!failure.FrameWorker.Item && !failure.RxScratch && !failure.TxScratch);

    for(unsigned gate=0;gate<7;++gate) {
        reset();Device idle;start(&idle);
        switch(gate) {
        case 0:idle.DatapathRunning=false;break;
        case 1:idle.Sdio.Sleeping=true;break;
        case 2:idle.Sdio.ClockOn=false;break;
        case 3:idle.Sdio.BusInterface=nullptr;break;
        case 4:idle.Chip.SdiodCore=nullptr;break;
        case 5:idle.FirmwareState=Ap6256FwError;break;
        default:idle.FirmwareHalted=1;break;
        }
        tick(&idle);assert(!Ap6256WatchdogCheckPending(&idle));
        assert(!idle.Watchdog.Enabled && !idle.Watchdog.Timer.Armed);
        assert(!idle.FrameWorker.Pending && !pending_reads && !core_reads && !acks);
        Ap6256DatapathStop(&idle);Ap6256DatapathDestroy(&idle);
    }
    puts("watchdog production lifecycle, missed IRQ, IRQ race, NAK, failure and retention cases passed");
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=output_dir('interrupt-watchdog'))
    args = parser.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    source = None or ROOT
    hdr = (ROOT / 'src/common/watchdog.h').read_text(encoding='utf-8-sig')
    hdr = re.sub('^#(?:include|pragma)[^\\n]*', '', hdr, flags=re.M)
    sdpcm = re.sub('^#(?:include|pragma)[^\\n]*', '', (ROOT / 'src/common/sdpcm.h').read_text(encoding='utf-8-sig'), flags=re.M)
    funcs = _functions((source / 'src/common/datapath.c').read_text(encoding='utf-8-sig'))
    names = ['Ap6256DatapathInit', 'Ap6256DatapathStart', 'Ap6256DatapathStop', 'Ap6256DatapathDestroy', 'Ap6256ProcessHostMailbox', 'Ap6256FramePass', 'Ap6256FrameWorker', 'Ap6256DatapathSuspend', 'Ap6256DatapathResume']
    watchdog = re.sub('^#include[^\\n]*', '', (ROOT / 'src/common/watchdog.c').read_text(encoding='utf-8-sig'), flags=re.M)
    code = PRE + '\n' + sdpcm + '\n' + hdr + DEVICE + '\n' + watchdog + '\n' + '\n'.join((funcs[n] for n in names)) + TEST
    generated = out / 'tests.cpp'
    write_text(generated, code, encoding='utf-8')
    command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(tx.VC / 'include')] + ['/I' + str(tx.INC / f) for f in ('ucrt', 'shared', 'um')] + [str(generated), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    result = subprocess.run(command, capture_output=True, text=True)
    write_text(out / 'compile.log', result.stdout + result.stderr, encoding='utf-8')
    if result.returncode:
        print(result.stdout + result.stderr)
        raise SystemExit(result.returncode)
    run = subprocess.run([str(out / 'tests.exe')] + [], capture_output=True, text=True)
    write_text(out / 'run.log', run.stdout + run.stderr, encoding='utf-8')
    receipt = {'passed': run.returncode == 0, 'exit_code': run.returncode, 'before': bool(None), 'source_sha256': {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [source / 'src/common/datapath.c']}, 'watchdog_sha256': hashlib.sha256((ROOT / 'src/common/watchdog.c').read_bytes()).hexdigest(), 'fixtures': ['timer/work scheduling', 'SDIO register/FIFO', 'OS consumers'], 'board_tested': False}
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2), encoding='utf-8')
    print(run.stdout + run.stderr)
    raise SystemExit(run.returncode)
if __name__ == '__main__':
    main()
