# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Inject a firmware halt through production mailbox/control/recovery functions.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, subprocess
AP = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('control', AP / 'tests/test-control-retry.py')
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)
from driver_sources import _functions
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
MOCK = r'''
typedef LONG NDIS_STATUS;
typedef PVOID NDIS_HANDLE;
typedef UINT16 WDI_PORT_ID;
typedef ULONG eDiagnoseLevel;
#define NDIS_STATUS_SUCCESS 0
#define NDIS_OBJECT_TYPE_STATUS_INDICATION 0x81
#define NDIS_STATUS_INDICATION_REVISION_1 1
#define NDIS_SIZEOF_STATUS_INDICATION_REVISION_1 sizeof(NDIS_STATUS_INDICATION)
#define NDIS_STATUS_WDI_INDICATION_FIRMWARE_STALLED (WDI_INDICATION_PREFIX | WDI_INDICATION_FIRMWARE_STALLED)
struct NDIS_STATUS_INDICATION {
    struct { UCHAR Type,Revision;USHORT Size; } Header;
    PVOID SourceHandle,RequestId;ULONG PortNumber,StatusCode;PVOID StatusBuffer;ULONG StatusBufferSize;
};
struct AP6256_HANG_DIAGNOSIS { int Lock; AP6256_FW_CRASH Crash; };
static AP6256_HANG_DIAGNOSIS Ap6256HangDiagnosis;
struct Wifi { volatile LONG Stopping,HardwareAvailable;BOOLEAN SoftwareRadioState;int ConnectLock; };
typedef Wifi* PAP6256_WIFI;
static Wifi fixture_wifi;
static PAP6256_WIFI Ap6256WifiFromDevice(Device*) { return &fixture_wifi; }
static std::vector<UINT32> memory_reads;
static std::vector<char> order;
static std::vector<UCHAR> ram(0xc0000),rom_memory(0xb0000);
static UINT32 failed_address,mailbox_value=0x40012;
static NTSTATUS ack_status=STATUS_SUCCESS;
static unsigned indications,publishes,acks,halt_at;
static bool halt_on_write,halt_on_mbo;
static bool console_tail_stalls;
static Device* startup_device;
VOID Ap6256FirmwareHalt(Device*,UINT32,UINT32);
static NTSTATUS Ap6256WifiSetRadioState(Device*,BOOLEAN) { return STATUS_SUCCESS; }
static NTSTATUS Ap6256ModelStartInterfaces(PAP6256_WIFI,Device*) { return STATUS_SUCCESS; }
static NTSTATUS Ap6256MboInitialize(PAP6256_WIFI) {
    if(halt_on_mbo) Ap6256FirmwareHalt(startup_device,0x40012,1);
    return halt_on_mbo ? STATUS_DEVICE_HARDWARE_ERROR : STATUS_SUCCESS;
}
static void Ap6256NetTxKick(Device*) {}
static NTSTATUS Ap6256SdioReadBackplane32(Device* c,UINT32 addr,UINT32* out) {
    if(addr>=c->Chip.RamBase && addr-c->Chip.RamBase<ram.size()) {
        assert(indications==1 && !c->Bcdc.Pending && c->Bcdc.ResponseEvent);
        memory_reads.push_back(addr);
        if(addr==failed_address) return STATUS_CRC_ERROR;
        assert(!(addr&3) && addr-c->Chip.RamBase<=ram.size()-4);
        memcpy(out,ram.data()+addr-c->Chip.RamBase,4);return STATUS_SUCCESS;
    }
    *out=mailbox_value;return STATUS_SUCCESS;
}
static NTSTATUS Ap6256SdioWriteBackplane32(Device*,UINT32,UINT32) { ++acks;return ack_status; }
static NTSTATUS Ap6256SdioRamRW(Device* c,BOOLEAN write,UINT32 addr,PUCHAR buffer,ULONG n) {
    assert(!write && !c->Bcdc.ResponseLock && !c->Sdio.TxStateLock);


    if(c->FirmwareHalted && c->FirmwareCrash.Magic) {
        assert(indications==1 && !c->Bcdc.Pending && c->Bcdc.ResponseEvent);
        assert(Ap6256HangDiagnosis.Crash.Magic==AP6256_CRASH_MAGIC);
    }
    memory_reads.push_back(addr);
    if(addr==failed_address) return STATUS_CRC_ERROR;
    if(console_tail_stalls && n==97) return STATUS_IO_TIMEOUT;
    if(addr<c->Chip.RamBase) {
        assert(addr<=rom_memory.size() && n<=rom_memory.size()-addr);memcpy(buffer,rom_memory.data()+addr,n);
    } else {
        auto off=addr-c->Chip.RamBase;
        assert(off<=ram.size() && n<=ram.size()-off);memcpy(buffer,ram.data()+off,n);
    }
    return STATUS_SUCCESS;
}
static void NdisMIndicateStatusEx(PVOID,NDIS_STATUS_INDICATION* i) {
    assert(i->StatusCode==NDIS_STATUS_WDI_INDICATION_FIRMWARE_STALLED && i->StatusBufferSize==sizeof(WDI_MESSAGE_HEADER));
    auto h=(WDI_MESSAGE_HEADER*)i->StatusBuffer;
    assert(h->PortId==0xffff && h->Status==0 && h->TransactionId==0 && h->Reserved==0 && h->IhvSpecificId==0);
    assert(i->RequestId==nullptr && i->PortNumber==0 && fixture_wifi.HardwareAvailable==0);
    assert(Ap6256HangDiagnosis.Crash.Magic==AP6256_CRASH_MAGIC && publishes==1);
    order.push_back('I');++indications;
}
'''
TEST = r'''
static Device setup() {
    static UCHAR tx[4096],rx[4096];Device c={};
    c.DatapathRunning=TRUE;c.FirmwareState=2;c.TxScratchSize=40960;c.MiniportHandle=(PVOID)1;
    c.Sdio.TxSeq=255;c.Sdio.MaxTxSeq=0;c.Sdio.Function2BlockSize=512;c.Sdio.MaxTransferBytes[2]=32768;
    c.Bcdc.IoctlBuffer=tx;c.Bcdc.ResponseBuffer=rx;c.Bcdc.IoctlBufferSize=sizeof(tx);
    c.Bcdc.ResponseBufferSize=sizeof(rx);c.Bcdc.Initialized=TRUE;c.Bcdc.RequestId=40;
    c.Chip.ChipId=0x4345;c.Chip.ChipRev=9;c.Chip.RamBase=0x198000;c.Chip.RamSize=ULONG(ram.size());
    c.Chip.SharedAddress=0x19a000;memcpy(c.MacAddress,"\x02\x01\x02\x03\x04\x05",6);
    memset(tx,0,sizeof(tx));memset(rx,0,sizeof(rx));std::fill(ram.begin(),ram.end(),UCHAR(0));std::fill(rom_memory.begin(),rom_memory.end(),UCHAR(0));
    memory_reads.clear();order.clear();logs.clear();writes.clear();write_results.clear();operations.clear();
    waits=delays=terminations=firmware_commands=grant_at=stop_at=0;
    indications=publishes=acks=halt_at=0;failed_address=0;mailbox_value=0x40012;ack_status=STATUS_SUCCESS;console_tail_stalls=false;
    reply=true;firmware_error=stop_on_failure=halt_on_write=halt_on_mbo=force_wait_timeout=false;waiting_device=nullptr;wait_hook=nullptr;
    fixture_wifi.Stopping=FALSE;fixture_wifi.HardwareAvailable=1;fixture_wifi.SoftwareRadioState=TRUE;fixture_wifi.ConnectLock=0;
    Ap6256HangDiagnosis={};return c;
}
static NTSTATUS command(Device* c) { UINT32 on=1;return Ap6256BcdcSetIovar(c,"bus:rxglom",&on,4); }
static void install(Device* c) {
    SDPCM_SHARED sh={};sh.Flags=3|SDPCM_SHARED_TRAP|SDPCM_SHARED_ASSERT;
    sh.TrapAddress=0x19b000;sh.AssertFileAddress=0x10000;sh.AssertExpressionAddress=0x19c000;
    sh.AssertLine=77;sh.ConsoleAddress=0x19d000;
    memcpy(ram.data()+0x2000,&sh,sizeof(sh));
    AP6256_FW_TRAP t={};t.Type=4;t.Epc=0x22b37e;t.Pc=0x22b3a4;t.Lr=0x6ee85;t.Sp=0x239000;t.Registers[0]=123;
    memcpy(ram.data()+0x3000,&t,sizeof(t));
    memcpy(rom_memory.data()+0x10000,"wlc_bsscfg.c",13);memcpy(ram.data()+0x4000,"cfg != NULL",12);
    UINT32 con[]={0x19e000,12,4};memcpy(ram.data()+0x5008,con,sizeof(con));memcpy(ram.data()+0x6000,"ijklABCDEFGH",12);
    (void)c;
}
static void halt_waiter() { Ap6256FirmwareHalt(waiting_device,0x40012,1); }
#ifdef HAS_HOST_CRASH_PREPARE
static void boundary_waiter() {
    if(waits==1) { waiting_device->FirmwareHalted=1;return; }
    assert(waits==2);
    Ap6256PrepareFirmwareCrash(waiting_device,0x40012,1);
    Ap6256ModelRecordFirmwareCrash(waiting_device);
    Ap6256NetFirmwareHalted(waiting_device);
    Ap6256BcdcFirmwareHalted(waiting_device);
}
#endif
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    auto c=setup();install(&c);halt_on_write=true;
    assert(command(&c)==STATUS_DEVICE_HARDWARE_ERROR);
    assert(c.FirmwareHalted==1 && c.FirmwareState==3 && c.Bcdc.Pending==FALSE);
    assert(c.HostCipherStore==1 && c.HostCipherFirmwareQualified==0);
    assert(indications==1 && publishes==2 && order==std::vector<char>({'P','I','A','P'}));
    auto crash=c.FirmwareCrash;
    assert(crash.Valid==31 && crash.Size==sizeof(crash) && crash.Trap.Pc==0x22b3a4 && crash.Trap.Registers[0]==123);
    assert(crash.Command==263 && crash.RequestId==41 && crash.Set==1 && !strcmp(crash.Iovar,"bus:rxglom"));
    assert(!strcmp(crash.AssertFile,"wlc_bsscfg.c") && !strcmp(crash.AssertExpression,"cfg != NULL"));
    assert(crash.ConsoleLength==12 && !memcmp(crash.Console,"ABCDEFGHijkl",12));
    assert(!c.Bcdc.Lock && !c.Bcdc.ResponseLock && !c.Sdio.TxLock && !c.Sdio.TxStateLock);
    assert(command(&c)==STATUS_DEVICE_HARDWARE_ERROR && writes.size()==1 && waits==1 && delays==0);
    UINT32 value=0;AP6256_BCDC_QUERY_RESULT result={};
    assert(Ap6256BcdcDcmdWithResult(&c,262,FALSE,0,&value,4,&result)==STATUS_DEVICE_HARDWARE_ERROR && !result.FirmwareReply);
    auto reads=memory_reads.size();Ap6256FirmwareHalt(&c,0x40012,1);
    assert(indications==1 && memory_reads.size()==reads);
    puts("PASS: in-flight command abort, complete bounded crash capture, indication-before-completion, duplicate halt and fail-fast GET/SET");

    UCHAR blob[1025];memset(blob,0xa5,sizeof(blob));UINT32 count=99;
    assert(Ap6256WdiHangDiagnose(&Ap6256HangDiagnosis,0,1024,blob,&count)==0 && count==sizeof(crash));
    assert(!memcmp(blob,&crash,sizeof(crash)) && blob[count]==0xa5);
    Ap6256WdiHangDiagnose(&Ap6256HangDiagnosis,0,1,blob,&count);assert(count==0);
    Ap6256WdiHangDiagnose(&c,0,1024,blob,&count);assert(count==0);
    Ap6256WdiHangDiagnose(&Ap6256HangDiagnosis,0,1024,nullptr,&count);assert(count==0);
    c={};Ap6256WdiHangDiagnose(&Ap6256HangDiagnosis,0,1024,blob,&count);assert(count==sizeof(crash));
    puts("PASS: HangDiagnose uses driver context; bounded output survives adapter teardown and rejects small/invalid buffers");

    c=setup();install(&c);waiting_device=&c;reply=false;wait_hook=halt_waiter;
    assert(command(&c)==STATUS_DEVICE_HARDWARE_ERROR && waits==1 && indications==1);
    c=setup();install(&c);waiting_device=&c;c.Sdio.MaxTxSeq=255;halt_at=1;
    assert(command(&c)==STATUS_DEVICE_HARDWARE_ERROR && delays==1 && waits==0 && writes.empty());
    puts("PASS: halt interrupts reply wait and closed SDPCM credit window without waiting five seconds or 1500 ms");

    c=setup();install(&c);UINT32 isr=0x80;
    assert(Ap6256ProcessHostMailbox(&c,0x18002000,&isr)==STATUS_DEVICE_HARDWARE_ERROR && acks==1 && indications==1);
    assert(Ap6256ProcessHostMailbox(&c,0x18002000,&isr)==STATUS_DEVICE_HARDWARE_ERROR && indications==1);
    c=setup();install(&c);ack_status=STATUS_CRC_ERROR;
    assert(Ap6256ProcessHostMailbox(&c,0x18002000,&isr)==STATUS_DEVICE_HARDWARE_ERROR && indications==1);
    c=setup();mailbox_value=0;ack_status=STATUS_CRC_ERROR;
    assert(Ap6256ProcessHostMailbox(&c,0x18002000,&isr)==STATUS_CRC_ERROR && !c.FirmwareHalted && indications==0);
    c=setup();c.Chip.SharedAddress=0xfffffff0;
    Ap6256FirmwareHalt(&c,0x40012,1);assert(memory_reads.empty() && c.FirmwareCrash.SharedStatus==STATUS_INVALID_ADDRESS && indications==1);
    c=setup();install(&c);failed_address=c.Chip.SharedAddress;
    Ap6256FirmwareHalt(&c,0x40012,1);assert(memory_reads.size()==1 && c.FirmwareCrash.Valid==0 && indications==1);
    c=setup();install(&c);auto sh=(SDPCM_SHARED*)(ram.data()+0x2000);
    sh->TrapAddress=0x18000000;sh->AssertFileAddress=0xffffffff;sh->AssertExpressionAddress=0;sh->ConsoleAddress=0xffffffff;
    Ap6256FirmwareHalt(&c,0x40012,1);assert(memory_reads.size()==1 && c.FirmwareCrash.Valid==1 && indications==1);
    c=setup();install(&c);sh=(SDPCM_SHARED*)(ram.data()+0x2000);sh->Flags=4;
    Ap6256FirmwareHalt(&c,0x40012,1);assert(memory_reads.size()==1 && c.FirmwareCrash.SharedStatus==STATUS_REVISION_MISMATCH);
    c=setup();install(&c);UINT32 con[]={0xfffffff0,0xffffffff,0};memcpy(ram.data()+0x5008,con,sizeof(con));
    Ap6256FirmwareHalt(&c,0x40012,1);assert(c.FirmwareCrash.Valid==15 && c.FirmwareCrash.ConsoleStatus==STATUS_INVALID_ADDRESS);
    assert(!Ap6256CrashRamRange(&c,0xffffffff,80) && !Ap6256CrashRamRange(&c,0x198000,0xffffffff));
    puts("PASS: production mailbox detection, corrupt/wrapped/MMIO crash pointers, unsupported shared ABI and bus read failures");

    c=setup();install(&c);sh=(SDPCM_SHARED*)(ram.data()+0x2000);sh->TrapAddress=0x19b001;
    Ap6256FirmwareHalt(&c,0x40012,1);assert(c.FirmwareCrash.TrapStatus==STATUS_INVALID_ADDRESS && !(c.FirmwareCrash.Valid&2));
    c=setup();install(&c);failed_address=0x19b010;
    Ap6256FirmwareHalt(&c,0x40012,1);assert(c.FirmwareCrash.TrapStatus==STATUS_CRC_ERROR && !(c.FirmwareCrash.Valid&2));
    assert(c.FirmwareCrash.Valid&16);
    puts("PASS: word trap reads reject unaligned pointers and retain console evidence after a partial trap read failure");

    c=setup();install(&c);std::string chronological(3000,'x');chronological.replace(952,17,"TRAP PC 0022FFFF ");
    for(unsigned i=0;i<3000;++i) ram[0x6000+(i+177)%3000]=UCHAR(chronological[i]);
    UINT32 ring[]={0x19e000,3000,177};memcpy(ram.data()+0x5008,ring,sizeof(ring));
    Ap6256FirmwareHalt(&c,0x40012,1);
    assert(c.FirmwareCrash.ConsoleLength==319 && !memcmp(c.FirmwareCrash.Console,chronological.data()+2681,319));
    bool pc_logged=false;unsigned console_chunks=0;
    for(auto& s:logs) { if(s.find("TRAP PC 0022FFFF ")!=std::string::npos)pc_logged=true;if(s.find("firmware console [")!=std::string::npos)++console_chunks;assert(s.size()<511); }
    assert(pc_logged && console_chunks>=8);
    puts("PASS: wrapped 2 KiB console keeps the trap header in bounded log chunks and a 319-byte diagnosis tail");

    c=setup();install(&c);console_tail_stalls=true;
    std::string board_console(2048,'z');board_console.replace(768,14,"TRAP free NULL");
    for(unsigned i=0;i<2048;++i) ram[0x6000+(i+865)%2048]=UCHAR(board_console[i]);
    UINT32 board_ring[]={0x19e000,2048,865};memcpy(ram.data()+0x5008,board_ring,sizeof(board_ring));
    Ap6256FirmwareHalt(&c,0x40012,1);
    assert(c.FirmwareCrash.ConsoleStatus==STATUS_SUCCESS && (c.FirmwareCrash.Valid&16));
    assert(c.FirmwareCrash.ConsoleLength==319 && !memcmp(c.FirmwareCrash.Console,board_console.data()+1729,319));
    for(UINT32 address:memory_reads) if(address>=0x19e000 && address<0x19e800)assert(!(address&3));
    puts("PASS: historical unaligned console wrap and 97-byte tail complete through aligned words despite a variable-length CMD53 failure");
#ifdef HAS_CONSOLE_WORD_READ
    c=setup();install(&c);c.FirmwareHalted=1;
    Ap6256PrepareFirmwareCrash(&c,0x40012,1);Ap6256ModelRecordFirmwareCrash(&c);
    Ap6256NetFirmwareHalted(&c);Ap6256BcdcFirmwareHalted(&c);
    UCHAR small[9];memset(small,0xa5,sizeof(small));
    ram[ram.size()-1]=0x37;
    assert(Ap6256CrashReadConsole(&c,c.Chip.RamBase+ULONG(ram.size())-1,small,1)==STATUS_SUCCESS);
    assert(small[0]==0x37 && small[1]==0xa5 && memory_reads.size()==1);
    reads=memory_reads.size();
    assert(Ap6256CrashReadConsole(&c,0xffffffff,small,2)==STATUS_INVALID_ADDRESS);
    assert(Ap6256CrashReadConsole(&c,c.Chip.RamBase,small,0)==STATUS_INVALID_ADDRESS && memory_reads.size()==reads);
    puts("PASS: word console copying preserves byte limits and rejects zero/wrapped/outside ranges before bus access");
#endif

    c=setup();install(&c);waiting_device=&c;reply=false;wait_hook=halt_waiter;force_wait_timeout=true;
    assert(command(&c)==STATUS_DEVICE_HARDWARE_ERROR && waits==2 && indications==1);
    for(auto& s:logs)assert(s.find("response timed out")==std::string::npos);
    puts("PASS: a timeout racing the halt waits for the host indication/abort barrier instead of returning a firmware timeout");
#ifdef HAS_HOST_CRASH_PREPARE
    c=setup();waiting_device=&c;reply=false;wait_hook=boundary_waiter;
    assert(command(&c)==STATUS_DEVICE_HARDWARE_ERROR && waits==2 && order==std::vector<char>({'P','I','A'}));
    assert(memory_reads.empty() && c.FirmwareCrash.SharedStatus==STATUS_PENDING);
    Ap6256WdiHangDiagnose(&Ap6256HangDiagnosis,0,1024,blob,&count);
    assert(count==sizeof(crash) && ((AP6256_FW_CRASH*)blob)->SharedStatus==STATUS_PENDING);
    puts("PASS: detected-but-not-yet-indicated halt blocks completion until notification; diagnosis can use host metadata before SDIO");
#endif

    c=setup();install(&c);c.FirmwareState=1;c.FirmwareHalted=1;c.Go.NativeStateUncertain=TRUE;
    c.PowerSaveDx[0]={TRUE,TRUE,10,0,2};c.PowerSaveDx[1]={TRUE,TRUE,1,0,0};
    UINT32 ptr=c.Chip.SharedAddress;memcpy(ram.data()+ram.size()-4,&ptr,4);
    assert(Ap6256WaitForShared(&c)==STATUS_DEVICE_HARDWARE_ERROR && c.FirmwareHalted==1 && c.Go.NativeStateUncertain);
    assert(c.PowerSaveDx[0].Seen && c.PowerSaveDx[1].Seen);
    sh=(SDPCM_SHARED*)(ram.data()+0x2000);sh->Flags=4;
    assert(Ap6256WaitForShared(&c)==STATUS_REVISION_MISMATCH && c.FirmwareHalted==1 && c.Go.NativeStateUncertain);
    sh->Flags=3;failed_address=ptr;
    assert(Ap6256WaitForShared(&c)==STATUS_CRC_ERROR && c.FirmwareHalted==1 && c.Go.NativeStateUncertain);
    failed_address=0;assert(Ap6256WaitForShared(&c)==STATUS_SUCCESS && c.FirmwareHalted==0 && !c.Go.NativeStateUncertain);
    assert(!c.PowerSaveDx[0].Seen && !c.PowerSaveDx[1].Seen);
    assert(command(&c)==STATUS_SUCCESS);
    printf("PASS: fresh firmware instance accepts commands; crash record is %zu bytes\n",sizeof(crash));
    c=setup();c.FirmwareHalted=1;fixture_wifi.HardwareAvailable=0;
    assert(Ap6256NetHardwareStart(&c)==STATUS_DEVICE_HARDWARE_ERROR && fixture_wifi.HardwareAvailable==0);
    c=setup();install(&c);startup_device=&c;halt_on_mbo=true;
    assert(Ap6256NetHardwareStart(&c)==STATUS_DEVICE_HARDWARE_ERROR && fixture_wifi.HardwareAvailable==0 && indications==1);
    assert(!fixture_wifi.ConnectLock);
    puts("PASS: halt before or during adapter startup cannot republish hardware availability");
}
'''

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-dir', type=Path, default=output_dir('firmware-halt'))
    p.add_argument('--source-root', type=Path, default=AP)
    a = p.parse_args()
    out = a.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    root = a.source_root.resolve()
    pre = control.PRE.split('static BOOLEAN configured')[0]
    pre = pre.replace('static unsigned waits, delays, allocations;', 'static unsigned waits, delays, allocations;\nstatic void (*wait_hook)();')
    pre = pre.replace('assert(t->QuadPart == -50000000); ++waits;', 'assert(!t || t->QuadPart == -50000000); ++waits;if(wait_hook) wait_hook();\n if(force_wait_timeout && t)return STATUS_TIMEOUT;')
    pre = pre.replace('static void (*wait_hook)();', 'static void (*wait_hook)();\nstatic bool force_wait_timeout;')
    sd = (root / 'src/common/sdpcm.h').read_text(encoding='utf-8-sig')
    types = control.declaration(sd, 'SDPCM_SHARED') + (root / 'src/common/firmware_crash.h').read_text(encoding='utf-8-sig').replace('#pragma once', '').replace('C_ASSERT(', 'static_assert(')
    types += (AP / 'src/common/power_stats.h').read_text(encoding='utf-8-sig').replace('#pragma once', '')
    types += (AP / 'src/common/host_fips_wire.h').read_text(encoding='utf-8-sig').replace('#pragma once', '')
    pre = pre.replace('struct Device {', types + r'''
struct Device {
 int HostFipsLock=0;AP6256_FIPS_SESSION HostFipsSessions[16]={};UINT32 HostFipsBlockedMask=0,HostFipsRetiredMask=0;BOOLEAN HostFipsReady=FALSE;
 AP6256_POWER_SAVE_DX PowerSaveDx[2]={};
 struct { BOOLEAN NativeStateUncertain=FALSE; } Go;
 struct { UINT32 ChipId,ChipRev,RamBase,RamSize,SharedAddress; } Chip;
 UCHAR MacAddress[6];ULONG FirmwareState;AP6256_FW_CRASH FirmwareCrash;PVOID MiniportHandle;BOOLEAN RxSkip;''')
    pre = pre.replace('struct Device {', 'struct Device { ULONG HostCipherStore=0;LONG HostCipherFirmwareQualified=1;')
    text = pre
    text += '\nstatic void Ap6256HostCipherStoreInvalidateAll(ULONG* p) {++*p;}\n'
    text += r'''
static NTSTATUS Ap6256HostCipherFirmwareStarted(Device* p) {assert(p->FirmwareState==1&&!p->FirmwareHalted);p->HostCipherStore=0;p->HostCipherFirmwareQualified=0;return STATUS_SUCCESS;}
'''
    text += '\n'.join(re.findall('^#define (?:SDPCM_|BCDC_|BRCMF_C_(?:SET|GET)_VAR|HMB_|SMB_|I_HMB_|SD_REG_)[^\\n]+', sd, re.M)) + '\n'
    text += '\n'.join(re.findall('^#define AP6256_BCDC_[^\\n]+', (root / 'src/common/bcdc.h').read_text(encoding='utf-8-sig'), re.M)) + '\n'
    text += '\n'.join(re.findall('^#define BCDC_HDR_LEN[^\\n]+', (root / 'src/common/bcdc.c').read_text(encoding='utf-8-sig'), re.M)) + '\n'
    text += '\n'.join(re.findall('^#define (?:AP6256_CONTROL_TX_RETRIES|AP6256_FW_READY_RETRIES)[^\\n]+', (root / 'src/common/datapath.c').read_text(encoding='utf-8-sig') + '\n' + (root / 'src/common/firmware.c').read_text(encoding='utf-8-sig'), re.M)) + '\n'
    text += '#define AP6256_SDIO_FUNC_DATA 2\n#define Ap6256FwError 3\n'
    for name in ('SDPCM_HW_HEADER', 'SDPCM_SW_HEADER', 'SDPCM_HW_EXT', 'BCDC_DATA_HEADER', 'BCDC_DCMD_HEADER'):
        text += control.declaration(sd, name)
    text += control.declaration((AP / 'src/common/bcdc.h').read_text(encoding='utf-8-sig'), 'AP6256_BCDC_QUERY_RESULT')
    wdi = (control.INC / 'km/dot11wdi.h').read_text(encoding='utf-8-sig')
    text += re.search('^#define WDI_INDICATION_FIRMWARE_STALLED[^\\n]+', wdi, re.M)[0] + '\n'
    text += re.search('^#define WDI_INDICATION_PREFIX[^\\n]+', (control.INC / 'km/dot11wificxintf.h').read_text(encoding='utf-8-sig'), re.M)[0] + '\n'
    text += MOCK.split('struct AP6256_HANG_DIAGNOSIS')[0]
    text += control.declaration(wdi, 'WDI_MESSAGE_HEADER') + '\nstruct AP6256_HANG_DIAGNOSIS' + MOCK.split('struct AP6256_HANG_DIAGNOSIS', 1)[1]
    text += 'NDIS_STATUS Ap6256WdiHangDiagnose(NDIS_HANDLE,eDiagnoseLevel,UINT32,UINT8*,UINT32*);\n'
    text += 'VOID Ap6256NetFirmwareHalted(Device*);VOID Ap6256ModelRecordFirmwareCrash(Device*);\n'
    mock = control.MOCKS.replace('if(reply) {', 'if(halt_on_write) { Ap6256FirmwareHalt(c,0x40012,1);return STATUS_SUCCESS; }\n        if(reply) {')
    mock = mock.replace('++delays;', '++delays;\n if(delays==halt_at) Ap6256FirmwareHalt(waiting_device,0x40012,1);')
    text += mock
    text += (AP / 'src/common/host_fips_wire.c').read_text(encoding='utf-8-sig').replace('#include "host_fips_wire.h"', '')
    fips = _functions((AP / 'src/common/host_fips.c').read_text(encoding='utf-8-sig'))
    for name in ('Ap6256FipsSnapshot', 'Ap6256FipsActive', 'Ap6256FipsReset', 'Ap6256FipsTxCurrent', 'Ap6256FipsBcdcTxCurrent'):
        text += fips[name].replace('PAP6256_DEVICE_CONTEXT', 'Device*') + '\n'
    text += '#define Ap6256RawBcdcTxCurrent Ap6256FipsBcdcTxCurrent\n'
    functions = [('datapath.h', 'Ap6256TxHdrLen'), ('datapath.c', 'Ap6256Align4'), ('datapath.c', 'Ap6256AlignTransfer'), ('datapath.c', 'Ap6256DatapathSendSdpcm'), ('bcdc.c', 'Ap6256BcdcProcessControlFrame'), ('bcdc.c', 'Ap6256BcdcFirmwareHalted'), ('bcdc.c', 'Ap6256BcdcDcmdWithResult'), ('bcdc.c', 'Ap6256BcdcSetIovarResultIf'), ('bcdc.c', 'Ap6256BcdcSetIovarIf'), ('bcdc.c', 'Ap6256BcdcSetIovar'), ('firmware.c', 'Ap6256CrashRamRange'), ('firmware.c', 'Ap6256CrashString'), ('firmware.c', 'Ap6256PrepareFirmwareCrash'), ('firmware.c', 'Ap6256CrashReadTrap'), ('firmware.c', 'Ap6256CrashReadConsole'), ('firmware.c', 'Ap6256CaptureFirmwareCrash'), ('firmware.c', 'Ap6256FirmwareHalt'), ('datapath.c', 'Ap6256ProcessHostMailbox'), ('firmware.c', 'Ap6256IsNvramLengthToken'), ('firmware.c', 'Ap6256WaitForShared'), ('wdi/ndis_miniport.c', 'Ap6256ModelRecordFirmwareCrash'), ('wdi/ndis_miniport.c', 'Ap6256WdiHangDiagnose'), ('wdi/netadapter.c', 'Ap6256NetFirmwareHalted'), ('common/netadapter.c', 'Ap6256NetHardwareStart')]
    for (file, name) in functions:
        path = root / 'src' / file if file.startswith(('wdi/', 'common/')) else root / 'src/common' / file
        if name in ('Ap6256PrepareFirmwareCrash', 'Ap6256CrashReadTrap', 'Ap6256CrashReadConsole') and name not in _functions(path.read_text(encoding='utf-8-sig')):
            continue
        if name == 'Ap6256PrepareFirmwareCrash':
            text += '#define HAS_HOST_CRASH_PREPARE 1\n'
        if name == 'Ap6256CrashReadConsole':
            text += '#define HAS_CONSOLE_WORD_READ 1\n'
        f = _functions(path.read_text(encoding='utf-8-sig'))[name].replace('static ', '') if file.startswith(('wdi/', 'common/')) else control.function(root, 'common/' + file, name)
        if name == 'Ap6256ModelRecordFirmwareCrash':
            f = f.replace('KIRQL irql;', "order.push_back('P');++publishes;KIRQL irql;")
        if name == 'Ap6256BcdcFirmwareHalted':
            f = f.replace('KIRQL irql;', "order.push_back('A');KIRQL irql;")
        text += f
    text += TEST
    source = out / 'tests.cpp'
    write_text(source, text, encoding='utf-8')
    cmd = [str(control.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/wd4505', '/I' + str(control.VC / 'include')]
    cmd += ['/I' + str(control.INC / x) for x in ('ucrt', 'shared', 'um')]
    cmd += [str(source), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(control.VC / 'lib/x64'), '/LIBPATH:' + str(control.LIB / 'ucrt/x64'), '/LIBPATH:' + str(control.LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(cmd, indent=2), encoding='utf-8')
    subprocess.run(cmd, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
    write_text(out / 'receipt.json', json.dumps(dict(test_sha256=sha(Path(__file__)), functions=functions, compiled_sha256=sha(source), compiler_sha256=sha(Path(cmd[0])), exe_sha256=sha(out / 'tests.exe'), source_sha256={file: sha(root / ('src/' + file if file.startswith(('wdi/', 'common/')) else 'src/common/' + file)) for (file, name) in functions}, board_modified=False, pldr_tested=False), indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
