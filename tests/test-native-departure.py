# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import subprocess
from driver_sources import _functions
from wdi_test_support import contract_preamble
AP = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, AP / 'tests' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
EXTRA = r'''
#include "native_departure.h"
#ifndef PASSIVE_LEVEL
#define PASSIVE_LEVEL 0
#endif
#ifndef MAXULONG
#define MAXULONG 0xffffffffUL
#endif
#define Ap6256FwRunning 1
#define STATUS_DEVICE_PROTOCOL_ERROR ((NTSTATUS)0xc0000186)
#ifndef STATUS_INTEGER_OVERFLOW
#define STATUS_INTEGER_OVERFLOW ((NTSTATUS)0xc0000095)
#endif
static unsigned starts,commits,ndpolls,ndwaits,query_fault,nd_irql;
static bool never_ack,fail_all_ack,fail_first_ack,lose_start,lose_commit,lose_commit_read;
static UINT32 eligibility,ack_status,commit_delay,commit_drops;
static AP6256_NATIVE_DEPARTURE_CONTROL fw;
typedef struct {BOOLEAN FirmwareReply,FirmwareError;INT32 FirmwareStatus;ULONG PayloadLength;} AP6256_BCDC_QUERY_RESULT;
static unsigned KeGetCurrentIrql(){return nd_irql;}
'''
TRANSPORT = r'''
static NTSTATUS Ap6256BcdcSetIovarIf(Device* d,UINT32 iface,PCSTR name,const VOID* p,ULONG n){
    assert(!iface&&!strcmp(name,"wdi_native_departure")&&n==48&&d->NativeKeyLock>0);
    auto a=*(const AP6256_NATIVE_DEPARTURE_CONTROL*)p;
    assert(a.Abi==AP6256_ND_ABI&&a.Bytes==48&&a.Token&&a.Reason&&a.Reason<=65535);
    assert(!memcmp(a.Peer,peer,6)&&!a.State&&!a.NativeStatus&&!a.TxStatus&&!a.Attempts&&!a.Flags);
    assert(a.Token==fw.Token||((mock_wsec&0x600)==0x600&&installed.size()>=3));
    if(a.Operation==AP6256_ND_START){
        if(a.Token!=fw.Token){
            assert(fw.State!=AP6256_ND_PENDING&&fw.State!=AP6256_ND_ACKED);
            fw=a;fw.State=AP6256_ND_PENDING;fw.Attempts=1;fw.Flags=3;
            ++starts;ndpolls=0;pendingRadioFrame=true;
        }
        return lose_start?STATUS_IO_TIMEOUT:0;
    }
    assert(a.Operation==AP6256_ND_COMMIT&&a.Token==fw.Token&&fw.State==AP6256_ND_ACKED&&(fw.TxStatus&2));
    if(commit_drops){--commit_drops;return STATUS_IO_TIMEOUT;}
    if(commit_delay){fw.Operation=AP6256_ND_COMMIT;fw.State=AP6256_ND_COMMITTING;return 0;}
    ++commits;fw.Operation=AP6256_ND_COMMIT;fw.State=AP6256_ND_COMMITTED;fw.Flags=0;
    pendingRadioFrame=false;d->FirmwareLinkUp=false;
    return lose_commit?STATUS_IO_TIMEOUT:0;
}
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device* d,UINT32 iface,PCSTR name,VOID* p,ULONG n,AP6256_BCDC_QUERY_RESULT* result){
    assert(!iface&&!strcmp(name,"wdi_native_departure")&&n==48&&d->NativeKeyLock>0);
    auto request=*(AP6256_NATIVE_DEPARTURE_CONTROL*)p;
    assert(request.Abi==AP6256_ND_ABI&&request.Bytes==48&&!request.Operation&&!request.Reason&&!request.State);
    AP6256_NATIVE_DEPARTURE_CONTROL out={};out.Abi=AP6256_ND_ABI;out.Bytes=48;
    result->FirmwareReply=TRUE;result->PayloadLength=48;
    if(!request.Token){out.Flags=eligibility;memcpy(out.Peer,peer,6);}
    else {
        assert(request.Token==fw.Token);
        if(fw.State==AP6256_ND_PENDING&&!never_ack&&ndpolls>=2){
            bool rejected=fail_all_ack||(fail_first_ack&&starts==1);
            fw.State=rejected?AP6256_ND_FAILED:AP6256_ND_ACKED;
            fw.NativeStatus=rejected?-12:0;fw.TxStatus=rejected?0:ack_status;
        }
        if(fw.State==AP6256_ND_COMMITTING&&commit_delay&&!--commit_delay){fw.State=AP6256_ND_COMMITTED;fw.Flags=0;pendingRadioFrame=false;d->FirmwareLinkUp=false;++commits;}
        out=fw;
        if(out.State==AP6256_ND_COMMITTED&&lose_commit_read)return STATUS_IO_TIMEOUT;
        switch(query_fault){
        case 1:result->FirmwareReply=FALSE;break;
        case 2:result->PayloadLength=47;break;
        case 3:result->FirmwareError=TRUE;break;
        case 4:++out.Token;break;
        case 5:out.Peer[1]^=2;break;
        case 6:++out.Reason;break;
        case 7:out.Bytes=47;break;
        case 8:out.Reserved[0]=1;break;
        case 9:out.Flags=1;break;
        case 10:out.State=100;break;
        case 11:out.Attempts=2;break;
        case 12:out.Operation=AP6256_ND_COMMIT;break;
        default:break;
        }
    }
    memcpy(p,&out,48);return 0;
}
static NTSTATUS KeDelayExecutionThread(int mode,BOOLEAN alert,LARGE_INTEGER* delay){
    assert(!mode&&!alert&&installed.size()>=3&&(mock_wsec&0x600)==0x600);
    if(delay->QuadPart==-100000LL){++ndpolls;++ndwaits;return delay_status;}
    assert(delay->QuadPart==-5000000LL&&pendingRadioFrame);++grace;
    if(!delay_status)pendingRadioFrame=false;return delay_status;
}
'''
MAIN = r'''
static void fresh(Device& d){
    setup(d);keys(d);d.FirmwareHostCipherPatchVerified=TRUE;d.Chip.ChipId=0x4345;d.Chip.ChipRev=9;
    d.FirmwareState=Ap6256FwRunning;d.DatapathRunning=true;d.Sdio.BusInterface=&d;
    fw={};starts=commits=ndpolls=ndwaits=query_fault=nd_irql=0;eligibility=3;
    never_ack=fail_all_ack=fail_first_ack=lose_start=lose_commit=lose_commit_read=false;ack_status=2;commit_delay=commit_drops=0;
}
int main(){
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);Device d={};BOOLEAN handled=FALSE;
    fresh(d);departing=true;lose_start=lose_commit=true;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0);
    assert(starts==1&&commits==1&&fw.Reason==3&&ndwaits==2&&!grace&&!badOrder&&!legacy_requests);
    assert(!tracked(d)&&installed.size()==1&&mock_wsec==0x804&&!d.NativeDeparturePending&&!d.NativeDepartureToken&&!d.NativeKeyLock);
    puts("PASS: production disconnect uses reason-preserving native ACK/COMMIT before key/PMF cleanup");
    fresh(d);fail_first_ack=true;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0&&starts==2&&commits==1&&fw.Token==2&&!grace);
    fresh(d);fail_all_ack=true;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_DEVICE_PROTOCOL_ERROR&&starts==3&&!commits);
    assert(d.NativeDeparturePending&&d.NativeDepartureToken==3&&tracked(d)==3&&mock_wsec==0xe04&&!grace);
    puts("PASS: NOACK has bounded new-token retries; exhaustion preserves keys, PMF and pending ownership");
    fresh(d);never_ack=true;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_IO_TIMEOUT&&ndwaits==50&&starts==1&&!commits);
    auto token=d.NativeDepartureToken;auto count=calls.size();auto key=data_key(0,TRUE);
    assert(Ap6256WifiClearSecurityState(&d)==STATUS_DEVICE_BUSY&&calls.size()==count);
    assert(Ap6256WifiAddCcmpKey(&d,&key)==STATUS_DEVICE_BUSY&&calls.size()==count);
    assert(Ap6256WifiDeleteCcmpKeyIf(&d,0,0,TRUE,peer)==STATUS_DEVICE_BUSY&&calls.size()==count);
    assert(Ap6256NativeDeparture(&d,peer,4,&handled)==STATUS_DEVICE_BUSY&&starts==1);
    never_ack=false;assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0&&starts==1&&commits==1&&fw.Token==token);
    puts("PASS: missing callback retains the transaction and blocks cleanup/key mutation; resume uses the same token and frame");
    for(auto failure:{STATUS_IO_TIMEOUT,(NTSTATUS)0x101}){
        fresh(d);delay_status=failure;
        assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_IO_TIMEOUT&&starts==1&&!commits&&d.NativeDeparturePending&&tracked(d)==3&&mock_wsec==0xe04);
        delay_status=0;assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0&&starts==1&&commits==1);
    }
    fresh(d);lose_commit_read=true;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_IO_TIMEOUT&&starts==1&&commits==1&&d.NativeDeparturePending&&tracked(d)==3&&mock_wsec==0xe04);
    lose_commit_read=false;assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0&&starts==1&&commits==1&&!d.NativeDeparturePending);
    puts("PASS: interrupted polls and lost COMMIT receipt preserve ownership; receipt recovery completes without another departure");
    for(unsigned fault=1;fault<=12;++fault){
        fresh(d);query_fault=fault;
        assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_DEVICE_PROTOCOL_ERROR&&starts==1&&!commits);
        assert(d.NativeDeparturePending&&tracked(d)==3&&mock_wsec==0xe04&&!grace&&!d.NativeKeyLock);
        query_fault=0;assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0&&starts==1&&commits==1);
    }
    puts("PASS: absent/short/error replies, stale token/peer/reason, malformed ABI/results and inconsistent phase are rejected before cleanup");
    for(unsigned fault=0;fault<4;++fault){
        fresh(d);handled=TRUE;
        if(fault==0)eligibility=0;
        if(fault==1)d.Chip.ChipRev=6;
        if(fault==2)d.FirmwareHostCipherPatchVerified=FALSE;
        if(fault==3)for(auto& k:d.NativeKeys)k.Valid=FALSE;
        assert(Ap6256NativeDeparture(&d,peer,3,&handled)==0&&!handled&&!starts&&!commits&&!grace);
    }
    fresh(d);d.HostCipherStore.Configured=true;
    assert(Ap6256NativeDeparture(&d,peer,3,&handled)==0&&!handled&&!starts);
    fresh(d);d.HostFipsSessions[0].Generation=1;
    assert(Ap6256NativeDeparture(&d,peer,3,&handled)==0&&!handled&&!starts);
    fresh(d);eligibility=2;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_DEVICE_PROTOCOL_ERROR&&!starts&&!grace&&tracked(d)==3&&mock_wsec==0xe04);
    fresh(d);d.NativeDepartureNext=MAXULONG;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_INTEGER_OVERFLOW&&!starts&&!grace&&tracked(d)==3);
    fresh(d);nd_irql=2;
    assert(Ap6256NativeDeparture(&d,peer,3,&handled)==STATUS_INVALID_PARAMETER&&!starts&&!d.NativeKeyLock);
    puts("PASS: exact-image/native-key/PMF eligibility, raw-owner isolation, missing-key rejection, token overflow and IRQL gates");
    fresh(d);assert(Ap6256WifiLeaveForPowerDown(&d)==0&&starts==1&&commits==1&&fw.Reason==8&&!grace);
    assert(!tracked(d)&&mock_wsec==0x804&&!d.NativeDeparturePending&&!d.NativeDepartureToken);
    fresh(d);never_ack=true;
    assert(Ap6256WifiLeaveForPowerDown(&d)==STATUS_IO_TIMEOUT&&d.NativeDeparturePending&&starts==1&&!commits&&!grace&&tracked(d)==3);
    d.FirmwareLinkUp=false;never_ack=false;
    assert(Ap6256WifiLeaveForPowerDown(&d)==0&&starts==1&&commits==1&&!grace&&!d.NativeDeparturePending);
    puts("PASS: orderly power departure uses the same native ACK transaction and resumes after link-down without substituting the legacy fixed wait");
    fresh(d);ack_status=0x2002;commit_drops=1;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0&&starts==1&&commits==1&&!d.NativeDepartureToken);
    fresh(d);commit_delay=3;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0&&starts==1&&commits==1&&!d.NativeDeparturePending);
    fresh(d);fail_delete=true;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_IO_TIMEOUT&&starts==1&&commits==1&&d.NativeDeparturePending&&d.NativeDepartureCommitted&&d.NativeDepartureToken);
    assert(tracked(d)==3&&mock_wsec==0xe04&&!d.FirmwareLinkUp);
    auto before=calls.size();key=data_key(0,TRUE);
    assert(Ap6256WifiAddCcmpKey(&d,&key)==STATUS_DEVICE_BUSY&&calls.size()==before);
    fail_delete=false;
    assert(Ap6256WifiLeaveForPowerDown(&d)==0&&starts==1&&commits==1&&!tracked(d)&&mock_wsec==0x804&&!d.NativeDeparturePending&&!d.NativeDepartureCommitted&&!d.NativeDepartureToken);
    puts("PASS: high ACK status bits, lost COMMIT request, delayed COMMIT, failed tracked-key cleanup and power-down recovery without retransmission");

}
'''

def fixture():
    explicit = module('test-explicit-disconnect')
    source = explicit.fixture()
    assert source.endswith(explicit.MAIN)
    source = source[:-len(explicit.MAIN)]
    source = source.replace('Ap6256BcdcSetIovarIf', 'FixtureKeySetIovarIf')
    source = source.replace('struct Device {', 'struct Device {struct {UINT32 ChipId=0,ChipRev=0;} Chip;BOOLEAN FirmwareHostCipherPatchVerified=FALSE;int FirmwareState=0;bool DatapathRunning=false;LONG FirmwareHalted=0;struct {void* BusInterface=nullptr;bool Sleeping=false;} Sdio;')
    mocks = explicit.MOCKS
    stub = 'static NTSTATUS Ap6256NativeDeparture(Device*,const UCHAR*,UINT32,BOOLEAN* handled){*handled=FALSE;return 0;}\n'
    assert stub in mocks
    mocks = mocks.replace(stub, '')
    start = mocks.index('static NTSTATUS KeDelayExecutionThread(')
    end = mocks.index('static NTSTATUS Ap6256BcdcGetIovar(', start)
    mocks = mocks[:start] + mocks[end:]
    mocks = mocks.replace('if(departing&&(!grace||pendingRadioFrame))', 'if(departing&&(pendingRadioFrame||(!grace&&!commits)))')
    functions = _functions((AP / 'src/common/native_departure.c').read_text(encoding='utf-8-sig'))
    replacement = EXTRA + mocks + TRANSPORT
    replacement += '\n'.join((functions[n] for n in ('Ap6256NativeDepartureRead', 'Ap6256NativeDepartureLocked', 'Ap6256NativeDeparture'))) + '\n'
    assert explicit.MOCKS in source
    source = source.replace(explicit.MOCKS, replacement)
    source += _functions((AP / 'src/common/wifi_ops.c').read_text(encoding='utf-8-sig'))['Ap6256WifiLeaveForPowerDown'] + '\n'
    return source + MAIN

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    tx = module('test-wdi-transmit')
    cpp = args.output / 'test.cpp'
    exe = args.output / 'test.exe'
    write_text(cpp, contract_preamble() + fixture(), encoding='utf-8')
    cmd = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4505', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(tx.VC / 'include'), '/I' + str(AP / 'src/common')]
    cmd += ['/I' + str(tx.INC / s) for s in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    cmd += [str(cpp), '/Fe:' + str(exe), '/Fo:' + str(args.output / 'test.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64'), 'advapi32.lib', str(tx.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    build = subprocess.run(cmd, capture_output=True)
    write_bytes(args.output / 'compile.log', build.stdout + build.stderr)
    if build.returncode:
        print((build.stdout + build.stderr).decode(errors='replace'))
        build.check_returncode()
    run = subprocess.run([str(exe)], capture_output=True)
    write_bytes(args.output / 'run.log', run.stdout + run.stderr)
    print((run.stdout + run.stderr).decode(errors='replace'), end='')
    run.check_returncode()
    names = ['src/common/native_departure.c', 'src/common/native_departure.h', 'src/common/wifi_ops.c', 'src/common/ap6256.h', str(Path(__file__).relative_to(AP))]
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    result = dict(passed=True, board_verified=False, source_sha256={n: sha(AP / n) for n in names}, executable_sha256=sha(exe), boundary='Native departure receipts, pending recovery, commit confirmation, disconnect/power ordering and key cleanup.')
    write_text(args.output / 'result.json', json.dumps(result, indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
