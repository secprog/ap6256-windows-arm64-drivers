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
import re
import subprocess
from driver_sources import read_source_text
from wdi_test_support import contract_preamble
AP = Path(__file__).resolve().parents[1]
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define NDIS_SUPPORT_NDIS620 1
#define NDIS_SUPPORT_NDIS630 1
#include <ntddndis.h>
#define WIFICX_TEMPORARY_REMOVED_FOR_USERMODE
#include <dot11wificxintf.h>
#include <dot11wificxtypes.hpp>
#include <TlvGeneratorParser.hpp>
#include <cassert>
#include <cstdio>
#include <functional>
#include <vector>
typedef LONG NTSTATUS;
typedef UCHAR KIRQL;
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0xc000009e)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define TraceInfo(flag,...) ((void)printf(__VA_ARGS__))
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define AP6256_STATION_PORT 0
#define AP6256_SCAN_TIMEOUT_MS 4000
#define Ap6256FwRunning 1
struct Task {BOOLEAN Active;WDI_MESSAGE_HEADER Header;PVOID RequestId;LONGLONG DeadlineMs;};
struct Device {LONG ScanSyncId;BOOLEAN DatapathRunning;int FirmwareState;
    struct {LONG DiscoverScanPending;NTSTATUS DiscoverStatus;} P2p;};
struct Wifi {Device* Ctx;KIRQL CommandLock;Task ScanTask,P2pDiscoverTask;UINT16 ScanTaskSyncId;
    WDI_MESSAGE_HEADER IndicationHeader;LONG ScanIndicated,ScanDropped;TLV_CONTEXT TlvContext;int ScanTimer;};
struct AP6256_SCAN_PARAMS {ULONG MaximumScanTime;};
struct BRCMF_ESCAN_RESULT {UINT32 BufLen,Version;UINT16 SyncId,BssCount;UCHAR BssInfo;};
typedef Device* PAP6256_DEVICE_CONTEXT;
typedef Wifi* PAP6256_WIFI;
typedef Task* PAP6256_WDI_TASK;
typedef void* AP6256_REQUEST;
static Wifi* current;
static std::function<void()> lockHook,m3Hook,quiesceHook;
static std::vector<UINT32> completions;
static std::vector<PVOID> requests;
static unsigned m3s,submits,timerStops;
static NTSTATUS submitStatus,quiesceStatus;
static UINT16 submittedSync;
static BOOLEAN m3Done;
static void KeAcquireSpinLock(KIRQL* lock,KIRQL* old) {
    if(lockHook){auto callback=lockHook;lockHook=nullptr;callback();}
    assert(!*lock);*old=0;*lock=1;
}
static void KeReleaseSpinLock(KIRQL* lock,KIRQL) {assert(*lock);*lock=0;}
static Wifi* Ap6256WifiFromDevice(Device*) {return current;}
static NTSTATUS Ap6256SendIndicationRq(Wifi* w,UINT16 id,WDI_MESSAGE_HEADER* h,
    UINT32 txn,PVOID request,NTSTATUS,const void*,ULONG) {
    assert(!w->CommandLock && id==WDI_INDICATION_SCAN_COMPLETE && txn==h->TransactionId);
    completions.push_back(txn);requests.push_back(request);return 0;
}
static BOOLEAN Ap6256ClaimTask(Wifi* w,Task* task,WDI_MESSAGE_HEADER* header,PVOID* request) {
    KIRQL old;KeAcquireSpinLock(&w->CommandLock,&old);BOOLEAN active=task->Active;
    if(active){*header=task->Header;*request=task->RequestId;task->Active=FALSE;}
    KeReleaseSpinLock(&w->CommandLock,old);return active;
}
#define AP6256_TIMER_STOP(t,w) ((void)(t),(void)(w),++timerStops)
#define AP6256_TIMER_START(t,ms) ((void)(t),(void)(ms))
static NDIS_STATUS TestParseScan(ULONG,const UCHAR*,TLV_CONTEXT*,WDI_SCAN_PARAMETERS*) {return 0;}
static void TestCleanupScan(WDI_SCAN_PARAMETERS*) {}
static NTSTATUS Ap6256NdisToNtStatus(NDIS_STATUS s) {return (NTSTATUS)s;}
static NTSTATUS Ap6256CaptureScanParameters(Wifi*,WDI_SCAN_PARAMETERS*,AP6256_SCAN_PARAMS* p) {p->MaximumScanTime=4000;return 0;}
static PVOID Ap6256RequestGetId(AP6256_REQUEST r) {return r;}
static void Ap6256SetTaskDeadline(Wifi*,Task* t,ULONG ms) {t->DeadlineMs=ms;}
static void Ap6256CompleteRequest(Wifi*,AP6256_REQUEST,NTSTATUS status) {
    assert(status==0);m3Done=TRUE;++m3s;if(m3Hook)m3Hook();
}
static NTSTATUS Ap6256QuiesceP2pListen(Wifi*) {if(quiesceHook)quiesceHook();return quiesceStatus;}
static NTSTATUS Ap6256WifiScanStart(Device* d,const AP6256_SCAN_PARAMS*,UINT16 sync) {
    assert(m3Done && sync && sync==(UINT16)d->ScanSyncId);++submits;submittedSync=sync;return submitStatus;
}
'''
TEST = r'''
static void reset(Device& d,Wifi& w) {
    d={};w={};w.Ctx=&d;current=&w;d.ScanSyncId=41;d.DatapathRunning=TRUE;d.FirmwareState=Ap6256FwRunning;
    m3s=submits=timerStops=0;submitStatus=quiesceStatus=0;submittedSync=0;m3Done=FALSE;
    completions.clear();requests.clear();lockHook=m3Hook=quiesceHook=nullptr;
}
static UINT16 begin(Wifi& w,UINT32 txn) {
    WDI_MESSAGE_HEADER h={};h.TransactionId=txn;UINT16 sync=0;
    assert(Ap6256BeginScanTask(&w,&h,(PVOID)(ULONG_PTR)(txn+100),&sync)==0);return sync;
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    Device d;Wifi w;unsigned cases=0;
    reset(d,w);auto sync=begin(w,13);
    Ap6256NetScanComplete(&d,0,41);
    assert(w.ScanTask.Active && completions.empty());++cases;
    assert(sync==42 && w.ScanTaskSyncId==42 && d.ScanSyncId==42);
    for(unsigned stage=0;stage<2;++stage) {
        reset(d,w);WDI_MESSAGE_HEADER h={};h.TransactionId=13;
        auto stale=[&](){Ap6256NetScanComplete(&d,0,41);assert(w.ScanTask.Active);};
        if(stage)m3Hook=stale;else quiesceHook=stale;
        Ap6256HandleScanRequest(&w,(PVOID)113,&h,nullptr,0);
        assert(submits==1 && submittedSync==42 && m3s==1 && completions.empty());
        Ap6256NetScanComplete(&d,0,42);
        assert(!w.ScanTask.Active && completions==std::vector<UINT32>{13} && requests[0]==(PVOID)113);
        Ap6256NetScanComplete(&d,0,42);assert(completions.size()==1 && !timerStops);++cases;
    }
    for(unsigned stage=0;stage<3;++stage) {
        reset(d,w);sync=begin(w,11);
        auto replace=[&](){w.ScanTask.Active=FALSE;begin(w,13);};
        if(stage==0)replace();else if(stage==1)lockHook=replace;
        else {++d.ScanSyncId;w.ScanTaskSyncId=(UINT16)d.ScanSyncId;}
        Ap6256NetScanComplete(&d,0,sync);
        assert(w.ScanTask.Active && completions.empty() && !timerStops);++cases;
    }
    for(NTSTATUS status:{(NTSTATUS)0,(NTSTATUS)0xc0000001}) {
        reset(d,w);sync=begin(w,73);Ap6256NetScanComplete(&d,status,0);
        assert(w.ScanTask.Active);Ap6256NetScanComplete(&d,status,sync);
        assert(completions==std::vector<UINT32>{73} && !w.ScanTask.Active && !timerStops);++cases;
    }
    for(UINT16 event:{(UINT16)0,(UINT16)41,(UINT16)42}) for(ULONG size=0;size<=12;++size) {
        reset(d,w);begin(w,13);BRCMF_ESCAN_RESULT e={};e.SyncId=event;UINT16 parsed=0xffff;
        bool valid=Ap6256WifiEscanEventIsCurrent(&d,(UCHAR*)&e,size,&parsed)!=0;
        assert(valid==(size==12 && event==42));
        if(valid)Ap6256NetScanComplete(&d,0,parsed);
        assert(completions.size()==(valid?1u:0u));++cases;
    }
    reset(d,w);sync=7;assert(!Ap6256WifiEscanEventIsCurrent(&d,nullptr,12,&sync) && !sync);++cases;
    for(bool p2p:{false,true}) {
        reset(d,w);if(p2p)w.P2pDiscoverTask.Active=TRUE;else begin(w,13);
        LONG previous=d.ScanSyncId;UINT16 ignored=1;WDI_MESSAGE_HEADER h={};
        assert(Ap6256BeginScanTask(&w,&h,nullptr,&ignored)==STATUS_DEVICE_BUSY && !ignored && d.ScanSyncId==previous);++cases;
    }
    for(LONG before:{65534L,65535L,131071L,2147483647L}) {
        reset(d,w);d.ScanSyncId=before;sync=begin(w,13);assert(sync && sync==(UINT16)d.ScanSyncId);
        Ap6256NetScanComplete(&d,0,sync);assert(completions.size()==1);++cases;
    }
    reset(d,w);w.P2pDiscoverTask.Active=TRUE;d.P2p.DiscoverScanPending=1;
    Ap6256NetScanComplete(&d,7,40);assert(d.P2p.DiscoverScanPending && completions.empty());
    Ap6256NetScanComplete(&d,7,41);assert(!d.P2p.DiscoverScanPending && d.P2p.DiscoverStatus==7 && completions.empty());++cases;
    for(bool quiesceFail:{false,true}) {
        reset(d,w);WDI_MESSAGE_HEADER h={};h.TransactionId=73;
        if(quiesceFail)quiesceStatus=(NTSTATUS)0xc0000001;else submitStatus=(NTSTATUS)0xc0000001;
        Ap6256HandleScanRequest(&w,(PVOID)173,&h,nullptr,0);
        assert(m3s==1 && completions==std::vector<UINT32>{73} && !w.ScanTask.Active);++cases;
    }
    printf("PASS: %u scan ownership cases; production publication/claim/handler, deterministic stale and replacement interleavings, M3 order, malformed/duplicate events, wrap and failure cleanup\n",cases);
}
'''

def definition(source, name):
    spec = importlib.util.spec_from_file_location('scan_result_definition', AP / 'tests/test-scan-results.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result.definition(source, name)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, default=output_dir('scan-ownership'))
    args = parser.parse_args()
    net = read_source_text(AP / 'src/common/netadapter.c', encoding='utf-8-sig')
    ops = read_source_text(AP / 'src/common/wifi_ops.c', encoding='utf-8-sig')
    text = contract_preamble() + PRE
    text += 'NTSTATUS Ap6256BeginScanTask(Wifi* Wifi,const WDI_MESSAGE_HEADER* Header,PVOID RequestId,UINT16* SyncId)' + definition(net, 'Ap6256BeginScanTask')
    text += 'VOID Ap6256NetScanComplete(Device* Ctx,NTSTATUS CompletionStatus,UINT16 SyncId)' + definition(net, 'Ap6256NetScanComplete')
    text += 'BOOLEAN Ap6256WifiEscanEventIsCurrent(Device* Ctx,const UCHAR* EventData,ULONG Length,PUINT16 SyncId)' + definition(ops, 'Ap6256WifiEscanEventIsCurrent')
    handler = definition(net, 'Ap6256HandleScanRequest').replace('ParseWdiTaskScan(', 'TestParseScan(').replace('CleanupParsedWdiTaskScan(', 'TestCleanupScan(')
    text += 'VOID Ap6256HandleScanRequest(Wifi* Wifi,AP6256_REQUEST Request,PWDI_MESSAGE_HEADER Header,const UCHAR* Tlv,ULONG TlvLength)' + handler + TEST
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_bytes(cpp, text.encode())
    vc = VC
    sdk = SDK
    inc = INC
    lib = LIB
    command = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4505', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(vc / 'include')]
    command += ['/I' + str(inc / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64'), 'advapi32.lib']
    compiled = subprocess.run(command, capture_output=True)
    write_bytes(out / 'compile.log', compiled.stdout + compiled.stderr)
    assert compiled.returncode == 0, (compiled.stdout + compiled.stderr).decode(errors='replace')
    run = subprocess.run([str(out / 'tests.exe')], capture_output=True)
    write_bytes(out / 'run.log', run.stdout + run.stderr)
    expected = None and run.returncode != 0 and (b'Assertion failed: w.ScanTask.Active && completions.empty()' in run.stdout + run.stderr)
    assert expected or run.returncode == 0, (run.stdout + run.stderr).decode(errors='replace')
    print('PASS: frozen historical completes the replacement scan; expected assertion failure' if expected else run.stdout.decode(), end='\n' if expected else '')
    report = dict(passed=True, negative_control=bool(expected), board_verified=False, source_sha256={p: hashlib.sha256((AP / p).read_bytes()).hexdigest() for p in ('src/common/netadapter.c', 'src/common/wifi_ops.c')}, generated_cpp_sha256=hashlib.sha256(cpp.read_bytes()).hexdigest(), command=command)
    write_text(out / 'result.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
