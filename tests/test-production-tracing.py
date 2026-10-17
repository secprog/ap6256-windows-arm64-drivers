# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Compile trace.c with the actual Microsoft TraceLogging metadata writer.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, json, subprocess, importlib.util
import re
from driver_sources import _functions
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tx', ROOT / 'tests/test-wdi-transmit.py')
tx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tx)
SHIM = r'''
#pragma once
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#define NOMINMAX
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <evntprov.h>
#include <evntrace.h>
#include <vector>
#include <string>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#define _NTDEF_
#define NTSTRSAFE_NO_UNICODE_STRING_FUNCTIONS
#define DISPATCH_LEVEL 2
#define DPFLTR_IHVDRIVER_ID 77
#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_WARNING_LEVEL 1
#define DPFLTR_INFO_LEVEL 3
#define DPFLTR_MASK 0x80000000u
typedef struct _DEVICE_OBJECT* PDEVICE_OBJECT;
static UCHAR fixture_irql;
static unsigned debug_calls,unregister_calls;
static unsigned register_calls;
static unsigned debug_calls_at_register;
static std::vector<std::string> debug_messages;
static bool fail_register;
static PENABLECALLBACK enable_callback;
static PVOID enable_context;
struct Captured {
    EVENT_DESCRIPTOR Descriptor;
    std::vector<std::vector<UCHAR>> Data;
};
static std::vector<Captured> captured;
static UCHAR KeGetCurrentIrql() {return fixture_irql;}
static ULONG vDbgPrintExWithPrefix(PCSTR prefix,ULONG component,ULONG level,PCSTR format,va_list arguments) {
    assert(component==DPFLTR_IHVDRIVER_ID);
    ULONG importance=level<32 ? (1u<<level) : level;
    if(importance & 1u) {
        ++debug_calls;
        char message[512];vsnprintf(message,sizeof(message),format,arguments);
        debug_messages.emplace_back(std::string(prefix)+message);
    }
    return 0;
}
ULONG DbgPrintEx(ULONG,ULONG,PCSTR,...) {++debug_calls;return 0;}
static ULONG WINAPI FixtureRegister(LPCGUID,PENABLECALLBACK callback,PVOID context,REGHANDLE* handle) {
    debug_calls_at_register=debug_calls;++register_calls;
    if(fail_register) return ERROR_NOT_ENOUGH_MEMORY;
    enable_callback=callback;enable_context=context;*handle=1;return 0;
}
static ULONG WINAPI FixtureUnregister(REGHANDLE handle) {
    assert(handle==1);++unregister_calls;enable_callback=nullptr;enable_context=nullptr;return 0;
}
static ULONG WINAPI FixtureSetInformation(REGHANDLE,EVENT_INFO_CLASS,PVOID,ULONG) {return 0;}
static ULONG WINAPI FixtureWrite(REGHANDLE handle,const EVENT_DESCRIPTOR* descriptor,
    LPCGUID,LPCGUID,ULONG count,EVENT_DATA_DESCRIPTOR* fields) {
    assert(handle==1);Captured out;out.Descriptor=*descriptor;
    for(ULONG i=0;i<count;++i) {
        auto p=(const UCHAR*)(ULONG_PTR)fields[i].Ptr;
        out.Data.emplace_back(p,p+fields[i].Size);
    }
    captured.push_back(out);return 0;
}
#ifndef AP6256_TRACE_REAL_ETW
#define TLG_EVENT_REGISTER FixtureRegister
#define TLG_EVENT_UNREGISTER FixtureUnregister
#define TLG_EVENT_SET_INFORMATION FixtureSetInformation
#define TLG_EVENT_WRITE_TRANSFER FixtureWrite
#endif
'''
LIVE = r'''
#define AP6256_TRACE_REAL_ETW
#include "TRACE_SOURCE"
#include <evntcons.h>
#include <tdh.h>
#include <cstring>
static unsigned received_messages,received_recoveries;
static void WINAPI record(EVENT_RECORD* event) {
    ULONG size=0;
    if(TdhGetEventInformation(event,0,nullptr,nullptr,&size)!=ERROR_INSUFFICIENT_BUFFER)return;
    std::vector<UCHAR> buffer(size);auto info=(TRACE_EVENT_INFO*)buffer.data();
    assert(TdhGetEventInformation(event,0,nullptr,info,&size)==0);
    if(!info->EventNameOffset)return;
    auto name=(const WCHAR*)(buffer.data()+info->EventNameOffset);
    if(wcscmp(name,L"DriverMessage")==0) {
        PROPERTY_DATA_DESCRIPTOR prop={};prop.PropertyName=(ULONGLONG)(ULONG_PTR)L"Message";
        prop.ArrayIndex=ULONG_MAX;ULONG bytes=0;
        assert(TdhGetPropertySize(event,0,nullptr,1,&prop,&bytes)==0);
        std::vector<UCHAR> message(bytes);
        assert(TdhGetProperty(event,0,nullptr,1,&prop,bytes,message.data())==0);
        assert(strcmp((const char*)message.data(),"AP6256 native ETW roundtrip 271")==0);
        ++received_messages;
    } else if(wcscmp(name,L"WatchdogRecovery")==0) {
        assert(event->EventHeader.EventDescriptor.Keyword==TRACE_WATCHDOG);
        struct Expected {PCWSTR Name;ULONG Bytes;ULONGLONG Value;};
        const Expected expected[]={{L"DeviceId",4,7},{L"Reason",4,2},{L"Status",4,0},
            {L"Pending",4,4},{L"Interrupts",4,0},{L"Polls",8,1},
            {L"Recoveries",8,1},{L"ReadFailures",8,0}};
        for(const auto& field:expected) {
            PROPERTY_DATA_DESCRIPTOR prop={};prop.PropertyName=(ULONGLONG)(ULONG_PTR)field.Name;
            prop.ArrayIndex=ULONG_MAX;ULONG bytes=0;ULONGLONG value=0;
            assert(TdhGetPropertySize(event,0,nullptr,1,&prop,&bytes)==0 && bytes==field.Bytes);
            assert(TdhGetProperty(event,0,nullptr,1,&prop,bytes,(PBYTE)&value)==0);
            assert(value==field.Value);
        }
        ++received_recoveries;
    }
}
int wmain(int argc,WCHAR** argv) {
    assert(argc==2);
    const GUID provider={0x05c68da4,0x3816,0x40b7,{0x9d,0x55,0xaa,0xae,0x16,0x44,0xe8,0x41}};
    WCHAR name[96];swprintf_s(name,L"AP6256.HostTests.%lu",GetCurrentProcessId());
    std::vector<UCHAR> backing(sizeof(EVENT_TRACE_PROPERTIES)+2048);
    auto properties=(EVENT_TRACE_PROPERTIES*)backing.data();
    properties->Wnode.BufferSize=ULONG(backing.size());
    properties->Wnode.Flags=WNODE_FLAG_TRACED_GUID;properties->Wnode.ClientContext=1;
    properties->BufferSize=64;properties->MinimumBuffers=2;properties->MaximumBuffers=4;
    properties->Wnode.Guid=provider;


    properties->LogFileMode=EVENT_TRACE_FILE_MODE_SEQUENTIAL |
        EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC;
    properties->LoggerNameOffset=sizeof(EVENT_TRACE_PROPERTIES);
    properties->LogFileNameOffset=sizeof(EVENT_TRACE_PROPERTIES)+256;
    wcscpy_s((WCHAR*)(backing.data()+properties->LoggerNameOffset),128,name);
    wcscpy_s((WCHAR*)(backing.data()+properties->LogFileNameOffset),896,argv[1]);
    assert(NT_SUCCESS(Ap6256TraceInitialize()));
    TRACEHANDLE session=0;ULONG status=StartTraceW(&session,name,properties);
    if(status!=0){Ap6256TraceCleanup();printf("StartTrace returned %lu; no session created\n",status);return int(status);}
    status=EnableTraceEx2(session,&provider,EVENT_CONTROL_CODE_ENABLE_PROVIDER,4,0x1ff,0,0,nullptr);
    if(status==0) {
        TraceInfo(TRACE_DRIVER,"AP6256 native ETW roundtrip %u",271u);
        Ap6256TraceWatchdog(7,2,0,4,0,1,1,0);
    }
    Ap6256TraceCleanup();
    ULONG stop=ControlTraceW(session,name,properties,EVENT_TRACE_CONTROL_STOP);
    assert(stop==0);if(status!=0)return int(status);
    EVENT_TRACE_LOGFILEW file={};file.LogFileName=argv[1];
    file.ProcessTraceMode=PROCESS_TRACE_MODE_EVENT_RECORD;file.EventRecordCallback=record;
    TRACEHANDLE reader=OpenTraceW(&file);assert(reader!=INVALID_PROCESSTRACE_HANDLE);
    assert(ProcessTrace(&reader,1,nullptr,nullptr)==0);assert(CloseTrace(reader)==0);
    assert(received_messages==1 && received_recoveries==1);
    puts("Windows ETW/TDH roundtrip passed");
}
'''

def lifecycle_source():
    """Execute both actual DriverEntry bodies and their real cleanup hooks."""
    wdi = _functions((ROOT / 'src/wdi/ndis_miniport.c').read_text(encoding='utf-8-sig').replace('DriverEntry(', 'Ap6256TraceFixtureEntry('))
    kmdf = _functions((ROOT / 'src/common/kmdf_driver.c').read_text(encoding='utf-8-sig').replace('DriverEntry(', 'Ap6256TraceFixtureEntry('))
    wentry = wdi['Ap6256TraceFixtureEntry']
    kentry = kmdf['Ap6256TraceFixtureEntry']

    def fields(body, variable):
        names = sorted(set(re.findall('\\b' + variable + '\\.(\\w+)', body)) - {'Header'})
        return '\n'.join((('Slot ' if 'Handler' in n else 'ULONG ') + n + '{};' for n in names))
    callbacks = sorted(set(re.findall('=\\s*(Ap6256\\w+)\\s*;', wentry)) - {'Ap6256NdisUnload'})
    pre = r'''
typedef PVOID PDRIVER_OBJECT;typedef LONG NDIS_STATUS;typedef PVOID NDIS_HANDLE;
#define PAGED_CODE() ((void)0)
#define NDIS_STATUS_SUCCESS 0
#define NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS 1
#define NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2 2
#define NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2 sizeof(NDIS_MINIPORT_DRIVER_CHARACTERISTICS)
#define NDIS_OBJECT_TYPE_MINIPORT_WDI_CHARACTERISTICS 2
#define NDIS_MINIPORT_WDI_CHARACTERISTICS_REVISION_1 1
#define NDIS_MINIPORT_DRIVER_WDI_CHARACTERISTICS_REVISION_1 1
#define NDIS_SIZEOF_MINIPORT_WDI_CHARACTERISTICS_REVISION_1 sizeof(NDIS_MINIPORT_DRIVER_WDI_CHARACTERISTICS)
#define AP6256_WDI_VERSION 0x1010au
struct Slot { template<class T>Slot& operator=(T){return *this;} };
struct FakeHeader {UCHAR Type,Revision;USHORT Size;};
struct NDIS_MINIPORT_DRIVER_CHARACTERISTICS { FakeHeader Header;
FIELDS1
};
struct NDIS_MINIPORT_DRIVER_WDI_CHARACTERISTICS { FakeHeader Header;
FIELDS2
};
static NDIS_HANDLE Ap6256MiniportDriverHandle;
static struct { KSPIN_LOCK Lock; } Ap6256HangDiagnosis;
static LONG ndis_status,wdf_status;
static void KeInitializeSpinLock(KSPIN_LOCK* p) {*p=0;}
static NDIS_STATUS NdisMRegisterWdiMiniportDriver(PDRIVER_OBJECT,PUNICODE_STRING,PVOID,
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS*,NDIS_MINIPORT_DRIVER_WDI_CHARACTERISTICS*,NDIS_HANDLE* handle) {
    if(ndis_status==0)*handle=(PVOID)1;return ndis_status;
}
static void NdisMDeregisterWdiMiniportDriver(NDIS_HANDLE) {
    assert(Ap6256EtwRegistered || fail_register);
}
typedef PVOID WDFOBJECT;
struct WDF_DRIVER_CONFIG {PVOID Add;};
struct WDF_OBJECT_ATTRIBUTES {void(*EvtCleanupCallback)(WDFOBJECT);ULONG ExecutionLevel;};
#define WDF_DRIVER_CONFIG_INIT(c,f) ((c)->Add=(PVOID)(f))
#define WDF_OBJECT_ATTRIBUTES_INIT(a) memset(a,0,sizeof(*a))
#define WdfExecutionLevelPassive 2
#define WDF_NO_HANDLE nullptr
static void (*saved_cleanup)(WDFOBJECT);
static void Ap6256EvtDeviceAdd() {}
static NTSTATUS WdfDriverCreate(PDRIVER_OBJECT,PUNICODE_STRING,WDF_OBJECT_ATTRIBUTES* a,
    WDF_DRIVER_CONFIG*,PVOID) {
    assert(a->ExecutionLevel==WdfExecutionLevelPassive && a->EvtCleanupCallback);
    saved_cleanup=a->EvtCleanupCallback;return (NTSTATUS)wdf_status;
}
'''
    pre = pre.replace('FIELDS1', fields(wentry, 'chars')).replace('FIELDS2', fields(wentry, 'wdiChars'))
    pre += '\n'.join(('static void ' + n + '() {}' for n in callbacks))
    code = '#include "TRACE_SOURCE"\n#include "VERSION_SOURCE"\n#include "STAMP_SOURCE"\n' + pre
    code += wdi['Ap6256NdisUnload'] + '\n' + wentry.replace('Ap6256TraceFixtureEntry(', 'WdiEntry(') + '\n'
    code += kmdf['Ap6256EvtDriverTraceCleanup'] + '\n' + kentry.replace('Ap6256TraceFixtureEntry(', 'KmdfEntry(') + '\n'
    code += r'''
int main() {
    assert(WdiEntry(nullptr,nullptr)==0 && register_calls==1 && Ap6256EtwRegistered);
    assert(debug_calls_at_register==0);
    Ap6256NdisUnload(nullptr);assert(unregister_calls==1 && !Ap6256EtwRegistered);
    ndis_status=STATUS_NOT_SUPPORTED;
    assert(!NT_SUCCESS(WdiEntry(nullptr,nullptr)) && register_calls==2);
    assert(unregister_calls==2 && !Ap6256EtwRegistered);
    ndis_status=0;
    assert(KmdfEntry(nullptr,nullptr)==0 && register_calls==3 && Ap6256EtwRegistered);
    saved_cleanup(nullptr);assert(unregister_calls==3 && !Ap6256EtwRegistered);
    wdf_status=STATUS_INSUFFICIENT_RESOURCES;
    assert(!NT_SUCCESS(KmdfEntry(nullptr,nullptr)) && register_calls==4);
    assert(unregister_calls==4 && !Ap6256EtwRegistered);
    saved_cleanup(nullptr);assert(unregister_calls==4);
    fail_register=true;ndis_status=0;
    assert(WdiEntry(nullptr,nullptr)==0 && register_calls==5 && !Ap6256EtwRegistered);

    Ap6256NdisUnload(nullptr);
    assert(unregister_calls==4);
    assert(debug_messages.empty());
    puts("production WDI/KMDF registration-failure, create-failure and unload lifecycle passed");
}
'''
    return code.replace('VERSION_SOURCE', str(ROOT / 'src/common/version.h').replace('\\', '/')).replace('STAMP_SOURCE', str(ROOT / 'src/common/buildstamp.h').replace('\\', '/'))
TEST = r'''
#include "TRACE_SOURCE"
static bool has(const std::vector<UCHAR>& bytes,const char* text) {
    std::string value((const char*)bytes.data(),bytes.size());
    return value.find(text)!=std::string::npos;
}
static void enable(UCHAR level,ULONGLONG keywords) {
    assert(enable_callback);GUID source={};
    enable_callback(&source,EVENT_CONTROL_CODE_ENABLE_PROVIDER,level,keywords,0,nullptr,enable_context);
}
int main() {
    unsigned eval=0,debug_before=debug_calls;
    TraceData("packet opt-in %u",++eval);
#if AP6256_TRACE_DATAPATH
    assert(eval==1 && debug_calls==debug_before && captured.empty());eval=0;
#else
    assert(eval==0 && debug_calls==debug_before);
#endif
    TraceInfo(TRACE_DRIVER,"unregistered %u",++eval);
    TraceDiag("default startup");TraceError(TRACE_DRIVER,"default error");
    assert(eval==1 && captured.empty() && debug_calls==0);
    fail_register=true;assert(!NT_SUCCESS(Ap6256TraceInitialize()));
    TraceError(TRACE_DRIVER,"failure %u",++eval);Ap6256TraceCleanup();
    assert(eval==2 && captured.empty() && unregister_calls==0);
    fail_register=false;assert(NT_SUCCESS(Ap6256TraceInitialize()));


    enable(5,0x1ff);
    const unsigned counts[]={0,1,2,4,5};
    for(ULONG mode=0;mode<=4;++mode) {
        Ap6256TraceSetDebugLevel(mode);captured.clear();unsigned before=debug_calls;
        TraceError(TRACE_DRIVER,"error");TraceWarn(TRACE_DRIVER,"warning");
        TraceInfo(TRACE_DRIVER,"information");TraceVerbose(TRACE_DRIVER,"verbose");
        TraceDiag("diagnostic");TraceData("packet");
        assert(captured.size()==5);
        assert(debug_calls-before==counts[mode]+(AP6256_TRACE_DATAPATH && mode==4 ? 1u:0u));
    }
    Ap6256TraceSetDebugLevel(99);debug_before=debug_calls;
    TraceError(TRACE_DRIVER,"invalid policy");assert(debug_calls==debug_before);
    captured.clear();Ap6256TraceCleanup();
    assert(NT_SUCCESS(Ap6256TraceInitialize()));Ap6256TraceSetDebugLevel(4);
    TraceInfo(TRACE_DRIVER,"no consumer");assert(captured.empty());
    enable(4,TRACE_POWER);
    TraceInfo(TRACE_SDIO,"filtered category");assert(captured.empty());
    TraceVerbose(TRACE_POWER,"filtered level");assert(captured.empty());
    TraceInfo(TRACE_POWER,"power %u",++eval);
    assert(eval==3 && captured.size()==1 && captured.back().Descriptor.Level==4);
    assert(captured.back().Descriptor.Keyword==TRACE_POWER);
    assert(has(captured.back().Data[1],"DriverMessage"));
    bool message=false;for(auto& part:captured.back().Data) message |= has(part,"power 3");assert(message);
    captured.clear();enable(5,0x1ff);
    const ULONG categories[]={TRACE_DRIVER,TRACE_DEVICE,TRACE_SDIO,TRACE_CHIP,
        TRACE_FIRMWARE,TRACE_BCDC,TRACE_NETADAPTER,TRACE_POWER};
    for(ULONG category:categories) for(UCHAR level=2;level<=5;++level) {
        Ap6256TraceMessage(category,level,0,"","metadata %u %u",category,level);
        assert(captured.back().Descriptor.Level==level && captured.back().Descriptor.Keyword==category);
    }
    std::string big(2048,'x');TraceWarn(TRACE_DRIVER,"%s",big.c_str());
    auto& last=captured.back();bool bounded=false,overflow=false;
    for(auto& part:last.Data) {
        if(part.size()==512 && part.back()==0 && part.front()=='x')bounded=true;
        if(part.size()==1 && part[0]==1)overflow=true;
    }
    assert(bounded && overflow);
    captured.clear();fixture_irql=DISPATCH_LEVEL;
    TraceWarn(TRACE_SDIO,"dispatch");assert(captured.size()==1);
    fixture_irql=DISPATCH_LEVEL+1;TraceError(TRACE_SDIO,"high IRQL");assert(captured.size()==1);
    fixture_irql=0;
    captured.clear();enable(4,TRACE_WATCHDOG);
    Ap6256TraceWatchdog(7,0,0,0,0,0,0,0);
    Ap6256TraceWatchdog(7,2,0,4,0,1,1,0);
    Ap6256TraceWatchdog(7,4,STATUS_CRC_ERROR,0,0,2,1,1);
    assert(captured.size()==3);
    assert(has(captured[0].Data[1],"WatchdogState"));
    assert(has(captured[1].Data[1],"WatchdogRecovery"));
    assert(has(captured[2].Data[1],"WatchdogReadFailure"));
    assert(captured[0].Descriptor.Keyword==TRACE_WATCHDOG);
    assert(captured[0].Descriptor.Level==4 && captured[1].Descriptor.Level==3);
    assert(captured[1].Data.size()==10);
    const ULONGLONG values[]={7,2,0,4,0,1,1,0};
    const char* fields[]={"DeviceId","Reason","Status","Pending","Interrupts","Polls","Recoveries","ReadFailures"};
    for(unsigned i=0;i<8;++i) {
        assert(has(captured[1].Data[1],fields[i]));
        assert(captured[1].Data[i+2].size()==(i<5?4u:8u));
        ULONGLONG value=0;memcpy(&value,captured[1].Data[i+2].data(),captured[1].Data[i+2].size());
        assert(value==values[i]);
    }
    captured.clear();Ap6256TraceCleanup();Ap6256TraceCleanup();
    assert(unregister_calls==2);
    TraceError(TRACE_DRIVER,"after cleanup");Ap6256TraceWatchdog(7,1,0,0,0,0,0,0);
    assert(captured.empty());
    assert(debug_calls>30);
    assert(!Ap6256TraceInformationEnabled(TRACE_SDIO));
    for(ULONG mode=0;mode<=4;mode++) {
        Ap6256TraceSetDebugLevel(mode);
        assert(Ap6256TraceInformationEnabled(TRACE_SDIO)==(mode>=3));
    }
    Ap6256TraceSetDebugLevel(0);
    assert(NT_SUCCESS(Ap6256TraceInitialize()));
    assert(!Ap6256TraceInformationEnabled(TRACE_SDIO));
    enable(3,TRACE_SDIO);assert(!Ap6256TraceInformationEnabled(TRACE_SDIO));
    enable(4,TRACE_POWER);assert(!Ap6256TraceInformationEnabled(TRACE_SDIO));
    enable(4,TRACE_DRIVER);assert(!Ap6256TraceInformationEnabled(TRACE_SDIO));
    assert(Ap6256TraceInformationEnabled(TRACE_SDIO|TRACE_DRIVER));
    enable(4,TRACE_SDIO);assert(Ap6256TraceInformationEnabled(TRACE_SDIO));
    fixture_irql=DISPATCH_LEVEL;assert(Ap6256TraceInformationEnabled(TRACE_SDIO));
    fixture_irql=DISPATCH_LEVEL+1;assert(!Ap6256TraceInformationEnabled(TRACE_SDIO));
    fixture_irql=0;Ap6256TraceCleanup();
    assert(!Ap6256TraceInformationEnabled(TRACE_SDIO));
    puts("production TraceLogging metadata/filter/payload/lifetime cases passed");
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=output_dir('production-tracing'))
    parser.add_argument('--lifecycle', action='store_true')
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--packet', action='store_true')
    parser.add_argument('--force-windbg', action='store_true')
    args = parser.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    if args.force_windbg and (not args.lifecycle):
        parser.error('--force-windbg requires --lifecycle')
    write_text(out / 'ntddk.h', SHIM, encoding='utf-8')
    generated = out / 'tests.cpp'
    write_text(generated, (LIVE if args.live else lifecycle_source() if args.lifecycle else TEST).replace('TRACE_SOURCE', str(ROOT / 'src/common/trace.c').replace('\\', '/')), encoding='utf-8')
    command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(out), '/I' + str(tx.VC / 'include')] + ['/I' + str(tx.INC / f) for f in ('ucrt', 'shared', 'um', 'km')] + [str(generated), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64'), 'advapi32.lib']
    if args.live:
        command.insert(1, '/wd4505')
        command.append('tdh.lib')
    if args.packet:
        command.insert(1, '/DAP6256_TRACE_DATAPATH=1')
    if args.force_windbg:
        command.insert(1, '/DAP6256_FORCE_WINDBG=1')
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    compiled = subprocess.run(command, capture_output=True, text=True)
    write_text(out / 'compile.log', compiled.stdout + compiled.stderr, encoding='utf-8')
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    run = subprocess.run([str(out / 'tests.exe')] + ([str((out / 'roundtrip.etl').resolve())] if args.live else []), capture_output=True, text=True)
    write_text(out / 'run.log', run.stdout + run.stderr, encoding='utf-8')
    write_text(out / 'receipt.json', json.dumps({'passed': run.returncode == 0, 'exit_code': run.returncode, 'production_source_sha256': hashlib.sha256((ROOT / 'src/common/trace.c').read_bytes()).hexdigest(), 'trace_header_sha256': hashlib.sha256((ROOT / 'src/common/trace.h').read_bytes()).hexdigest(), 'packet_trace_enabled': args.packet, 'forced_windbg': False, 'retired_force_macro_attempted': args.force_windbg, 'microsoft_tracelogging_header_sha256': hashlib.sha256((tx.INC / 'shared/TraceLoggingProvider.h').read_bytes()).hexdigest(), 'real_microsoft_metadata': True, 'etw_syscalls_fixture': not args.live, 'user_mode_producer': args.live, 'kernel_irql_fixture': True, 'board_tested': False}, indent=2), encoding='utf-8')
    print(run.stdout + run.stderr)
    raise SystemExit(run.returncode)
if __name__ == '__main__':
    main()
