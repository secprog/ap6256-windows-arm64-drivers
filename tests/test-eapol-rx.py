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
AP = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, AP / 'tests' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
EXTRA = r'''
typedef int WDI_RX_INDICATION_LEVEL;
typedef NBL* PNET_BUFFER;
#define Ap6256TraceRxRefused 3
#define Ap6256TraceRxResumed 4
#define NDIS_STATUS_PAUSED ((LONG)0xc023002a)
#define WDI_EXT_TID_UNKNOWN 31
#define WDI_RX_INDICATION_FROM_RX_RESUME_FRAMES 2
#undef TraceVerbose
#define TraceVerbose(t,...) trace(__VA_ARGS__)
#define Ap6256TalDumpRxState(...) ((void)0)
#define NET_BUFFER_LIST_FIRST_NB(n) (n)
#define NET_BUFFER_DATA_LENGTH(n) ((ULONG)(n)->bytes.size())
static std::vector<std::string> eapol_logs;
static ULONGLONG KeQueryInterruptTime(){return 123456;}
static PCSTR Ap6256TalNdisStatusName(NDIS_STATUS){return "fixture";}
static unsigned diagnostic_mappings;
static void* NdisGetDataBuffer(NBL* n,ULONG length,void*,ULONG,ULONG){unlocked();diagnostic_mappings++;return length==n->bytes.size()?n->bytes.data():nullptr;}
static void metadata_trace(const char* format,...){unlocked();char buffer[512];va_list args;va_start(args,format);vsnprintf(buffer,sizeof(buffer),format,args);va_end(args);eapol_logs.emplace_back(buffer);}
#undef Ap6256TraceEapol
#undef Ap6256TalTraceEapolRxNbl
#undef TraceDiag
#define TraceDiag(...) metadata_trace(__VA_ARGS__)
#undef TraceFrameDiag
#define TraceFrameDiag(...) metadata_trace(__VA_ARGS__)
static BOOLEAN Ap6256RawGenerationCurrent(Device*,UINT32,ULONG generation,BOOLEAN hc){return !generation && !hc;}
static BOOLEAN Ap6256RawRxRead(Device*,UINT32,const UCHAR*,ULONG,AP6256_FIPS_FRAME_VIEW*,ULONG*,BOOLEAN*){return FALSE;}
static BOOLEAN Ap6256TalRxOwnerCurrent(Device*,UINT32,NBL*){return TRUE;}
static NDIS_STATUS indication_status;
static void notified(void*,int,UINT16,UINT32,void*,NDIS_STATUS* status){unlocked();notifications++;*status=indication_status;}
static void setup(Device& c){
    for(auto n:allocated){assert(n->freed);delete n;}allocated.clear();c={};current=&c;
    claims=upcalls=notifications=0;build_hook=queue_hook=claim_hook=delete_hook={};fail_build=false;
    c.TalStarted=c.TalApiOpen=c.TalPeerCreated=c.TalRxOpen=TRUE;c.RxBatching=TRUE;
    c.RxNblPool=&c;c.WdiDataPathHandle=&c;c.WdiDataApi.RxInorderDataIndication=notified;
    indication_status=NDIS_STATUS_SUCCESS;eapol_logs.clear();diagnostic_mappings=0;
}
static void packet(Device& c,bool eapol,UINT32 iface=0,UCHAR replay=14){
    UCHAR frame[113]={};memcpy(frame+6,a,6);frame[12]=eapol?0x88:8;frame[13]=eapol?0x8e:0;
    frame[14]=2;frame[15]=3;frame[17]=95;frame[18]=2;frame[19]=0x13;frame[20]=0xc8;frame[30]=replay;
    Ap6256WdiRxIndicate(&c,frame,sizeof(frame),0,iface);assert(!claims && !upcalls);
}
static unsigned pull(Device& c){
    NBL* chain=nullptr;Ap6256TalRxGetMpdus(&c,WDI_PEER_ANY,31,&chain);unsigned count=0;
    while(chain){auto next=chain->next;assert(chain==allocated[count]);Ap6256TalFreeRxNbl(&c,chain);chain=next;count++;}
    return count;
}
int main(int argc,char**){
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);Device c={};
    setup(c);packet(c,false);assert(!notifications && c.RxBatched==1);packet(c,true);
    if(notifications!=1 || c.RxBatched!=0){puts("EXPECTED-REGRESSION: EAPOL waits for the ordinary receive batch");return 17;}
    if(argc>1)return 0;
    assert(c.RxQueueCount==2 && c.RxQueueHead==allocated[0] && c.RxQueueTail==allocated[1]);
    Ap6256WdiRxFlush(&c);assert(notifications==1);assert(pull(c)==2);
    setup(c);indication_status=NDIS_STATUS_PAUSED;packet(c,true);assert(notifications==1 && c.RxPaused);
    packet(c,true);assert(notifications==1 && c.RxQueueCount==2);
    indication_status=NDIS_STATUS_SUCCESS;Ap6256TalRxResume(&c);assert(!c.RxPaused && notifications==2);assert(pull(c)==2);
    setup(c);c.RxStopped=TRUE;packet(c,true);assert(!notifications && c.RxQueueCount==1 && !pull(c));
    c.RxStopped=FALSE;Ap6256TalRxIndicateQueued(&c,0,"restart");assert(notifications==1 && pull(c)==1);
    setup(c);c.StationRxStopped=TRUE;packet(c,true);assert(!pull(c) && c.RxQueueCount==1);
    c.StationRxStopped=FALSE;assert(pull(c)==1);
    setup(c);c.TalRxOpen=FALSE;packet(c,true);assert(!notifications && !pull(c));
    c.TalRxOpen=TRUE;Ap6256TalRxIndicateQueued(&c,0,"open");assert(notifications==1 && pull(c)==1);
    setup(c);c.TalPeerCreated=FALSE;packet(c,true);assert(!notifications && !pull(c));
    c.TalPeerCreated=TRUE;Ap6256TalRxIndicateQueued(&c,0,"peer");assert(notifications==1 && pull(c)==1);
    setup(c);packet(c,true,99);assert(allocated.empty() && !notifications);
    setup(c);for(unsigned i=0;i<16;i++)packet(c,false);assert(notifications==1 && pull(c)==16);
    for(unsigned batch=0;batch<1000;batch++) {
        setup(c);for(unsigned i=0;i<16;i++)packet(c,false);
        assert(notifications==1 && pull(c)==16 && diagnostic_mappings==0 && eapol_logs.empty());
    }
    puts("PASS: 16000 ordinary receive packets without diagnostic buffer mapping");
    setup(c);puts("PASS: immediate EAPOL notification, FIFO, pause/resume, stop/readiness gates, ordinary batching");
}
'''

def fixture(previous=None):
    (rx, hot, tx) = (module('test-rx-lifetime'), module('test-hotspot'), module('test-wdi-transmit'))
    hot.read_source_text = lambda path, **kw: re.sub('(?m)^\\s*//[^\\n]*', '', rx.read_source_text(path, **kw))
    header = rx.read_source_text(AP / 'src/ap6256.h')
    tal = rx.read_source_text(AP / 'src/wdi_tal.c')
    pre = rx.PRE.replace('#include <functional>', '#include <functional>\n#include <string>\n#include <stdarg.h>')
    pre = pre.replace('bool freed=false;', 'bool freed=false;std::vector<UCHAR> bytes;')
    text = pre + rx.read_source_text(AP / 'src/common/host_fips_wire.h').replace('#pragma once', '')
    for (source, pattern) in ((header, '^#define AP6256_(?:STATION_PORT|GROUP_PORT|GO_PEERS|GO_CLIENTS)\\s+[^\\n]+'), (rx.read_source_text(AP / 'src/wifi_ops.h'), '^#define AP6256_WDI_OPMODE_P2P_(?:GO|CLIENT)\\s+[^\\n]+'), (tal, '^#define RX_(?:PORT|PEER|FIPS_GENERATION|HOST_CIPHER)\\([^\\n]+')):
        text += '\n'.join(re.findall(pattern, source, re.M)) + '\n'
    text += tx.declaration(header, 'AP6256_GO_PEER') + tx.declaration(header, 'AP6256_GO_DATA_STAGE') + tx.declaration(tal, 'AP6256_RX_ROUTE')
    mock = rx.MOCK.replace('BOOLEAN TalStarted,TalApiOpen,', 'BOOLEAN RxPaused,TalStarted,TalApiOpen,')
    mock = mock.replace('void* AllocateWiFiFrameMetaData;', 'void* AllocateWiFiFrameMetaData;\nvoid (*RxInorderDataIndication)(void*,int,UINT16,UINT32,void*,NDIS_STATUS*);')
    mock = re.sub('static void Ap6256TalNotifyRxWaiting[^\\n]+', '', mock)
    mock = re.sub('static void Ap6256TalRxIndicateQueued[^\\n]+', '', mock)
    mock = mock.replace('Device*,UCHAR* frame,ULONG,UCHAR,UINT32,UINT32)', 'Device*,UCHAR* frame,ULONG length,UCHAR,UINT32,UINT32)')
    mock = mock.replace('allocated.push_back(n);return n;', 'n->bytes.resize(32+length-14);n->bytes[0]=8;n->bytes[1]=2;const UCHAR snap[]={0xaa,0xaa,3,0,0,0,frame[12],frame[13]};memcpy(n->bytes.data()+24,snap,8);memcpy(n->bytes.data()+32,frame+14,length-14);allocated.push_back(n);return n;')
    text += mock + EXTRA.split('static NDIS_STATUS indication_status;')[0]
    signatures = ['VOID Ap6256TalNotifyRxWaiting(Device* Ctx,int Level,NDIS_STATUS* WifiStatus)', 'VOID Ap6256TalRxIndicateQueued(Device* Ctx,int Level,PCSTR Reason)', 'BOOLEAN Ap6256TalResolveRxPeer(Device* Ctx,UINT32 IfIndex,const UCHAR* Source,AP6256_RX_ROUTE* Route)', 'VOID Ap6256WdiRxIndicate(Device* Ctx,PUCHAR Frame,ULONG Length,UCHAR Priority,UINT32 IfIndex)', 'VOID Ap6256WdiRxFlush(Device* Ctx)', 'VOID Ap6256TalRxGetMpdus(TAL_TXRX_HANDLE MiniportTalTxRxContext,WDI_PEER_ID PeerId,WDI_EXTENDED_TID ExTid,PNET_BUFFER_LIST* ppNBL)', 'VOID Ap6256TalRxResume(TAL_TXRX_HANDLE MiniportTalTxRxContext)']
    for signature in signatures:
        name = re.search('(Ap6256\\w+)\\(', signature)[1]
        body = hot.body(str(previous.resolve()) if previous and name == 'Ap6256WdiRxIndicate' else 'wdi_tal.c', name)
        text += signature + '\n' + body + '\n'
    text += 'static NDIS_STATUS indication_status;' + EXTRA.split('static NDIS_STATUS indication_status;')[1]
    return (text, tx)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    previous = None
    records = []
    for (name, source) in [('current', None)]:
        (text, tx) = fixture(source)
        folder = out / name
        folder.mkdir(exist_ok=True)
        cpp = folder / 'test.cpp'
        write_bytes(cpp, text.encode())
        exe = folder / 'test.exe'
        command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4505', '/Od', '/MT', '/I' + str(tx.VC / 'include')]
        command += ['/I' + str(tx.INC / f) for f in ('ucrt', 'shared', 'um')]
        command += [str(cpp), '/Fe:' + str(exe), '/Fo:' + str(folder / 'test.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64')]
        result = subprocess.run(command, capture_output=True)
        write_bytes(folder / 'compile.log', result.stdout + result.stderr)
        if result.returncode:
            print((result.stdout + result.stderr).decode(errors='replace'))
            result.check_returncode()
        result = subprocess.run([str(exe)] + (['urgent'] if source else []), capture_output=True)
        output = result.stdout + result.stderr
        write_bytes(folder / 'run.log', output)
        print(output.decode(errors='replace'), end='')
        assert result.returncode == (17 if source else 0)
        if source:
            assert b'EXPECTED-REGRESSION:' in output
        sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        records.append(dict(name=name, exit_code=result.returncode, fixture_sha256=sha(cpp), executable_sha256=sha(exe), source_sha256=sha(source or AP / 'src/wdi/wdi_tal.c')))
    write_text(out / 'result.json', json.dumps(dict(passed=True, board_verified=False, records=records), indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
