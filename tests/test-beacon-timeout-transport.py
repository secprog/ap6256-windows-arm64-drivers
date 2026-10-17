# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import sys
ROOT = Path(__file__).resolve().parents[1]
CONTROL = runpy.run_path(str(ROOT / 'tests/test-control-retry.py'))
FRAME = r'''
static unsigned reply_payload_bytes=16, scalar_value=4, scalar_gets=0, scalar_sets=0;
static NTSTATUS Ap6256SdioFrameRW(Device* c, BOOLEAN write, PUCHAR p, ULONG n) {
    assert(write && c->Sdio.TxLock && !c->Sdio.TxStateLock && !c->Bcdc.ResponseLock);
    writes.emplace_back(p,p+n);
    const unsigned hdr=c->Sdio.TxGlom?20:12;
    const unsigned wire=c->Sdio.TxGlom?(rd32(p+4)&0xffffff)+4:rd16(p);
    assert(wire==hdr+16+16 && rd32(p+hdr+4)==16);
    const bool set=(rd32(p+hdr+8)&2)!=0;
    assert(rd32(p+hdr)==(set?263u:262u));
    assert(!memcmp(p+hdr+16,"bcn_timeout",12));
    if(set){++scalar_sets;scalar_value=rd32(p+hdr+28);}else ++scalar_gets;
    c->Sdio.MaxTxSeq=(UINT8)(c->Sdio.TxSeq+32);
    std::vector<UCHAR> bytes(16+reply_payload_bytes,0xa5);
    BCDC_DCMD_HEADER answer={set?263u:262u,0xffffffffu,rd32(p+hdr+8),0};
    memcpy(bytes.data(),&answer,16);
    if(reply_payload_bytes)memcpy(bytes.data()+16,&scalar_value,min(reply_payload_bytes,4u));
    Ap6256BcdcProcessControlFrame(c,bytes.data(),(ULONG)bytes.size());
    return 0;
}
'''
TEST = r'''
static Device setup() {
    static UCHAR tx[4096],rx[4096];
    assert(!allocations);memset(tx,0,sizeof(tx));memset(rx,0,sizeof(rx));
    logs.clear();writes.clear();write_results.clear();operations.clear();
    waits=delays=terminations=firmware_commands=grant_at=stop_at=0;
    configured=TRUE;reply=true;firmware_error=stop_on_failure=false;waiting_device=nullptr;
    scalar_value=4;scalar_gets=scalar_sets=0;
    Device c={};c.DatapathRunning=TRUE;c.TxScratchSize=40960;
    c.Sdio.Function2BlockSize=512;c.Sdio.TxSeq=255;c.Sdio.MaxTxSeq=0;c.Sdio.MaxTransferBytes[2]=32768;
    c.Bcdc.RequestId=40;c.Bcdc.IoctlBuffer=tx;c.Bcdc.IoctlBufferSize=sizeof(tx);
    c.Bcdc.ResponseBuffer=rx;c.Bcdc.ResponseBufferSize=sizeof(rx);
    return c;
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    volatile bool expected_rejection=EXPECT_EXACT_REJECTION;
    for(unsigned size:{4u,5u,8u,16u,32u,4080u}) {
        reply_payload_bytes=size;auto c=setup();
        struct {UINT32 before,value,after;} out={0x12345678,0,0x87654321};
        AP6256_BCDC_QUERY_RESULT result={};
        assert(Ap6256BcdcGetIovarResultIf(&c,0,"bcn_timeout",&out.value,4,&result)==0);
        assert(result.FirmwareReply && !result.FirmwareError && result.PayloadLength==size);
        assert(out.value==4 && out.before==0x12345678 && out.after==0x87654321 && !allocations);
        c=setup();NTSTATUS status=Ap6256WifiApplyUnreachableThreshold(&c,3000);
        if(expected_rejection && size!=4) {
            assert(status==STATUS_DEVICE_PROTOCOL_ERROR && scalar_gets==1 && !scalar_sets && scalar_value==4);
        }else {
            assert(status==0 && scalar_gets==2 && scalar_sets==1 && scalar_value==3);
        }
        assert(!allocations && !c.Bcdc.Pending && !c.Bcdc.Lock && !c.Bcdc.ResponseLock);
    }
    for(unsigned size:{0u,1u,2u,3u}) {
        reply_payload_bytes=size;auto c=setup();
        assert(Ap6256WifiApplyUnreachableThreshold(&c,3000)==STATUS_DEVICE_PROTOCOL_ERROR);
        assert(scalar_gets==1 && !scalar_sets && scalar_value==4 && !allocations);
    }
    puts(EXPECT_EXACT_REJECTION?"PASS: frozen historical rejects valid padded replies before any SET":"PASS: real SDPCM/BCDC preserves raw reply length, bounded scalar copy and verified three-second programming; short replies rejected");
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--helper-source', type=Path, default=ROOT / 'src/common/wifi_ops.c')
    args = parser.parse_args()
    out = args.output.resolve()
    env = CONTROL['main'].__globals__
    mocks = CONTROL['MOCKS']
    a = mocks.index('static NTSTATUS Ap6256SdioFrameRW(')
    b = mocks.index('static VOID Ap6256SdioTxFail', a)
    env['MOCKS'] = mocks[:a] + FRAME + mocks[b:]
    extra = CONTROL['function'](ROOT, 'common/bcdc.c', 'Ap6256BcdcGetIovarResultIf')
    for name in ('Ap6256WifiValidateUnreachableThreshold', 'Ap6256WifiReadBeaconTimeout', 'Ap6256WifiApplyUnreachableThreshold'):
        extra += CONTROL['function'](ROOT, str(args.helper_source.resolve()), name)
    env['TEST'] = '#define EXPECT_EXACT_REJECTION ' + str(int(False)) + '\n' + extra + TEST
    sys.argv = [str(Path(__file__)), '--output-dir', str(out)]
    CONTROL['main']()
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    write_text(out / 'receipt.json', json.dumps(dict(passed=True, board_verified=False, frozen_negative_control=False, helper_source_sha256=sha(args.helper_source), bcdc_source_sha256=sha(ROOT / 'src/common/bcdc.c'), datapath_source_sha256=sha(ROOT / 'src/common/datapath.c'), legal_reply_payload_lengths=[4, 5, 8, 16, 32, 4080], short_reply_payload_lengths=[0, 1, 2, 3], ignored_echoed_header_length='0xffffffff', requested_scalar_bytes=4, verified_seconds=3, test_sha256=sha(Path(__file__))), indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
