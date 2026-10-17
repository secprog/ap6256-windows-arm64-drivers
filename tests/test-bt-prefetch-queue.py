# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.
# Additional permission: BLUETOOTH-LINKING-EXCEPTION.txt.

"""Exercise production Bluetooth prefetch ownership and admission."""

from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess

from test_support import output_dir, write_bluetooth_text, write_text
from toolchain import VC, INC, LIB

ROOT = Path(__file__).resolve().parents[1]


def function(text, name):
    mask = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: " " * len(m[0]), text, flags=re.S)
    match = re.search(r"(?m)^" + re.escape(name) + r"\(", mask)
    if not match:
        raise ValueError("Missing production function: " + name)
    start = text.rfind("\n\n", 0, match.start()) + 2
    brace = mask.index("{", match.end())
    depth = 1
    end = brace + 1
    while depth:
        depth += (mask[end] == "{") - (mask[end] == "}")
        end += 1
    return text[start:end]

PRE = r"""
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <deque>
#include <map>
#include <vector>
#include <mutex>
#include <thread>
#include <condition_variable>
typedef uint8_t UCHAR, *PUCHAR;
typedef uint32_t ULONG;
typedef int32_t LONG, NTSTATUS;
typedef LONG *PLONG;
typedef void VOID;
typedef uintptr_t ULONG_PTR;
typedef bool BOOLEAN;
#define TRUE true
#define FALSE false
#define DBG 0
#undef _In_
#undef _Inout_
#undef _In_reads_bytes_
#undef _In_reads_bytes_opt_
#undef _Field_size_bytes_
#define _In_
#define _Inout_
#define _In_reads_bytes_(x)
#define _In_reads_bytes_opt_(x)
#define _Field_size_bytes_(x)
#define NT_ASSERT(x) assert(x)
#define NT_SUCCESS(x) ((NTSTATUS)(x) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_PENDING ((NTSTATUS)0x103)
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001a)
#define STATUS_WDF_PAUSED ((NTSTATUS)0x80390002)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_INVALID_BUFFER_SIZE ((NTSTATUS)0xc0000206)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_QUOTA_EXCEEDED ((NTSTATUS)0xc0000044)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define HciPacketEvent 4
#define HciPacketAclData 2
#define POOL_FLAG_NON_PAGED 1
#define POOLTAG_BTHSERIALHCIBUSSAMPLE 1
#define FIELD_OFFSET(t, f) offsetof(t, f)
#define RtlCopyMemory(d, s, n) memcpy(d, s, n)
static void fixture_trace(const char*, ...) {}
#define DoTrace(l, t, args) fixture_trace args
struct LIST_ENTRY { LIST_ENTRY *Flink, *Blink; };
typedef LIST_ENTRY *PLIST_ENTRY;
static void InitializeListHead(PLIST_ENTRY p) { p->Flink = p->Blink = p; }
static bool IsListEmpty(PLIST_ENTRY p) { return p->Flink == p; }
static void InsertTailList(PLIST_ENTRY p, PLIST_ENTRY e) {
    e->Flink = p; e->Blink = p->Blink; p->Blink->Flink = e; p->Blink = e;
}
static PLIST_ENTRY RemoveHeadList(PLIST_ENTRY p) {
    assert(!IsListEmpty(p));
    PLIST_ENTRY e = p->Flink; p->Flink = e->Flink; e->Flink->Blink = p; return e;
}
static std::mutex interlocked;
static LONG InterlockedIncrement(PLONG p) { std::lock_guard<std::mutex> g(interlocked); return ++*p; }
static LONG InterlockedDecrement(PLONG p) { std::lock_guard<std::mutex> g(interlocked); return --*p; }
struct BTHX_HCI_READ_WRITE_CONTEXT { UCHAR Type; ULONG DataLen; UCHAR Data[1]; };
typedef BTHX_HCI_READ_WRITE_CONTEXT *PBTHX_HCI_READ_WRITE_CONTEXT;
struct Request {
    std::vector<UCHAR> Buffer = std::vector<UCHAR>(2048);
    NTSTATUS Status = STATUS_PENDING;
    size_t Information = 0;
    unsigned Completed = 0;
    bool OutputFailure = false, Hold = false;
};
typedef Request *WDFREQUEST, *WDFMEMORY;
struct Queue { std::deque<WDFREQUEST> Requests; NTSTATUS State = STATUS_SUCCESS; };
typedef Queue *WDFQUEUE;
typedef std::mutex *WDFSPINLOCK;
static thread_local bool locked = false;
static void WdfSpinLockAcquire(WDFSPINLOCK p) { assert(!locked); p->lock(); locked = true; }
static void WdfSpinLockRelease(WDFSPINLOCK p) { assert(locked); locked = false; p->unlock(); }
static NTSTATUS WdfIoQueueRetrieveNextRequest(WDFQUEUE q, WDFREQUEST *out) {
    assert(locked); *out = nullptr;
    if (q->State != STATUS_SUCCESS) return q->State;
    if (q->Requests.empty()) return STATUS_NO_MORE_ENTRIES;
    *out = q->Requests.front(); q->Requests.pop_front(); return STATUS_SUCCESS;
}
static std::mutex handoff;
static std::condition_variable handoffCv;
static bool awaiting = false, releaseHeld = false;
static NTSTATUS WdfRequestRetrieveOutputMemory(WDFREQUEST r, WDFMEMORY *out) {
    assert(!locked);
    if (r->Hold) {
        std::unique_lock<std::mutex> g(handoff); awaiting = true; handoffCv.notify_all();
        handoffCv.wait(g, [] { return releaseHeld; });
    }
    if (r->OutputFailure) return STATUS_INVALID_PARAMETER;
    *out = r; return STATUS_SUCCESS;
}
static PBTHX_HCI_READ_WRITE_CONTEXT WdfMemoryGetBuffer(WDFMEMORY r, size_t *size) {
    *size = r->Buffer.size(); return (PBTHX_HCI_READ_WRITE_CONTEXT)r->Buffer.data();
}
static void WdfRequestCompleteWithInformation(WDFREQUEST r, NTSTATUS s, ULONG_PTR n) {
    assert(!locked && r->Completed == 0); ++r->Completed; r->Status = s; r->Information = n;
}
static NTSTATUS HCIContextValidate(LONG, PBTHX_HCI_READ_WRITE_CONTEXT) { return STATUS_SUCCESS; }
static std::map<void*, size_t> allocations;
static size_t liveBytes = 0, peakBytes = 0, allocationCalls = 0;
static bool failAllocation = false, enforceBudget = true;
static void *ExAllocatePool2(unsigned, size_t bytes, unsigned) {
    assert(locked);
    if (failAllocation) { failAllocation = false; return nullptr; }
    void *p = calloc(1, bytes); assert(p);
    allocations[p] = bytes; liveBytes += bytes; ++allocationCalls;
    if (liveBytes > peakBytes) peakBytes = liveBytes;
    if (enforceBudget) assert(liveBytes <= HCI_PREFETCH_MAX_ALLOCATION_BYTES);
    return p;
}
static void ExFreePool(void *p) {
    assert(locked && allocations.count(p));
    liveBytes -= allocations.at(p); allocations.erase(p); free(p);
}
"""

DEVICE = r"""
struct FDO_EXTENSION {
    std::mutex Lock;
    WDFSPINLOCK QueueAccessLock = &Lock;
    Queue Events, Data;
    WDFQUEUE ReadEventQueue = &Events, ReadDataQueue = &Data;
    LIST_ENTRY ReadEventList, ReadDataList;
    LONG EventQueueCount = 0, DataQueueCount = 0, EventListCount = 0, DataListCount = 0;
    ULONG PrefetchedPacketBytes = 0;
    LONG CntEventCompleted = 0, CntReadDataCompleted = 0;
    FDO_EXTENSION() { InitializeListHead(&ReadEventList); InitializeListHead(&ReadDataList); }
};
typedef FDO_EXTENSION *PFDO_EXTENSION;
"""

TEST = r"""
static NTSTATUS packet(PFDO_EXTENSION f, bool event, const std::vector<UCHAR>& b) {
    return ReadRequestComplete(f, (UCHAR)(event ? HciPacketEvent : HciPacketAclData),
        (ULONG)b.size(), const_cast<PUCHAR>(b.data()),
        event ? f->ReadEventQueue : f->ReadDataQueue,
        event ? &f->EventQueueCount : &f->DataQueueCount,
        event ? &f->ReadEventList : &f->ReadDataList,
        event ? &f->EventListCount : &f->DataListCount);
}
static void post(PFDO_EXTENSION f, bool event, WDFREQUEST r) {
    WdfSpinLockAcquire(f->QueueAccessLock);
    (event ? f->Events : f->Data).Requests.push_back(r);
    InterlockedIncrement(event ? &f->EventQueueCount : &f->DataQueueCount);
    WdfSpinLockRelease(f->QueueAccessLock);
}
static NTSTATUS consume(PFDO_EXTENSION f, bool event, WDFREQUEST r) {
    post(f, event, r);
    return ReadRequestComplete(f, (UCHAR)(event ? HciPacketEvent : HciPacketAclData), 0, nullptr,
        event ? f->ReadEventQueue : f->ReadDataQueue,
        event ? &f->EventQueueCount : &f->DataQueueCount,
        event ? &f->ReadEventList : &f->ReadDataList,
        event ? &f->EventListCount : &f->DataListCount);
}
static void empty(PFDO_EXTENSION f) {
    ReadPacketListsPurge(f);
    assert(allocations.empty() && liveBytes == 0 && f->PrefetchedPacketBytes == 0);
    assert(f->EventListCount == 0 && f->DataListCount == 0);
}
int main(int argc, char**) {
    FDO_EXTENSION f;
    if (argc > 1) {
        enforceBudget = false;
        for (unsigned i = 0; i < 4096; ++i) packet(&f, true, {0x0e, 0});
        for (unsigned i = 0; i < 256; ++i) packet(&f, false, std::vector<UCHAR>(MAX_HCI_ACLDATA_SIZE, 0x55));
        bool reproduced = peakBytes > HCI_PREFETCH_MAX_ALLOCATION_BYTES &&
            f.EventListCount > (LONG)HCI_PREFETCH_MAX_ENTRIES_PER_LIST &&
            f.DataListCount > (LONG)HCI_PREFETCH_MAX_ENTRIES_PER_LIST;
        printf("baseline: event=%ld acl=%ld requested_bytes=%zu; unbounded growth %s\n",
            (long)f.EventListCount, (long)f.DataListCount, peakBytes, reproduced ? "reproduced" : "NOT reproduced");
        empty(&f); return reproduced ? 0 : 1;
    }

    for (unsigned i = 0; i < HCI_PREFETCH_MAX_ENTRIES_PER_LIST; ++i)
        assert(packet(&f, true, {(UCHAR)i, 0}) == STATUS_SUCCESS);
    size_t calls = allocationCalls;
    for (unsigned i = 0; i < 100000; ++i)
        assert(packet(&f, true, {0x0e, 0}) == STATUS_QUOTA_EXCEEDED);
    assert(allocationCalls == calls && f.EventListCount == (LONG)HCI_PREFETCH_MAX_ENTRIES_PER_LIST);
    for (unsigned i = 0; i < HCI_PREFETCH_MAX_ENTRIES_PER_LIST; ++i) {
        Request r; assert(consume(&f, true, &r) == STATUS_SUCCESS);
        auto c = (PBTHX_HCI_READ_WRITE_CONTEXT)r.Buffer.data();
        assert(r.Completed == 1 && c->Type == HciPacketEvent && c->DataLen == 2 && c->Data[0] == (UCHAR)i);
        if (i == 0) assert(packet(&f, true, {0xa5, 0}) == STATUS_SUCCESS);
    }
    Request resumed; assert(consume(&f, true, &resumed) == STATUS_SUCCESS);
    assert(((PBTHX_HCI_READ_WRITE_CONTEXT)resumed.Buffer.data())->Data[0] == 0xa5);
    empty(&f);

    std::vector<UCHAR> acl(MAX_HCI_ACLDATA_SIZE, 0x55);
    for (unsigned i = 0; i < 8; ++i) {
        auto b = acl; b[4] = (UCHAR)i; assert(packet(&f, false, b) == STATUS_SUCCESS);
    }
    for (unsigned i = 0; i < 8; ++i) {
        Request r; assert(consume(&f, false, &r) == STATUS_SUCCESS);
        auto c = (PBTHX_HCI_READ_WRITE_CONTEXT)r.Buffer.data();
        assert(r.Completed == 1 && c->Type == HciPacketAclData &&
            c->DataLen == acl.size() && c->Data[4] == (UCHAR)i);
    }
    empty(&f);
    unsigned accepted = 0;
    while (packet(&f, false, acl) == STATUS_SUCCESS) ++accepted;
    assert(accepted > 1 && accepted < HCI_PREFETCH_MAX_ENTRIES_PER_LIST);
    for (unsigned i = 0; i < 100000; ++i) packet(&f, false, acl);
    for (unsigned i = 0; i < 100000; ++i) packet(&f, true, {0x0e, 0});
    assert(liveBytes == f.PrefetchedPacketBytes && liveBytes <= HCI_PREFETCH_MAX_ALLOCATION_BYTES);

    Request held; held.Hold = true;
    std::thread consumer([&] { assert(consume(&f, false, &held) == STATUS_SUCCESS); });
    { std::unique_lock<std::mutex> g(handoff); handoffCv.wait(g, [] { return awaiting; }); }
    calls = allocationCalls;
    for (unsigned i = 0; i < 10000; ++i) assert(packet(&f, false, acl) == STATUS_QUOTA_EXCEEDED);
    assert(calls == allocationCalls);
    { std::lock_guard<std::mutex> g(handoff); releaseHeld = true; handoffCv.notify_all(); }
    consumer.join(); assert(held.Completed == 1);
    assert(liveBytes == f.PrefetchedPacketBytes); empty(&f);

    failAllocation = true;
    assert(packet(&f, true, {0x0e, 0}) == STATUS_INSUFFICIENT_RESOURCES);
    assert(f.EventListCount == 0 && f.PrefetchedPacketBytes == 0);
    assert(packet(&f, true, {0x0e, 0}) == STATUS_SUCCESS);
    Request bad; bad.OutputFailure = true;
    assert(consume(&f, true, &bad) == STATUS_INVALID_PARAMETER);
    assert(bad.Completed == 1 && liveBytes == 0 && f.PrefetchedPacketBytes == 0);

    for (NTSTATUS state : {STATUS_WDF_PAUSED, STATUS_INVALID_PARAMETER}) {
        f.Events.State = state; calls = allocationCalls;
        assert(packet(&f, true, {0x0e, 0}) == state && allocationCalls == calls);
    }
    f.Events.State = STATUS_SUCCESS;
    assert(packet(&f, false, std::vector<UCHAR>(MAX_HCI_ACLDATA_SIZE + 1, 0)) == STATUS_INVALID_BUFFER_SIZE);
    assert(f.PrefetchedPacketBytes == 0);

    calls = allocationCalls;
    for (unsigned i = 0; i < 10000; ++i) {
        Request r; post(&f, false, &r); assert(packet(&f, false, acl) == STATUS_SUCCESS);
        auto c = (PBTHX_HCI_READ_WRITE_CONTEXT)r.Buffer.data();
        assert(r.Completed == 1 && c->Type == HciPacketAclData && c->DataLen == acl.size());
        assert(memcmp(c->Data, acl.data(), acl.size()) == 0);
    }
    assert(calls == allocationCalls);

    failAllocation = true;
    UCHAR event[] = {0x0e, 0};
    assert(ReadH4PacketComplete(&f, HciPacketEvent, event, sizeof(event)) == STATUS_SUCCESS);
    empty(&f);

    std::thread events([&] { for (unsigned i = 0; i < 30000; ++i) packet(&f, true, {0x0e, 0}); });
    std::thread data([&] { for (unsigned i = 0; i < 30000; ++i) packet(&f, false, acl); });
    std::thread purge([&] { for (unsigned i = 0; i < 300; ++i) ReadPacketListsPurge(&f); });
    events.join(); data.join(); purge.join(); empty(&f);
    assert(peakBytes <= HCI_PREFETCH_MAX_ALLOCATION_BYTES);
    printf("prefetch production cases passed; peak requested bytes=%zu; allocation calls=%zu\n", peakBytes, allocationCalls);
}
"""


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=output_dir('bt-prefetch'))
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    io = (ROOT / 'bt/src/io.c').read_text(encoding='utf-8-sig')
    header = (ROOT / 'bt/src/io.h').read_text(encoding='utf-8-sig')
    assert 'HCI_PREFETCH_MAX_ALLOCATION_BYTES' in header
    names = ['HLP_CreatePacketEntry', 'HLP_FreePacketEntryLocked', 'HLP_PurgePacketList',
             'ReadPacketListsPurge', 'ReadRequestComplete', 'ReadH4PacketComplete']
    for path, name in [('bt/src/io.c', 'ReadResourcesReset'),
                       ('bt/src/io.c', 'ReadResourcesFree'),
                       ('bt/src/pdo.c', 'PdoDevSelfManagedIoCleanup'),
                       ('bt/src/Fdo.c', 'FdoDevD0Exit')]:
        assert 'ReadPacketListsPurge(' in function((ROOT / path).read_text(encoding='utf-8-sig'), name), path
    fdo = (ROOT / 'bt/src/Fdo.c').read_text(encoding='utf-8-sig')
    release = function(fdo, 'FdoDevReleaseHardware')
    assert not re.search(r'WdfObjectDelete\s*\(\s*FdoExtension->QueueAccessLock\s*\)', release)
    assert not re.search(r'FdoExtension->QueueAccessLock\s*=', release)
    initialize = function(fdo, 'HlpInitializeFdoExtension')
    assert re.search(r'if\s*\(FdoExtension->QueueAccessLock == NULL\)\s*\{\s*Status = WdfSpinLockCreate', initialize)
    definitions = '\n'.join(line for line in header.splitlines()
        if re.match(r'#define (HCI_ACL_HEADER_SIZE|HCI_MAX_ACL_PAYLOAD_SIZE|MAX_HCI_ACLDATA_SIZE|HCI_PREFETCH_MAX_\w+)\b', line))
    entry = re.search(r'typedef struct _HCI_PACKET_ENTRY \{.*?\} HCI_PACKET_ENTRY, \*PHCI_PACKET_ENTRY;', header, re.S)[0]
    code = definitions + '\n' + PRE + entry + '\n' + DEVICE
    code += '\n' + '\n'.join(function(io, name) for name in names) + '\n' + TEST
    cpp = out / 'prefetch.cpp'
    write_bluetooth_text(cpp, code)
    command = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT',
               '/I' + str(VC / 'include')]
    command += ['/I' + str(INC / part) for part in ('ucrt', 'shared', 'um')]
    command += [str(cpp), '/Fe:' + str(out / 'prefetch.exe'), '/Fo:' + str(out / 'prefetch.obj'),
                '/link', '/LIBPATH:' + str(VC / 'lib/x64'),
                '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    build = subprocess.run(command, capture_output=True, text=True)
    write_text(out / 'compile.log', build.stdout + build.stderr, encoding='utf-8')
    if build.returncode:
        print(build.stdout + build.stderr)
        raise SystemExit(build.returncode)
    run = subprocess.run([str(out / 'prefetch.exe')], capture_output=True, text=True, timeout=60)
    write_text(out / 'run.log', run.stdout + run.stderr, encoding='utf-8')
    receipt = dict(passed=run.returncode == 0, exit_code=run.returncode, board_tested=False,
                   source_sha256={name: sha(ROOT / name) for name in
                       ('bt/src/io.c', 'bt/src/io.h', 'bt/src/driver.h', 'bt/src/Fdo.c', 'bt/src/pdo.c')},
                   test_sha256=sha(Path(__file__)), harness_sha256=sha(cpp), compiler_sha256=sha(Path(command[0])),
                   executable_sha256=sha(out / 'prefetch.exe'),
                   notices_sha256={name: sha(ROOT / name) for name in
                       ('LICENSE', 'NOTICE.txt', 'BLUETOOTH-LINKING-EXCEPTION.txt', 'bt/LICENSE-MS-PL.txt')})
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(run.stdout + run.stderr)
    raise SystemExit(run.returncode)


if __name__ == '__main__':
    main()
