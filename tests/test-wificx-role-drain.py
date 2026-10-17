# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

"""Execute the passive WLFC role cancellation barrier against an active writer."""
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, importlib.util, json, subprocess
from driver_sources import _functions
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('roles_drain', ROOT / 'tests/test-wificx-roles.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
PREAMBLE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
typedef void VOID,*PVOID;typedef uint16_t UINT16;
struct AP6256_LOCK {std::mutex Native;bool Writer;explicit AP6256_LOCK(bool writer=true):Writer(writer){}};
struct AP6256_WLFC {AP6256_LOCK WorkerLock;};
struct Device {AP6256_LOCK WlfcLifetimeLock{false};AP6256_WLFC* Wlfc=nullptr;};typedef Device* PAP6256_DEVICE_CONTEXT;
static std::mutex control;static std::condition_variable changed;
static bool writerEntered=false,releaseWriter=false,acquireAttempt=false,completed=false;
static unsigned cancelled=0;static UINT16 portSeen=0,peerSeen=0;static PVOID cookieSeen=nullptr;
static void Ap6256WlfcCancel(Device*,UINT16 port,UINT16 peer,PVOID cookie) {++cancelled;portSeen=port;peerSeen=peer;cookieSeen=cookie;}
static void Ap6256LockAcquire(AP6256_LOCK* l) {if(l->Writer){{std::lock_guard<std::mutex> g(control);acquireAttempt=true;}changed.notify_all();}l->Native.lock();}
static void Ap6256LockRelease(AP6256_LOCK* l) {l->Native.unlock();}
'''
TEST = r'''
int main() {
    Device d;Ap6256WlfcCancelAndWait(&d,2,3,(PVOID)9);assert(cancelled==0);
    AP6256_WLFC w;d.Wlfc=&w;
    for(unsigned round=0;round<32;++round) {
        writerEntered=releaseWriter=acquireAttempt=completed=false;
        std::thread writer([&]{std::unique_lock<std::mutex> write(w.WorkerLock.Native);std::unique_lock<std::mutex> gate(control);writerEntered=true;changed.notify_all();changed.wait(gate,[]{return releaseWriter;});});
        {std::unique_lock<std::mutex> g(control);changed.wait(g,[]{return writerEntered;});}
        std::thread cancel([&]{Ap6256WlfcCancelAndWait(&d,2,3,(PVOID)9);{std::lock_guard<std::mutex> g(control);completed=true;}changed.notify_all();});
        {std::unique_lock<std::mutex> g(control);changed.wait(g,[]{return acquireAttempt || completed;});assert(acquireAttempt && !completed);releaseWriter=true;}
        changed.notify_all();writer.join();cancel.join();assert(completed && portSeen==2 && peerSeen==3 && cookieSeen==(PVOID)9);
    }
    assert(cancelled==32);puts("PASS production WLFC cancel/drain: 32 active writer barriers, scoped cancellation and absent-engine case");
}
'''

def main():
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    fn = _functions((ROOT / 'src/common/wlfc.c').read_text(encoding='utf-8-sig'))['Ap6256WlfcCancelAndWait']
    text = PREAMBLE + fn + TEST
    out = output_dir('wificx-role-drain') / 'current'
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    command = [str(base.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4505', '/Od', '/MT', '/I' + str(base.VC / 'include'), '/I' + str(base.INC / 'ucrt'), str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(base.VC / 'lib/x64'), '/LIBPATH:' + str(base.LIB / 'ucrt/x64'), '/LIBPATH:' + str(base.LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    run = subprocess.run([str(out / 'tests.exe')], timeout=30)
    assert run.returncode == 0, run.returncode
    write_text(out / 'receipt.json', json.dumps({'result': 'passed', 'function': 'Ap6256WlfcCancelAndWait', 'active_writer_cases': 32, 'board_verified': False, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest()}, indent=2), encoding='utf-8')
if __name__ == '__main__':
    main()
