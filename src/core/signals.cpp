// SPDX-FileCopyrightText: Copyright 2024-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/arch.h"
#include "common/assert.h"
#include "common/decoder.h"
#include "common/logging/log.h"
#include "common/signal_context.h"
#include "core/libraries/kernel/threads/exception.h"
#include "core/signals.h"
#include "emulator.h"

#ifdef _WIN32
#include <atomic>
#include <chrono>
#include <thread>
#include <unordered_set>
#include <windows.h>
// tlhelp32.h requires windows.h to have been included first; keep it in its own block so the
// include sorter cannot move it above.
#include <tlhelp32.h>
static constexpr DWORD MS_VC_EXCEPTION = 0x406D1388;
#else
#include <csignal>
#include <pthread.h>
#ifdef ARCH_X86_64
#include <Zydis/Formatter.h>
#endif
#endif

#ifndef _WIN32
namespace Libraries::Kernel {
void SigactionHandler(int native_signum, siginfo_t* inf, ucontext_t* raw_context);
extern std::array<OrbisKernelExceptionHandler, 32> Handlers;
} // namespace Libraries::Kernel
#endif

namespace Core {

#if defined(_WIN32)

// ---------------------------------------------------------------------------
// RED ZONE TRAP (diagnostic build only)
//
// CUSA00049 dies deterministically at 0x8012d6ca5, dereferencing a pointer it has just
// reloaded from [rsp-0x20]. That pointer is written at 0x8012d6a3e from RSI, which the
// prologue proves non-null (it dereferences [rsi+0x10] at 0x8012d68d1) and which nothing
// rewrites in between. At the moment of the crash the slot reads zero while the caller's own
// copy of the same pointer is still intact one frame up, so the red-zone copy is destroyed
// while the frame that owns it is still live.
//
// The previous iteration armed a hardware watchpoint from inside the fault handler, which
// meant it could only ever arm on a thread that happened to take a tracked memory fault while
// the window was open. On the run that crashed, the fatal thread took exactly one such fault
// inside the window - and the slot was *already* zero when it did. So the corruption does not
// come from our fault handler, and a fault-driven trap can never be armed early enough to
// witness it.
//
// This version does not depend on faults at all. A monitor thread installs an execution
// breakpoint (DR1) on the instruction immediately after the store, on every thread in the
// process. When it fires, the pointer has just been written and is live; we then point a write
// watchpoint (DR0) at that exact slot. Whatever writes it next - guest code, emulator code or
// the kernel - stops the processor on the spot and identifies itself by its RIP.
// ---------------------------------------------------------------------------

/// First instruction after `mov QWORD PTR [rsp-0x20], rsi` in the leaf function at 0x8012d68c0.
static constexpr u64 GuestStoreRip = 0x8012d6a43;
/// Bounds of that leaf function, used to log any exception taken while it is running.
static constexpr u64 GuestFuncLo = 0x8012d68c0;
static constexpr u64 GuestFuncHi = 0x8012d6ca8;
/// Offset of the watched red-zone slot from the owning frame's RSP.
static constexpr u64 RedZoneSlot = 0x20;
/// The leaf pushes six registers, so a live frame still has its return address at rsp+0x30.
static constexpr u64 LeafReturnSlot = 0x30;
static constexpr u64 LeafReturnAddress = 0x8012df2b4;
/// The guest image is loaded at 0x800000000; anything below that is host code.
static constexpr u64 GuestImageBase = 0x800000000;

/// DR7 bit 0 (L0) enables DR0, and bits 16..19 hold (LEN0 << 2) | RW0 - here RW0=01 for
/// "break on data write" and LEN0=11 for eight bytes, giving 0xD. Bit 2 (L1) enables DR1, and
/// bits 20..23 stay zero, which encodes RW1=00 "break on instruction execution" with LEN1=00,
/// the only legal length for an execution breakpoint.
static constexpr u64 Dr7EnableExec1 = 0x4ULL;
static constexpr u64 Dr7EnableWrite0 = 0x1ULL | (0xDULL << 16);
static constexpr u64 Dr7MaskWrite0 = 0xFULL | (0xFULL << 16);

/// RSP of the frame whose red-zone slot DR0 currently watches, per thread.
static u64& TrapLeafRsp() {
    static thread_local u64 value = 0;
    return value;
}

/// Installs the execution breakpoint on every thread of this process, including ones created
/// later. Debug registers are per-thread and reachable only through a thread's CONTEXT, so each
/// thread has to be suspended briefly once; after that it is remembered and left alone.
static void RedZoneArmerThread() {
    std::unordered_set<DWORD> armed;
    const DWORD pid = GetCurrentProcessId();
    const DWORD self = GetCurrentThreadId();
    while (true) {
        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 entry{};
            entry.dwSize = sizeof(THREADENTRY32);
            if (Thread32First(snapshot, &entry)) {
                do {
                    if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == self ||
                        armed.contains(entry.th32ThreadID)) {
                        continue;
                    }
                    const HANDLE thread =
                        OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                   FALSE, entry.th32ThreadID);
                    if (thread == nullptr) {
                        continue;
                    }
                    if (SuspendThread(thread) != static_cast<DWORD>(-1)) {
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (GetThreadContext(thread, &ctx)) {
                            ctx.Dr1 = GuestStoreRip;
                            ctx.Dr7 = (ctx.Dr7 & ~(0xFULL << 20)) | Dr7EnableExec1;
                            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                            if (SetThreadContext(thread, &ctx)) {
                                armed.insert(entry.th32ThreadID);
                            }
                        }
                        ResumeThread(thread);
                    }
                    CloseHandle(thread);
                } while (Thread32Next(snapshot, &entry));
            }
            CloseHandle(snapshot);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

static LONG WINAPI SignalHandler(EXCEPTION_POINTERS* pExp) noexcept {
    const auto* signals = Signals::Instance();
    DWORD code = 0;
    PVOID address = nullptr;

    if (pExp != nullptr && pExp->ExceptionRecord != nullptr) {
        code = pExp->ExceptionRecord->ExceptionCode;
        address = pExp->ExceptionRecord->ExceptionAddress;
    }

    // Any exception taken while the watched guest function is running matters, not just the
    // memory-tracking faults the old probe looked at: every kind of dispatch writes below RSP,
    // and a C++ throw or an APC delivered here would have been completely invisible before.
    if (pExp != nullptr && pExp->ContextRecord != nullptr && code != EXCEPTION_SINGLE_STEP) {
        const u64 rip = pExp->ContextRecord->Rip;
        if (rip >= GuestFuncLo && rip < GuestFuncHi) {
            static std::atomic<u32> seen{0};
            if (seen.fetch_add(1, std::memory_order_relaxed) < 200) {
                const auto* rz = reinterpret_cast<const u64*>(pExp->ContextRecord->Rsp);
                LOG_WARNING(Debug,
                            "RedZoneWatch: exception {:#x} at rip={:#x} rsp={:#x}  "
                            "[rsp-0x20]={:#018x}",
                            static_cast<u64>(code), rip, pExp->ContextRecord->Rsp, rz[-4]);
            }
        }
    }

    bool handled = false;
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
        handled = signals->DispatchAccessViolation(
            pExp, reinterpret_cast<void*>(pExp->ExceptionRecord->ExceptionInformation[1]));
        break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        handled = signals->DispatchIllegalInstruction(pExp);
        break;
    case EXCEPTION_SINGLE_STEP: {
        auto* c = pExp != nullptr ? pExp->ContextRecord : nullptr;
        if (c == nullptr) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        // DR1 - execution breakpoint just after the store. The pointer is in the red zone and
        // live from here until the reload at 0x8012d6ca0, so aim the write watchpoint at it.
        // Re-aimed on every call: the invocation that gets corrupted is not necessarily the
        // first one this thread makes.
        if ((c->Dr6 & 0x2ULL) != 0) {
            const u64 slot = c->Rsp - RedZoneSlot;
            const u64 value = *reinterpret_cast<const u64*>(slot);
            TrapLeafRsp() = c->Rsp;
            static std::atomic<u64> calls{0};
            const u64 n = calls.fetch_add(1, std::memory_order_relaxed) + 1;
            if (value == 0) {
                // The guest stored a null itself. That would move the bug upstream of this
                // function entirely and clear the red zone of any responsibility.
                LOG_CRITICAL(
                    Debug, "RedZoneTrap: the value stored is ALREADY ZERO at rsp={:#x} (call #{})",
                    c->Rsp, n);
            } else {
                c->Dr0 = slot;
                c->Dr7 = (c->Dr7 & ~Dr7MaskWrite0) | Dr7EnableWrite0;
            }
            if ((n & (n - 1)) == 0) {
                LOG_INFO(Debug, "RedZoneTrap: watching call #{}  slot={:#x}  value={:#018x}", n,
                         slot, value);
            }
            c->Dr6 = 0;
            // RF tells the processor to execute the instruction under the breakpoint once
            // without trapping again, which is what makes resuming here safe.
            c->EFlags |= 0x10000;
            c->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // DR0 - the watched slot was written. The trap fires after the write retires, so RIP
        // already points at the instruction following the one responsible.
        if ((c->Dr6 & 0x1ULL) != 0) {
            const u64 slot = c->Dr0;
            const u64 value = *reinterpret_cast<const u64*>(slot);
            const u64 leaf_rsp = TrapLeafRsp();
            const u64 ret =
                leaf_rsp != 0 ? *reinterpret_cast<const u64*>(leaf_rsp + LeafReturnSlot) : 0;
            // Two signatures are worth waking up for. A writer whose RIP is below the guest
            // image is host code - the emulator or the kernel reaching into the guest's stack,
            // which is the bug we are hunting. A zero written while the leaf's return address
            // is still in place means the frame was live and its red zone was trampled.
            // Everything else is ordinary stack reuse after the function returned, which the
            // previous build drowned in; those are counted, not printed.
            const bool writer_is_host = c->Rip < GuestImageBase;
            const bool frame_still_live = ret == LeafReturnAddress;
            if (writer_is_host || (frame_still_live && value == 0)) {
                LOG_CRITICAL(Debug,
                             "RedZoneTrap: WRITE to {:#x} -> {:#018x} by the instruction before "
                             "rip={:#x}  rsp={:#x}  leaf rsp={:#x}  return slot={:#018x}  "
                             "host_writer={}  frame_live={}",
                             slot, value, c->Rip, c->Rsp, leaf_rsp, ret, writer_is_host,
                             frame_still_live);
                Common::Log::Flush();
            } else {
                static std::atomic<u64> reuse{0};
                const u64 n = reuse.fetch_add(1, std::memory_order_relaxed) + 1;
                if ((n & (n - 1)) == 0) {
                    LOG_INFO(Debug, "RedZoneTrap: {} benign stack reuses so far", n);
                }
            }
            // Keep the execution breakpoint, drop the watchpoint: the next call re-aims it.
            c->Dr7 &= ~Dr7MaskWrite0;
            c->Dr6 = 0;
            c->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    case DBG_PRINTEXCEPTION_C:
    case DBG_PRINTEXCEPTION_WIDE_C:
        // Used by OutputDebugString functions.
        return EXCEPTION_CONTINUE_EXECUTION;
    case MS_VC_EXCEPTION:
        LOG_DEBUG(Debug, "Pass MS_VC_EXCEPTION at {} to handler", address);
        return EXCEPTION_EXECUTE_HANDLER;
    default:
        break;
    }

    if (handled) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Breakpoints almost certainly come from our asserts/unreachables, no need to log it again.
    if (code != EXCEPTION_BREAKPOINT) {
        LOG_CRITICAL(Debug, "Unhandled Exception code {:#x} at {}", code, address);
        // Dump enough state to identify what corrupted the guest.
        //
        // The System V ABI lets guest leaf functions keep live data in the 128 bytes below RSP
        // (the red zone). Windows has no red zone and writes exception frames there, so any
        // handled fault taken while such a function is running destroys that data. Printing
        // the registers and the red zone at the moment of the fatal fault says whether that is
        // what actually happened here, or whether the corruption comes from somewhere else.
        if (code == EXCEPTION_ACCESS_VIOLATION && pExp != nullptr &&
            pExp->ContextRecord != nullptr) {
            const auto* ctx = pExp->ContextRecord;
            LOG_CRITICAL(Debug, "  rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}", ctx->Rax,
                         ctx->Rbx, ctx->Rcx, ctx->Rdx);
            LOG_CRITICAL(Debug, "  rsi={:#018x} rdi={:#018x} rbp={:#018x} rsp={:#018x}", ctx->Rsi,
                         ctx->Rdi, ctx->Rbp, ctx->Rsp);
            const auto* red = reinterpret_cast<const u64*>(ctx->Rsp - 128);
            for (u32 i = 0; i < 16; i += 2) {
                LOG_CRITICAL(Debug, "  [rsp-{:#05x}] {:#018x}   [rsp-{:#05x}] {:#018x}",
                             128 - i * 8, red[i], 128 - (i + 1) * 8, red[i + 1]);
            }
            // Also dump above RSP. A faulting leaf function pushes nothing, so the caller's
            // frame starts immediately here: the same values the crashing function received
            // as arguments are still visible in the caller's own locals. Comparing the two
            // says whether a pointer arrived corrupted or was corrupted after being stored.
            const auto* up = reinterpret_cast<const u64*>(ctx->Rsp);
            for (u32 i = 0; i < 16; i += 2) {
                LOG_CRITICAL(Debug, "  [rsp+{:#05x}] {:#018x}   [rsp+{:#05x}] {:#018x}", i * 8,
                             up[i], (i + 1) * 8, up[i + 1]);
            }
        }
        // Flush before anything else. Emulator::Shutdown() only flushes on its first call
        // (it early-returns once exit_done is set), so any earlier non-fatal exception -
        // a C++ exception at 0xe06d7363, for instance - permanently disables the flush for
        // every crash that follows. The line above would then never reach the file and the
        // log would simply end mid-write, which is exactly what CUSA00049 looked like.
        Common::Log::Flush();
        Common::Singleton<Core::Emulator>::Instance()->Shutdown();
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

#else

static std::string DisassembleInstruction(void* code_address) {
    char buffer[256] = "<unable to decode>";

#ifdef ARCH_X86_64
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    const auto status =
        Common::Decoder::Instance()->decodeInstruction(instruction, operands, code_address);
    if (ZYAN_SUCCESS(status)) {
        ZydisFormatter formatter;
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                        instruction.operand_count_visible, buffer, sizeof(buffer),
                                        reinterpret_cast<u64>(code_address), ZYAN_NULL);
    }
#endif

    return buffer;
}

void SignalHandler(int sig, siginfo_t* info, void* raw_context) {
    const auto* signals = Signals::Instance();

    auto* code_address = Common::GetRip(raw_context);

    switch (sig) {
    case SIGSEGV:
    case SIGBUS: {
        const bool is_write = Common::IsWriteError(raw_context);
        if (!signals->DispatchAccessViolation(raw_context, info->si_addr)) {
            // If the guest has installed a custom signal handler, and the access violation didn't
            // come from HLE memory tracking, pass the signal on
            if (Libraries::Kernel::Handlers[Libraries::Kernel::NativeToOrbisSignal(sig)]) {
                Libraries::Kernel::SigactionHandler(sig, info,
                                                    reinterpret_cast<ucontext_t*>(raw_context));
                return;
            }
            UNREACHABLE_MSG("Unhandled access violation at code address {}: {} address {}",
                            fmt::ptr(code_address), is_write ? "Write to" : "Read from",
                            fmt::ptr(info->si_addr));
        }
        break;
    }
    case SIGILL:
        if (!signals->DispatchIllegalInstruction(raw_context)) {
            if (Libraries::Kernel::Handlers[Libraries::Kernel::NativeToOrbisSignal(sig)]) {
                Libraries::Kernel::SigactionHandler(sig, info,
                                                    reinterpret_cast<ucontext_t*>(raw_context));
                return;
            }
            UNREACHABLE_MSG("Unhandled illegal instruction at code address {}: {}",
                            fmt::ptr(code_address), DisassembleInstruction(code_address));
        }
        break;
    default:
        if (sig == SIGSLEEP) {
            // Sleep thread until signal is received again
            sigset_t sigset;
            sigemptyset(&sigset);
            sigaddset(&sigset, SIGSLEEP);
            sigwait(&sigset, &sig);
        }
        break;
    }
}

#endif

SignalDispatch::SignalDispatch() {
#if defined(_WIN32)
    ASSERT_MSG(handle = AddVectoredExceptionHandler(0, SignalHandler),
               "Failed to register exception handler.");
    // Diagnostic: installs the red-zone execution breakpoint on every guest thread.
    std::thread(RedZoneArmerThread).detach();
#else
    struct sigaction action{};
    action.sa_sigaction = SignalHandler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);

    ASSERT_MSG(sigaction(SIGSEGV, &action, nullptr) == 0 &&
                   sigaction(SIGBUS, &action, nullptr) == 0,
               "Failed to register access violation signal handler.");
    ASSERT_MSG(sigaction(SIGILL, &action, nullptr) == 0,
               "Failed to register illegal instruction signal handler.");
    ASSERT_MSG(sigaction(SIGSLEEP, &action, nullptr) == 0,
               "Failed to register sleep signal handler.");
#endif
}

SignalDispatch::~SignalDispatch() {
#if defined(_WIN32)
    ASSERT_MSG(RemoveVectoredExceptionHandler(handle), "Failed to remove exception handler.");
#else
    struct sigaction action{};
    action.sa_handler = SIG_DFL;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);

    ASSERT_MSG(sigaction(SIGSEGV, &action, nullptr) == 0 &&
                   sigaction(SIGBUS, &action, nullptr) == 0,
               "Failed to remove access violation signal handler.");
    ASSERT_MSG(sigaction(SIGILL, &action, nullptr) == 0,
               "Failed to remove illegal instruction signal handler.");
#endif
}

bool SignalDispatch::DispatchAccessViolation(void* context, void* fault_address) const {
    for (const auto& [handler, _] : access_violation_handlers) {
        if (handler(context, fault_address)) {
            return true;
        }
    }
    return false;
}

bool SignalDispatch::DispatchIllegalInstruction(void* context) const {
    for (const auto& [handler, _] : illegal_instruction_handlers) {
        if (handler(context)) {
            return true;
        }
    }
    return false;
}

} // namespace Core
