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
#include <windows.h>
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

static LONG WINAPI SignalHandler(EXCEPTION_POINTERS* pExp) noexcept {
    const auto* signals = Signals::Instance();
    DWORD code = 0;
    PVOID address = nullptr;

    if (pExp != nullptr && pExp->ExceptionRecord != nullptr) {
        code = pExp->ExceptionRecord->ExceptionCode;
        address = pExp->ExceptionRecord->ExceptionAddress;
    }

    // Every exception taken while the CPU is running guest code is dangerous, whatever its
    // kind: Windows writes its records below RSP before any of our code runs, destroying the
    // 128 bytes of System V red zone that guest leaf functions are entitled to use. Now that
    // the memory tracker has stopped faulting on hot pages, count what is left and say where
    // it lands, so the remaining sources can be named rather than guessed at.
    if (pExp != nullptr && pExp->ContextRecord != nullptr) {
        static constexpr u64 GuestImageBase = 0x800000000;
        static constexpr u64 RedZoneFuncLo = 0x8012d68c0;
        static constexpr u64 RedZoneFuncHi = 0x8012d6ca8;
        const u64 rip = pExp->ContextRecord->Rip;
        if (rip >= GuestImageBase) {
            static volatile LONG64 guest_exceptions = 0;
            const u64 n = static_cast<u64>(InterlockedIncrement64(&guest_exceptions));
            if ((n & (n - 1)) == 0) {
                LOG_WARNING(Debug, "GuestException #{}: code={:#x} rip={:#x}", n,
                            static_cast<u64>(code), rip);
            }
            // CUSA00049 dies at 0x8012d6ca5 on a pointer it kept in the red zone of the leaf
            // function starting at 0x8012d68c0. Anything that interrupts that function while
            // it runs is a candidate for having destroyed it.
            if (rip >= RedZoneFuncLo && rip < RedZoneFuncHi) {
                static volatile LONG in_window = 0;
                if (InterlockedIncrement(&in_window) <= 64) {
                    LOG_CRITICAL(Debug, "RedZoneWindow: exception {:#x} at rip={:#x} rsp={:#x}",
                                 static_cast<u64>(code), rip, pExp->ContextRecord->Rsp);
                }
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
        // On an access violation, dump the guest state around the faulting frame. The System V
        // ABI the guest is compiled for reserves the 128 bytes below RSP - the red zone - for
        // leaf functions, and Windows writes exception records there, so a crash caused by that
        // corruption is recognisable from the red zone alone.
        if (code == EXCEPTION_ACCESS_VIOLATION && pExp != nullptr &&
            pExp->ContextRecord != nullptr) {
            const auto* ctx = pExp->ContextRecord;
            LOG_CRITICAL(Debug, "  rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}", ctx->Rax,
                         ctx->Rbx, ctx->Rcx, ctx->Rdx);
            LOG_CRITICAL(Debug, "  rsi={:#018x} rdi={:#018x} rbp={:#018x} rsp={:#018x}", ctx->Rsi,
                         ctx->Rdi, ctx->Rbp, ctx->Rsp);
            // Which address was touched, and whose code touched it. Without the module the
            // faulting RIP is just a number; with it, a crash inside the C runtime called from
            // the GPU path is immediately distinguishable from one in our own code.
            if (pExp->ExceptionRecord->NumberParameters >= 2) {
                const u64 fault_addr =
                    static_cast<u64>(pExp->ExceptionRecord->ExceptionInformation[1]);
                const bool is_write = pExp->ExceptionRecord->ExceptionInformation[0] == 1;
                LOG_CRITICAL(Debug, "  faulting {} of {:#018x}", is_write ? "write" : "read",
                             fault_addr);
            }
            HMODULE module = nullptr;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   reinterpret_cast<LPCSTR>(address), &module) != 0) {
                char path[MAX_PATH]{};
                if (GetModuleFileNameA(module, path, MAX_PATH) != 0) {
                    LOG_CRITICAL(Debug, "  in module {} at +{:#x}", path,
                                 reinterpret_cast<u64>(address) - reinterpret_cast<u64>(module));
                }
            }
            const auto* red = reinterpret_cast<const u64*>(ctx->Rsp - 128);
            for (u32 i = 0; i < 16; i += 2) {
                LOG_CRITICAL(Debug, "  [rsp-{:#05x}] {:#018x}   [rsp-{:#05x}] {:#018x}",
                             128 - i * 8, red[i], 128 - (i + 1) * 8, red[i + 1]);
            }
        }
        // Flush before anything else. Emulator::Shutdown() only flushes on its first call - it
        // early-returns once its exit_done flag is set - so any earlier non-fatal exception,
        // a C++ exception at 0xe06d7363 for instance, permanently disables the flush for every
        // crash that follows. The line above would then never reach the file and the log would
        // simply end mid-write, hiding the crash entirely.
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
