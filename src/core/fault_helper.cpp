// SPDX-FileCopyrightText: Copyright 2024-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "core/fault_helper.h"

#ifndef _WIN32

namespace Core::FaultHelper {
int Run(u32) {
    return 1;
}
bool Start() {
    return false;
}
void Drain() {}
bool IsActive() {
    return false;
}
} // namespace Core::FaultHelper

#else

#include <atomic>
#include <cstring>
#include <string>
#include <windows.h>

#include "common/logging/log.h"
#include "common/signal_context.h"
#include "core/signals.h"

namespace Core::FaultHelper {
namespace {

/// The helper cannot use the emulator's logger - it shares nothing with it - and a failure
/// there is invisible by definition, because the emulator is frozen while we hold a debug
/// event. So it keeps its own plain text trace next to the temp directory.
void Trace(const char* text) {
    wchar_t dir[MAX_PATH]{};
    if (GetTempPathW(MAX_PATH, dir) == 0) {
        return;
    }
    const std::wstring path = std::wstring(dir) + L"shadps4-fault-helper.log";
    const HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written = 0;
    WriteFile(file, text, static_cast<DWORD>(strlen(text)), &written, nullptr);
    WriteFile(file, "\r\n", 2, &written, nullptr);
    CloseHandle(file);
}

/// Ring of faults the helper has already made writable and the emulator has yet to record.
/// Lives in memory shared between the two processes; both sides only ever touch their own end.
struct Channel {
    static constexpr u32 Capacity = 4096;

    std::atomic<u32> head; // written by the helper
    std::atomic<u32> tail; // written by the emulator
    std::atomic<u64> dropped;
    struct Entry {
        u64 address;
        u32 is_write;
        u32 padding;
    } entries[Capacity];
};

Channel* channel = nullptr;
HANDLE channel_map = nullptr;
HANDLE helper_process = nullptr;
std::atomic<bool> active{false};

std::wstring ChannelName(u32 pid) {
    return L"shadps4-fault-channel-" + std::to_wstring(pid);
}

/// The guest image and its memory live above this; host allocations live below it. Faults on
/// host addresses are none of our business and must be handed back to the process untouched.
constexpr u64 GuestSpaceMin = 0x100000000ULL;

} // namespace

bool IsActive() {
    return active.load(std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// Emulator side
// ---------------------------------------------------------------------------

bool Start() {
    const u32 pid = GetCurrentProcessId();
    const std::wstring name = ChannelName(pid);

    channel_map = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                     sizeof(Channel), name.c_str());
    if (channel_map == nullptr) {
        LOG_ERROR(Core, "Fault helper: could not create the shared channel");
        return false;
    }
    channel = static_cast<Channel*>(
        MapViewOfFile(channel_map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Channel)));
    if (channel == nullptr) {
        LOG_ERROR(Core, "Fault helper: could not map the shared channel");
        return false;
    }
    channel->head.store(0, std::memory_order_relaxed);
    channel->tail.store(0, std::memory_order_relaxed);
    channel->dropped.store(0, std::memory_order_relaxed);

    wchar_t exe[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, exe, MAX_PATH) == 0) {
        LOG_ERROR(Core, "Fault helper: could not find our own executable");
        return false;
    }
    std::wstring command = L"\"" + std::wstring(exe) + L"\" --fault-helper " + std::to_wstring(pid);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                        nullptr, &si, &pi)) {
        LOG_ERROR(Core, "Fault helper: could not start the helper process ({})", GetLastError());
        return false;
    }
    CloseHandle(pi.hThread);
    helper_process = pi.hProcess;

    // The helper signals that it has attached by publishing a non-zero head. Attaching is the
    // only thing that must be complete before guest code runs: until then, faults would still
    // be delivered on the guest's own stack.
    for (u32 i = 0; i < 200; ++i) {
        if (channel->dropped.load(std::memory_order_acquire) == 1) {
            channel->dropped.store(0, std::memory_order_release);
            active.store(true, std::memory_order_release);
            LOG_INFO(Core, "Fault helper attached; guest faults will not touch the red zone");
            return true;
        }
        Sleep(10);
    }
    LOG_ERROR(Core, "Fault helper: the helper never reported that it attached");
    // The helper may be attached but stuck. Leaving it there would freeze the emulator for
    // good, so take it down and carry on with the in-process handler.
    TerminateProcess(helper_process, 1);
    CloseHandle(helper_process);
    helper_process = nullptr;
    return false;
}

void Drain() {
    if (!active.load(std::memory_order_relaxed) || channel == nullptr) {
        return;
    }
    const auto* signals = Signals::Instance();
    u32 tail = channel->tail.load(std::memory_order_relaxed);
    const u32 head = channel->head.load(std::memory_order_acquire);
    while (tail != head) {
        const Channel::Entry entry = channel->entries[tail % Channel::Capacity];
        tail++;

        // Rebuild just enough of an exception for the registered handlers: they only ask
        // whether the access was a write, and for the address.
        EXCEPTION_RECORD record{};
        record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
        record.NumberParameters = 2;
        record.ExceptionInformation[0] = entry.is_write;
        record.ExceptionInformation[1] = static_cast<ULONG_PTR>(entry.address);
        CONTEXT context{};
        EXCEPTION_POINTERS pointers{&record, &context};
        signals->DispatchAccessViolation(&pointers, reinterpret_cast<void*>(entry.address));
    }
    channel->tail.store(tail, std::memory_order_release);
}

// ---------------------------------------------------------------------------
// Helper side
// ---------------------------------------------------------------------------

namespace {

/// Makes the faulting page writable in the debuggee so it can make progress. This is the only
/// part of fault handling that cannot wait: everything else is bookkeeping the emulator does
/// on its own threads once it is running again.
bool Unprotect(HANDLE process, u64 address) {
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) == 0) {
        return false;
    }
    if (info.State != MEM_COMMIT) {
        return false;
    }
    DWORD wanted = PAGE_READWRITE;
    if (info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        wanted = PAGE_EXECUTE_READWRITE;
    }
    DWORD previous = 0;
    return VirtualProtectEx(process, info.BaseAddress, info.RegionSize, wanted, &previous) != 0;
}

void Publish(u64 address, u32 is_write) {
    const u32 head = channel->head.load(std::memory_order_relaxed);
    const u32 tail = channel->tail.load(std::memory_order_acquire);
    if (head - tail >= Channel::Capacity) {
        channel->dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    channel->entries[head % Channel::Capacity] = {address, is_write, 0};
    channel->head.store(head + 1, std::memory_order_release);
}

} // namespace

int Run(u32 parent_pid) {
    const std::wstring name = ChannelName(parent_pid);
    HANDLE map = nullptr;
    for (u32 i = 0; i < 200 && map == nullptr; ++i) {
        map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name.c_str());
        if (map == nullptr) {
            Sleep(10);
        }
    }
    if (map == nullptr) {
        return 1;
    }
    channel = static_cast<Channel*>(MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Channel)));
    if (channel == nullptr) {
        return 1;
    }

    if (!DebugActiveProcess(parent_pid)) {
        Trace("helper: DebugActiveProcess failed");
        return 1;
    }
    // Never take the emulator down with us, whatever happens here.
    DebugSetProcessKillOnExit(FALSE);

    HANDLE parent = OpenProcess(PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
                                FALSE, parent_pid);
    if (parent == nullptr) {
        DebugActiveProcessStop(parent_pid);
        return 1;
    }

    // Tell the emulator we are in place.
    Trace("helper: attached, entering the debug event loop");
    channel->dropped.store(1, std::memory_order_release);

    DEBUG_EVENT event{};
    while (WaitForDebugEvent(&event, INFINITE)) {
        DWORD status = DBG_EXCEPTION_NOT_HANDLED;
        switch (event.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
            const auto& record = event.u.Exception.ExceptionRecord;
            const bool first_chance = event.u.Exception.dwFirstChance != 0;
            // Attaching makes the kernel raise a breakpoint in the debuggee on a thread it
            // injects for the purpose. Nothing in the emulator expects it, so it has to be
            // swallowed here; handing it back would take the process down.
            if (record.ExceptionCode == EXCEPTION_BREAKPOINT ||
                record.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                status = DBG_CONTINUE;
                break;
            }
            if (record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && first_chance &&
                record.NumberParameters >= 2) {
                const u64 address = static_cast<u64>(record.ExceptionInformation[1]);
                const u32 is_write = static_cast<u32>(record.ExceptionInformation[0]);
                if (address >= GuestSpaceMin && Unprotect(parent, address)) {
                    Publish(address, is_write);
                    status = DBG_CONTINUE;
                }
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            if (event.dwProcessId == parent_pid) {
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                CloseHandle(parent);
                return 0;
            }
            status = DBG_CONTINUE;
            break;
        default:
            status = DBG_CONTINUE;
            break;
        }
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status);
    }

    CloseHandle(parent);
    return 0;
}

} // namespace Core::FaultHelper

#endif
