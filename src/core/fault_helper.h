// SPDX-FileCopyrightText: Copyright 2024-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "common/types.h"

namespace Core {

/// Out-of-thread guest fault handling for Windows.
///
/// A vectored exception handler runs on the faulting thread's own stack, and the kernel writes
/// its CONTEXT and EXCEPTION_RECORD immediately below RSP before any user code runs. The guest
/// is compiled for the System V ABI, which reserves those 128 bytes as the red zone for leaf
/// functions, so every guest fault silently destroys guest state. Nothing in user mode can
/// prevent or undo it.
///
/// When a debugger is attached, the kernel does not dispatch first-chance exceptions in user
/// mode at all: it suspends the debuggee and notifies the debugger. The guest stack is never
/// touched. That is the Windows equivalent of the userfaultfd path used on Linux.
///
/// A process cannot debug itself, so the emulator spawns a copy of itself in helper mode and
/// lets the child attach back. The debuggee is frozen while a debug event is pending, so the
/// helper cannot ask the emulator to run its buffer cache logic there - it would deadlock.
/// Instead the helper does the only part that must happen immediately, making the page writable
/// again, and queues the address. The emulator drains that queue on its own threads.
namespace FaultHelper {

/// Runs the helper loop. Called from main() when started with --fault-helper <pid>; never
/// returns until the debuggee exits.
int Run(u32 parent_pid);

/// Starts the helper for this process. Returns false if anything failed, in which case the
/// caller should keep using the in-process exception handler.
bool Start();

/// Applies every fault the helper has recorded since the last call. Must be called from an
/// emulator thread, at a point where invalidating guest memory is safe - before submitting
/// work to the GPU, in particular, so the cache never serves data the guest has overwritten.
void Drain();

/// Whether the helper is attached and handling guest faults.
bool IsActive();

} // namespace FaultHelper

} // namespace Core
