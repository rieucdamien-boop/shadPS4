// SPDX-FileCopyrightText: Copyright 2024-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <array>
#include <atomic>
#include "common/div_ceil.h"
#include "common/logging/log.h"
#include "core/emulator_settings.h"

#ifdef __unix__
#include "common/adaptive_mutex.h"
#else
#include "common/spin_lock.h"
#endif
#include "common/debug.h"
#include "common/types.h"
#include "video_core/buffer_cache/region_definitions.h"
#include "video_core/page_manager.h"

namespace VideoCore {

#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
using LockType = Common::AdaptiveMutex;
#else
using LockType = Common::SpinLock;
#endif

/// One flag per tracker region, recording that the guest took a write fault there.
///
/// The page-fault handler runs in the middle of a guest instruction and cannot touch the buffer
/// cache, so it drops a flag here and the next upload cycle picks it up. A fault is the one
/// unambiguous signal that the guest wrote a page *after* it was uploaded and re-protected -
/// exactly the memory that must stop being protected.
///
/// Hashed into a fixed table, so distinct regions can collide. A collision only pins another
/// region's dirty pages one cycle earlier than the counters would have; it never pins a page the
/// GPU writes, because ChangeRegionState releases those pins.
class StickyRegions {
    static constexpr size_t TableBits = 16;
    static constexpr size_t TableSize = 1ULL << TableBits;

public:
    /// Called from the guest page-fault handler. Setting one relaxed atomic is all the work
    /// that is permitted here.
    static void MarkFaulted(VAddr addr) {
        faulted[Index(addr)].store(true, std::memory_order_relaxed);
    }

    /// Reads and clears the flag for a region.
    static bool TakeFaulted(VAddr region_addr) {
        auto& slot = faulted[Index(region_addr)];
        return slot.load(std::memory_order_relaxed) &&
               slot.exchange(false, std::memory_order_relaxed);
    }

private:
    static size_t Index(VAddr addr) {
        return (addr >> TRACKER_HIGHER_PAGE_BITS) & (TableSize - 1);
    }

    static inline std::array<std::atomic<bool>, TableSize> faulted{};
};

/**
 * Allows tracking CPU and GPU modification of pages in a contigious 16MB virtual address region.
 * Information is stored in bitsets for spacial locality and fast update of single pages.
 */
class RegionManager {
public:
    explicit RegionManager(PageManager* tracker_, VAddr cpu_addr_)
        : tracker{tracker_}, cpu_addr{cpu_addr_} {
        cpu.Fill();
        gpu.Clear();
        writeable.Fill();
        readable.Fill();
    }
    explicit RegionManager() = default;

    void SetCpuAddress(VAddr new_cpu_addr) {
        cpu_addr = new_cpu_addr;
        // Managers are pooled and reassigned to new addresses, so the pinning history has to
        // start over: it describes how the guest treated the previous range, not this one.
        pinned.Clear();
        seen_once.Clear();
        seen_twice.Clear();
    }

    VAddr GetCpuAddr() const {
        return cpu_addr;
    }

    static constexpr size_t SanitizeAddress(size_t address) {
        return static_cast<size_t>(std::max<s64>(static_cast<s64>(address), 0LL));
    }

    template <Type type>
    RegionBits& GetRegionBits() noexcept {
        if constexpr (type == Type::CPU) {
            return cpu;
        } else if constexpr (type == Type::GPU) {
            return gpu;
        }
    }

    template <Type type>
    const RegionBits& GetRegionBits() const noexcept {
        if constexpr (type == Type::CPU) {
            return cpu;
        } else if constexpr (type == Type::GPU) {
            return gpu;
        }
    }

    /**
     * Change the state of a range of pages
     *
     * @param dirty_addr    Base address to mark or unmark as modified
     * @param size          Size in bytes to mark or unmark as modified
     */
    template <Type type, bool enable>
    void ChangeRegionState(u64 dirty_addr, u64 size) noexcept(type == Type::GPU) {
        RENDERER_TRACE;
        const size_t offset = dirty_addr - cpu_addr;
        const size_t start_page = SanitizeAddress(offset) / TRACKER_BYTES_PER_PAGE;
        const size_t end_page =
            Common::DivCeil(SanitizeAddress(offset + size), TRACKER_BYTES_PER_PAGE);
        if (start_page >= NUM_PAGES_PER_REGION || end_page <= start_page) {
            return;
        }

        RegionBits& bits = GetRegionBits<type>();
        if constexpr (enable) {
            bits.SetRange(start_page, end_page);
        } else {
            bits.UnsetRange(start_page, end_page);
        }
        if constexpr (type == Type::GPU && enable) {
            // The GPU produces the data in this range, so the CPU copy is no longer
            // authoritative. Release any pin held on these pages: keeping them permanently
            // CPU-modified would make every upload overwrite what the GPU just wrote.
            pinned.UnsetRange(start_page, end_page);
        }
        if constexpr (type == Type::CPU) {
            UpdateProtection<!enable, false>();
        } else if (EmulatorSettings.GetReadbacksMode() == GpuReadbacksMode::Precise) {
            UpdateProtection<enable, true>();
        }
    }

    /**
     * Loop over each page in the given range, turn off those bits and notify the tracker if
     * needed. Call the given function on each turned off region.
     *
     * @param query_cpu_range Base CPU address to loop over
     * @param size            Size in bytes of the CPU range to loop over
     * @param func            Function to call for each turned off region
     */
    template <Type type, bool clear>
    void ForEachModifiedRange(VAddr query_cpu_range, s64 size, auto&& func) {
        RENDERER_TRACE;
        const size_t offset = query_cpu_range - cpu_addr;
        const size_t start_page = SanitizeAddress(offset) / TRACKER_BYTES_PER_PAGE;
        const size_t end_page =
            Common::DivCeil(SanitizeAddress(offset + size), TRACKER_BYTES_PER_PAGE);
        if (start_page >= NUM_PAGES_PER_REGION || end_page <= start_page) {
            return;
        }

        RegionBits& bits = GetRegionBits<type>();
        RegionBits mask(bits, start_page, end_page);

        if constexpr (clear) {
            if constexpr (type == Type::CPU) {
                // Clearing the CPU bits re-protects these pages, so the guest's next write to
                // them faults again. For memory the guest rewrites every frame - streaming
                // vertex, instance and constant buffers - that is one fault per page per upload
                // cycle, for the lifetime of the process. Widening the fault granule does
                // nothing against it: the faults repeat in time, not in space.
                //
                // That matters beyond performance. On Windows a guest fault is dispatched on
                // the guest's own stack and destroys up to 128 bytes of its System V red zone
                // (see page_manager.cpp), so every avoidable fault is a chance to corrupt guest
                // state. Faults on hot memory are avoidable.
                //
                // A page that is still being cleared on its third upload cycle is one the guest
                // rewrites continuously. Pin it: leave it writable and permanently
                // CPU-modified. It is then re-uploaded on every use and never faults again.
                // Bandwidth is spent, but the GPU can never observe stale CPU data, so this is
                // the safe direction. Pages the GPU writes are excluded - ChangeRegionState
                // releases their pin - because there the CPU copy is not authoritative.
                const RegionBits cleared(bits, start_page, end_page);
                bits.UnsetRange(start_page, end_page);

                if (StickyRegions::TakeFaulted(cpu_addr)) {
                    // The guest already paid for a fault in this region since the last cycle,
                    // which proves it writes here after uploads. Pin what is dirty now instead
                    // of waiting for the counters to agree.
                    pinned |= cleared;
                } else {
                    pinned |= cleared;
                }
                seen_twice |= cleared & seen_once;
                seen_once |= cleared;

                const RegionBits keep(pinned, start_page, end_page);
                bits |= keep;
                UpdateProtection<true, false>();
            } else {
                bits.UnsetRange(start_page, end_page);
                if (EmulatorSettings.GetReadbacksMode() != GpuReadbacksMode::Disabled) {
                    UpdateProtection<false, true>();
                }
            }
        }

        for (const auto& [start, end] : mask) {
            func(cpu_addr + start * TRACKER_BYTES_PER_PAGE, (end - start) * TRACKER_BYTES_PER_PAGE);
        }
    }

    /**
     * Returns true when a region has been modified
     *
     * @param offset Offset in bytes from the start of the buffer
     * @param size   Size in bytes of the region to query for modifications
     */
    template <Type type>
    [[nodiscard]] bool IsRegionModified(u64 offset, u64 size) noexcept {
        RENDERER_TRACE;
        const size_t start_page = SanitizeAddress(offset) / TRACKER_BYTES_PER_PAGE;
        const size_t end_page =
            Common::DivCeil(SanitizeAddress(offset + size), TRACKER_BYTES_PER_PAGE);
        if (start_page >= NUM_PAGES_PER_REGION || end_page <= start_page) {
            return false;
        }

        const RegionBits& bits = GetRegionBits<type>();
        RegionBits test(bits, start_page, end_page);
        return test.Any();
    }

    LockType lock;

private:
    /**
     * Notify tracker about changes in the CPU tracking state of a word in the buffer
     *
     * @param word_index   Index to the word to notify to the tracker
     * @param current_bits Current state of the word
     * @param new_bits     New state of the word
     *
     * @tparam track True when the tracker should start tracking the new pages
     */
    template <bool track, bool is_read>
    void UpdateProtection() {
        RENDERER_TRACE;
        RegionBits mask = is_read ? (~gpu ^ readable) : (cpu ^ writeable);
        if (mask.None()) {
            return;
        }
        if constexpr (is_read) {
            readable = ~gpu;
        } else {
            writeable = cpu;
        }
        tracker->UpdatePageWatchersForRegion<track, is_read>(cpu_addr, mask);
    }

    PageManager* tracker;
    VAddr cpu_addr = 0;
    /// Pages that must stay writable and CPU-modified: the guest rewrites them continuously,
    /// so protecting them again would only buy another fault.
    RegionBits pinned;
    /// Upload cycles in which each page was found CPU-modified, saturating at two. A page that
    /// reaches a third becomes pinned.
    RegionBits seen_once;
    RegionBits seen_twice;
    RegionBits cpu;
    RegionBits gpu;
    RegionBits writeable;
    RegionBits readable;
};

} // namespace VideoCore
