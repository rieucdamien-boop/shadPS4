// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <algorithm>
#include <array>
#include <atomic>

#include "common/logging/log.h"
#include "common/types.h"
#include "video_core/renderer_vulkan/vk_common.h"

namespace VideoCore {

// Vulkan says nothing about a copy region that reaches outside the image it targets.
// The driver does the arithmetic and writes wherever it lands, which on this hardware
// ends as a device fault a few bytes past a memory block, with nothing in the report
// naming the copy responsible.
//
// So we check it ourselves in front of every copy we record. Nothing is skipped here:
// the job of this function is to name the offending region and its numbers.
inline bool CopyRegionFits(const char* who, const char* side, const vk::ImageCreateInfo& ci,
                           const vk::ImageSubresourceLayers& sub, const vk::Offset3D& offset,
                           const vk::Extent3D& extent) {
    const bool is_3d = ci.imageType == vk::ImageType::e3D;
    const u32 mip = sub.mipLevel;
    const u32 mip_w = std::max(ci.extent.width >> mip, 1u);
    const u32 mip_h = std::max(ci.extent.height >> mip, 1u);
    const u32 mip_d = std::max(ci.extent.depth >> mip, 1u);

    const char* reason = nullptr;
    if (mip >= ci.mipLevels) {
        reason = "mip level past the end";
    } else if (!is_3d && sub.baseArrayLayer + sub.layerCount > ci.arrayLayers) {
        reason = "layer range past the end";
    } else if (is_3d && (sub.baseArrayLayer != 0 || sub.layerCount != 1)) {
        reason = "several layers asked of a 3D image";
    } else if (static_cast<u32>(offset.x) + extent.width > mip_w) {
        reason = "wider than the mip";
    } else if (static_cast<u32>(offset.y) + extent.height > mip_h) {
        reason = "taller than the mip";
    } else if (is_3d && static_cast<u32>(offset.z) + extent.depth > mip_d) {
        reason = "deeper than the mip";
    }
    if (reason == nullptr) {
        return true;
    }

    static u32 reported = 0;
    if (reported < 64) {
        ++reported;
        LOG_ERROR(Render_Vulkan,
                  "{} {}: region outside the image, {}. image {}x{}x{} type {} levels {} "
                  "layers {} | region mip {} layers {}+{} offset {},{},{} extent {}x{}x{} "
                  "(that mip is {}x{}x{})",
                  who, side, reason, ci.extent.width, ci.extent.height, ci.extent.depth,
                  vk::to_string(ci.imageType), ci.mipLevels, ci.arrayLayers, mip,
                  sub.baseArrayLayer, sub.layerCount, offset.x, offset.y, offset.z,
                  extent.width, extent.height, extent.depth, mip_w, mip_h, mip_d);
    }
    return false;
}


// --- Journal circulaire des televersements -----------------------------------------------
//
// Ecrire une ligne de journal par region coute si cher que le crash disparait : le
// ralentissement referme la fenetre de course. On garde donc les derniers televersements
// en memoire, en nombres bruts, sans formatage ni disque, et on ne les imprime qu au
// moment de la faute.

struct UploadNote {
    u64 seq;
    u64 mem;
    u64 mem_off;
    u64 mem_end;
    u64 buf_off;
    u32 img_w, img_h, img_d, layers, levels;
    u32 mip, base_layer, layer_count;
    s32 off_x, off_y, off_z;
    u32 ext_w, ext_h, ext_d;
    u32 row_len, img_height;
};

inline constexpr size_t NumUploadNotes = 64;
inline std::array<UploadNote, NumUploadNotes> g_upload_notes{};
inline std::atomic<u64> g_upload_seq{0};

inline void NoteUpload(const vk::ImageCreateInfo& ci, const vk::BufferImageCopy& c, u64 mem,
                       u64 mem_off, u64 mem_size) {
    const u64 seq = g_upload_seq.fetch_add(1) + 1;
    UploadNote& n = g_upload_notes[(seq - 1) % NumUploadNotes];
    n.seq = seq;
    n.mem = mem;
    n.mem_off = mem_off;
    n.mem_end = mem_off + mem_size;
    n.buf_off = static_cast<u64>(c.bufferOffset);
    n.img_w = ci.extent.width;
    n.img_h = ci.extent.height;
    n.img_d = ci.extent.depth;
    n.layers = ci.arrayLayers;
    n.levels = ci.mipLevels;
    n.mip = c.imageSubresource.mipLevel;
    n.base_layer = c.imageSubresource.baseArrayLayer;
    n.layer_count = c.imageSubresource.layerCount;
    n.off_x = c.imageOffset.x;
    n.off_y = c.imageOffset.y;
    n.off_z = c.imageOffset.z;
    n.ext_w = c.imageExtent.width;
    n.ext_h = c.imageExtent.height;
    n.ext_d = c.imageExtent.depth;
    n.row_len = c.bufferRowLength;
    n.img_height = c.bufferImageHeight;
}

/// Imprime les derniers televersements enregistres. Appele depuis le rapport de faute.
inline void DumpUploadRing() {
    const u64 total = g_upload_seq.load();
    if (total == 0) {
        LOG_CRITICAL(Render_Vulkan, "    aucun televersement enregistre");
        return;
    }
    const u64 first = total > NumUploadNotes ? total - NumUploadNotes + 1 : 1;
    LOG_CRITICAL(Render_Vulkan, "    derniers televersements ({} au total, le plus recent en bas)",
                 total);
    for (u64 s = first; s <= total; ++s) {
        const UploadNote& n = g_upload_notes[(s - 1) % NumUploadNotes];
        if (n.seq != s) {
            continue;
        }
        LOG_CRITICAL(Render_Vulkan,
                     "      #{} img {}x{}x{} L:{} M:{} | memoire {:#x} [{:#x}, {:#x}) | mip {} "
                     "couches {}+{} offset {},{},{} etendue {}x{}x{} | tampon {:#x} rowlen {} "
                     "imgh {}",
                     n.seq, n.img_w, n.img_h, n.img_d, n.layers, n.levels, n.mem, n.mem_off,
                     n.mem_end, n.mip, n.base_layer, n.layer_count, n.off_x, n.off_y, n.off_z,
                     n.ext_w, n.ext_h, n.ext_d, n.buf_off, n.row_len, n.img_height);
    }
}
} // namespace VideoCore
