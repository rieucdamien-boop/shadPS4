// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <algorithm>

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

} // namespace VideoCore
