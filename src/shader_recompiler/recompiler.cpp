// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "shader_recompiler/frontend/control_flow_graph.h"
#include "shader_recompiler/frontend/decode.h"
#include "shader_recompiler/frontend/structured_control_flow.h"
#include "shader_recompiler/ir/passes/ir_passes.h"
#include "shader_recompiler/ir/post_order.h"
#include "shader_recompiler/profile.h"
#include "shader_recompiler/recompiler.h"
#include <cstdlib>
#include <cstring>
#include "common/logging/log.h"
#include "shader_recompiler/ir/attribute.h"
#include "shader_recompiler/ir/basic_block.h"
#include "shader_recompiler/ir/opcodes.h"

namespace Shader {

IR::BlockList GenerateBlocks(const IR::AbstractSyntaxList& syntax_list) {
    size_t num_syntax_blocks{};
    for (const auto& [_, type] : syntax_list) {
        if (type == IR::AbstractSyntaxNode::Type::Block) {
            ++num_syntax_blocks;
        }
    }
    IR::BlockList blocks{};
    blocks.reserve(num_syntax_blocks);
    for (const auto& [data, type] : syntax_list) {
        if (type == IR::AbstractSyntaxNode::Type::Block) {
            blocks.push_back(data.block);
        }
    }
    return blocks;
}

IR::Program TranslateProgram(const std::span<const u32>& code, Pools& pools, Info& info,
                             RuntimeInfo& runtime_info, const Profile& profile) {
    // Ensure first instruction is expected.
    constexpr u32 token_mov_vcchi = 0xBEEB03FF;
    if (code[0] != token_mov_vcchi) {
        LOG_WARNING(Render_Recompiler, "First instruction is not s_mov_b32 vcc_hi, #imm");
    }

    Gcn::GcnCodeSlice slice(code.data(), code.data() + code.size());
    Gcn::GcnDecodeContext decoder;

    // Decode and save instructions
    IR::Program program{info};
    program.ins_list.reserve(code.size());
    while (!slice.atEnd()) {
        program.ins_list.emplace_back(decoder.decodeInstruction(slice));
    }

    // Clear any previous pooled data.
    pools.ReleaseContents();

    // Create control flow graph
    Common::ObjectPool<Gcn::Block> gcn_block_pool{64};
    Gcn::CFG cfg{gcn_block_pool, program.ins_list};

    // Structurize control flow graph and create program.
    program.syntax_list =
        Shader::Gcn::BuildASL(pools.inst_pool, pools.block_pool, cfg, info, runtime_info, profile);
    program.blocks = GenerateBlocks(program.syntax_list);
    program.post_order_blocks = Shader::IR::PostOrder(program.syntax_list.front());

    // On NVIDIA GPUs HW interpolation of clip distance values seems broken, and we need to emulate
    // it with expensive discard in PS.
    if (std::getenv("SHADPS4_NO_CLIP_INJECT") == nullptr) { Shader::InjectClipDistanceAttributes(program, runtime_info); }

    // Run optimization passes
    if (!profile.support_float64) {
        Shader::Optimization::LowerFp64ToFp32(program);
    }
    Shader::Optimization::SsaRewritePass(program.post_order_blocks);
    Shader::Optimization::ConstantPropagationPass(program.post_order_blocks);
    Shader::Optimization::IdentityRemovalPass(program.blocks);
    if (info.l_stage == LogicalStage::TessellationControl) {
        Shader::Optimization::TessellationPreprocess(program, runtime_info);
        Shader::Optimization::HullShaderTransform(program, runtime_info);
    } else if (info.l_stage == LogicalStage::TessellationEval) {
        Shader::Optimization::TessellationPreprocess(program, runtime_info);
        Shader::Optimization::DomainShaderTransform(program, runtime_info);
    }
    Shader::Optimization::RingAccessElimination(program, runtime_info);
    Shader::Optimization::ReadLaneEliminationPass(program);
    Shader::Optimization::FlattenExtendedUserdataPass(program);
    Shader::Optimization::ResourceTrackingPass(program, profile);
    Shader::Optimization::LowerBufferFormatToRaw(program);
    Shader::Optimization::SharedMemorySimplifyPass(program, profile);
    Shader::Optimization::SharedMemoryToStoragePass(program, runtime_info, profile);
    Shader::Optimization::SharedMemoryBarrierPass(program, runtime_info, profile);
    Shader::Optimization::IdentityRemovalPass(program.blocks);
    Shader::Optimization::DeadCodeEliminationPass(program);
    Shader::Optimization::ConstantPropagationPass(program.post_order_blocks);
    Shader::Optimization::CollectShaderInfoPass(program, profile);

    Shader::IR::DumpProgram(program, info);
    { static const u64 ph = [] { const char* const e = std::getenv("SHADPS4_PROBE_HASH"); return e != nullptr ? std::strtoull(e, nullptr, 16) : 0ULL; }(); static const bool phalf = [] { const char* const e = std::getenv("SHADPS4_PROBE_HASH"); return e != nullptr && std::strlen(e) <= 8; }(); static const size_t pidx = [] { const char* const e = std::getenv("SHADPS4_PROBE_INDEX"); return e != nullptr ? static_cast<size_t>(std::strtoull(e, nullptr, 10)) : static_cast<size_t>(0); }(); if (ph != 0 && pidx != 0 && (phalf ? (info.pgm_hash >> 32) == ph : info.pgm_hash == ph)) { size_t idx = program.blocks.size(); IR::Inst* found = nullptr; for (IR::Block* const b : program.blocks) { for (IR::Inst& i : *b) { if (idx + 3 > pidx && idx < pidx + 4) { LOG_INFO(Render_Recompiler, "sonde {:#x}: index {} = {}", info.pgm_hash, idx, i.GetOpcode()); } if (idx == pidx) { found = &i; } ++idx; } } if (found != nullptr && IR::TypeOf(found->GetOpcode()) == IR::Type::F32) { for (IR::Block* const b : program.blocks) { for (IR::Inst& i : *b) { if (i.GetOpcode() == IR::Opcode::SetAttribute && IR::IsMrt(i.Arg(0).Attribute())) { i.SetArg(1, IR::Value{found}); } } } LOG_INFO(Render_Recompiler, "sonde active: index {} branche sur la sortie", pidx); } else { LOG_INFO(Render_Recompiler, "sonde inactive: {}", found == nullptr ? "index introuvable" : "la valeur n'est pas de type F32"); } } }
    { static const int pshift = [] { const char* const e = std::getenv("SHADPS4_PARAM_SHIFT"); return e != nullptr ? std::atoi(e) : 0; }(); if (pshift != 0) { u32 n = 0; for (IR::Block* const b : program.blocks) { for (IR::Inst& i : *b) { if (i.GetOpcode() != IR::Opcode::GetAttribute) { continue; } const IR::Attribute a = i.Arg(0).Attribute(); if (!IR::IsParam(a)) { continue; } const int k = static_cast<int>(u32(a) - u32(IR::Attribute::Param0)) + pshift; if (k >= 0 && k < 32) { i.SetArg(0, IR::Value{static_cast<IR::Attribute>(u32(IR::Attribute::Param0) + static_cast<u32>(k))}); ++n; } } } LOG_INFO(Render_Recompiler, "decalage {} applique a {} lectures, shader {:#x}", pshift, n, info.pgm_hash); } }

    return program;
}

} // namespace Shader
