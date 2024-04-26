
using System.Runtime.InteropServices;

/// <summary>
/// Structure representing the CPU registers
/// </summary>
[StructLayout(LayoutKindSequential, Pack = 1)]
public struct regs {
    /// <summary>
    /// General purpose register R15
    /// </summary>
    public ulong r_r15;
    /// <summary>
    /// General purpose register R14
    /// </summary>
    public ulong r_r14;
    /// <summary>
    /// General purpose register R13
    /// </summary>
    public ulong r_r13;
    /// <summary>
    /// General purpose register R12
    /// </summary>
    public ulong r_r12;
    /// <summary>
    /// General purpose register R11
    /// </summary>
    public ulong r_r11;
    /// <summary>
    /// General purpose register R10
    /// </summary>
    public ulong r_r10;
    /// <summary>
    /// General purpose register R9
    /// </summary>
    public ulong r_r9;
    /// <summary>
    /// General purpose register R8
    /// </summary>
    public ulong r_r8;
    /// <summary>
    /// Destination index register
    /// </summary>
    public ulong r_rdi;
    /// <summary>
    /// Source index register
    /// </summary>
    public ulong r_rsi;
    /// <summary>
    /// Base pointer register
    /// </summary>
    public ulong r_rbp;
    /// <summary>
    /// Base register
    /// </summary>
    public ulong r_rbx;
    /// <summary>
    /// Data register
    /// </summary>
    public ulong r_rdx;
    /// <summary>
    /// Count register
    /// </summary>
    public ulong r_rcx;
    /// <summary>
    /// Accumulator register
    /// </summary>
    public ulong r_rax;
    /// <summary>
    /// Trap number
    /// </summary>
    public uint r_trapno;
    /// <summary>
    /// Segment selector for FS
    /// </summary>
    public ushort r_fs;
    /// <summary>
    /// Segment selector for GS
    /// </summary>
    public ushort r_gs;
    /// <summary>
    /// Error code
    /// </summary>
    public uint r_err;
    /// <summary>
    /// Segment selector for ES
    /// </summary>
    public ushort r_es;
    /// <summary>
    /// Segment selector for DS
    /// </summary>
    public ushort r_ds;
    /// <summary>
    /// Instruction pointer
    /// </summary>
    public ulong r_rip;
    /// <summary>
    /// Code segment selector
    /// </summary>
    public ulong r_cs;
    /// <summary>
    /// Flags register
    /// </summary>
    public ulong r_rflags;
    /// <summary>
    /// Stack pointer
    /// </summary>
    public ulong r_rsp;
    /// <summary>
    /// Stack segment selector
    /// </summary>
    public ulong r_ss;
}

/// <summary>
/// Structure representing the floating-point environment and state
/// </summary>
[StructLayout(LayoutKindSequential)]
public struct envxmm {
    /// <summary>
    /// Control word
    /// </summary>
    public ushort en_cw;
    /// <summary>
    /// Status word
    /// </summary>
    public ushort en_sw;
    /// <summary>
    /// Tag word
    /// </summary>
    public byte en_tw;
    /// <summary>
    /// Reserved
    /// </summary>
    public byte en_zero;
    /// <summary>
    /// Opcode last executed
    /// </summary>
    public ushort en_opcode;
    /// <summary>
    /// Floating-point instruction pointer
    /// </summary>
    public ulong en_rip;
    /// <summary>
    /// Floating-point operand pointer
    /// </summary>
    public ulong en_rdp;
    /// <summary>
    /// SSE control/status register
    /// </summary>
    public uint en_mxcsr;
    /// <summary>
    /// Valid bits in MXCSR
    /// </summary>
    public uint en_mxcsr_mask;
}

/// <summary>
/// Structure representing the floating-point accumulator
/// </summary>
[StructLayout(LayoutKindSequential)]
public struct acc {
    /// <summary>
    /// Floating-point bytes
    /// </summary>
    [MarshalAs(UnmanagedTypeByValArray, SizeConst = 10)]
    public byte[] fp_bytes;
    private byte[] fp_pad; // Padding
}

/// <summary>
/// Structure representing the XMM floating-point accumulator
/// </summary>
[StructLayout(LayoutKindSequential)]
public struct xmmacc {
    /// <summary>
    /// XMM bytes
    /// </summary>
    [MarshalAs(UnmanagedTypeByValArray, SizeConst = 16)]
    public byte[] xmm_bytes;
}

/// <summary>
/// Structure representing the YMM floating-point accumulator
/// </summary>
[StructLayout(LayoutKindSequential)]
public struct ymmacc {
    /// <summary>
    /// YMM bytes
    /// </summary>
    [MarshalAs(UnmanagedTypeByValArray, SizeConst = 16)]
    public byte[] ymm_bytes;
}

/// <summary>
/// Structure representing the header of extended CPU state
/// </summary>
[StructLayout(LayoutKindSequential)]
public struct xstate_hdr {
    /// <summary>
    /// Extended state bitvector
    /// </summary>
    public ulong xstate_bv;
    [MarshalAs(UnmanagedTypeByValArray, SizeConst = 16)]
    private byte[] xstate_rsrv0; // Reserved
    [MarshalAs(UnmanagedTypeByValArray, SizeConst = 40)]
    private byte[] xstate_rsrv; // Reserved
}

/// <summary>
/// Structure representing the saved FPU extended state
/// </summary>
[StructLayout(LayoutKindSequential)]
public struct savefpu_xstate {
    /// <summary>
    /// XSTATE header
    /// </summary>
    public xstate_hdr sx_hd;
    /// <summary>
    /// YMM floating-point accumulators
    /// </summary>
    [MarshalAs(UnmanagedTypeByValArray, SizeConst = 16)]
    public ymmacc[] sx_ymm;
}

/// <summary>
/// Structure representing the FPU registers
/// </summary>
[StructLayout(LayoutKindSequential, Pack = 64)]
public struct fpregs {
    /// <summary>
    /// Floating-point environment
    /// </summary>
    public envxmm svn_env;
    /// <summary>
    /// Floating-point accumulators
    /// </summary>
    [MarshalAs(UnmanagedTypeByValArray, SizeConst = 8)]
    public acc[] sv_fp;
    /// <summary>
    /// XMM floating-point accumulators
    /// </summary>
    [MarshalAs(UnmanagedTypeByValArray, SizeConst = 16)]
    public xmmacc[] sv_xmm;
    private byte[] sv_pad; // Padding
    /// <summary>
    /// Saved FPU extended state
    /// </summary>
    public savefpu_xstate sv_xstate;
}

/// <summary>
/// Structure representing the debug registers
/// </summary>
[StructLayout(LayoutKindSequential, Pack = 1)]
public struct dbregs {
    /// <summary>
    /// Debug register 0
    /// </summary>
    public ulong dr0;
    /// <summary>
    /// Debug register 1
    /// </summary>
    public ulong dr1;
    /// <summary>
    /// Debug register 2
    /// </summary>
    public ulong dr2;
    /// <summary>
    /// Debug register 3
    /// </summary>
    public ulong dr3;
    /// <summary>
    /// Debug register 4
    /// </summary>
    public ulong dr4;
    /// <summary>
    /// Debug register 5
    /// </summary>
    public ulong dr5;
    /// <summary>
    /// Debug register 6
    /// </summary>
    public ulong dr6;
    /// <summary>
    /// Debug register 7
    /// </summary>
    public ulong dr7;
    /// <summary>
    /// Debug register 8
    /// </summary>
    public ulong dr8;
    /// <summary>
    /// Debug register 9
    /// </summary>
    public ulong dr9;
    /// <summary>
    /// Debug register 10
    /// </summary>
    public ulong dr10;
    /// <summary>
    /// Debug register 11
    /// </summary>
    public ulong dr11;
    /// <summary>
    /// Debug register 12
    /// </summary>
    public ulong dr12;
    /// <summary>
    /// Debug register 13
    /// </summary>
    public ulong dr13;
    /// <summary>
    /// Debug register 14
    /// </summary>
    public ulong dr14;
    /// <summary>
    /// Debug register 15
    /// </summary>
    public ulong dr15;
}
