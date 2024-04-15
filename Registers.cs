using System.Runtime.InteropServices;

namespace libdebug {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct regs {
        /// <summary> General purpose register r15 </summary>
        public ulong r_r15;
        /// <summary> General purpose register r14 </summary>
        public ulong r_r14;
        /// <summary> General purpose register r13 </summary>
        public ulong r_r13;
        /// <summary> General purpose register r12 </summary>
        public ulong r_r12;
        /// <summary> General purpose register r11 </summary>
        public ulong r_r11;
        /// <summary> General purpose register r10 </summary>
        public ulong r_r10;
        /// <summary> General purpose register r9 </summary>
        public ulong r_r9;
        /// <summary> General purpose register r8 </summary>
        public ulong r_r8;
        /// <summary> Destination index register </summary>
        public ulong r_rdi;
        /// <summary> Source index register </summary>
        public ulong r_rsi;
        /// <summary> Base pointer register </summary>
        public ulong r_rbp;
        /// <summary> Base index register </summary>
        public ulong r_rbx;
        /// <summary> Data register </summary>
        public ulong r_rdx;
        /// <summary> Counter register </summary>
        public ulong r_rcx;
        /// <summary> Accumulator register </summary>
        public ulong r_rax;
        /// <summary> Trap number </summary>
        public uint r_trapno;
        /// <summary> Segment register FS </summary>
        public ushort r_fs;
        /// <summary> Segment register GS </summary>
        public ushort r_gs;
        /// <summary> Error number </summary>
        public uint r_err;
        /// <summary> Extra segment register </summary>
        public ushort r_es;
        /// <summary> Data segment register </summary>
        public ushort r_ds;
        /// <summary> Instruction pointer register </summary>
        public ulong r_rip;
        /// <summary> Code segment register </summary>
        public ulong r_cs;
        /// <summary> RFLAGS register </summary>
        public ulong r_rflags;
        /// <summary> Stack pointer register </summary>
        public ulong r_rsp;
        /// <summary> Stack segment register </summary>
        public ulong r_ss;
    };


    [StructLayout(LayoutKind.Sequential)]
    public struct envxmm {
        /// <summary> Control word (16bits) </summary>
        public ushort en_cw; 
        /// <summary> Status word (16bits) </summary>
        public ushort en_sw;
        /// <summary> Tag word (8bits) </summary>
        public byte en_tw;
        /// <summary> TODO: Comment this Member </summary>
        public byte en_zero;
        /// <summary> Opcode last executed (11 bits) </summary>
        public ushort en_opcode;
        /// <summary> Floating point instruction pointer </summary>
        public ulong en_rip;
        /// <summary> Floating operand pointer </summary>
        public ulong en_rdp;
        /// <summary> SSE sontorol/status register </summary>
        public uint en_mxcsr;
        /// <summary> Valid bits in mxcsr </summary>
        public uint en_mxcsr_mask;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct acc {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public byte[] fp_bytes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        private byte[] fp_pad;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct xmmacc {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] xmm_bytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ymmacc {

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ymm_bytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct xstate_hdr {
        public ulong xstate_bv;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        private byte[] xstate_rsrv0;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
        private byte[] xstate_rsrv;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct savefpu_xstate {
        public xstate_hdr sx_hd;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public ymmacc[] sx_ymm;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 64)]
    public struct fpregs {
        public envxmm svn_env;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public acc[] sv_fp;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public xmmacc[] sv_xmm;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        private byte[] sv_pad;

        public savefpu_xstate sv_xstate;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct dbregs {
        public ulong dr0;
        public ulong dr1;
        public ulong dr2;
        public ulong dr3;
        public ulong dr4;
        public ulong dr5;
        public ulong dr6;
        public ulong dr7;
        public ulong dr8;
        public ulong dr9;
        public ulong dr10;
        public ulong dr11;
        public ulong dr12;
        public ulong dr13;
        public ulong dr14;
        public ulong dr15;
    }
}
