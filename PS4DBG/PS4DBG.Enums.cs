namespace libdebug {

    public partial class PS4DBG {

        public enum CMD_STATUS : uint {
            CMD_SUCCESS = 0x80000000,
            CMD_ERROR = 0xF0000001,
            CMD_TOO_MUCH_DATA = 0xF0000002,
            CMD_DATA_NULL = 0xF0000003,
            CMD_ALREADY_DEBUG = 0xF0000004,
            CMD_INVALID_INDEX = 0xF0000005
        };

        public enum CMDS : uint {
            CMD_VERSION = 0xBD000001,

            // Process Related Command Values
            CMD_PROC_LIST = 0xBDAA0001,

            CMD_PROC_READ = 0xBDAA0002,
            CMD_PROC_WRITE = 0xBDAA0003,
            CMD_PROC_MAPS = 0xBDAA0004,
            CMD_PROC_INTALL = 0xBDAA0005,
            CMD_PROC_CALL = 0xBDAA0006,
            CMD_PROC_ELF = 0xBDAA0007,
            CMD_PROC_PROTECT = 0xBDAA0008,
            CMD_PROC_SCAN = 0xBDAA0009,
            CMD_PROC_INFO = 0xBDAA000A,
            CMD_PROC_ALLOC = 0xBDAA000B,
            CMD_PROC_FREE = 0xBDAA000C,

            // Debugger Related Command Values
            CMD_DEBUG_ATTACH = 0xBDBB0001,

            CMD_DEBUG_DETACH = 0xBDBB0002,
            CMD_DEBUG_BREAKPT = 0xBDBB0003,
            CMD_DEBUG_WATCHPT = 0xBDBB0004,
            CMD_DEBUG_THREADS = 0xBDBB0005,
            CMD_DEBUG_STOPTHR = 0xBDBB0006,
            CMD_DEBUG_RESUMETHR = 0xBDBB0007,
            CMD_DEBUG_GETREGS = 0xBDBB0008,
            CMD_DEBUG_SETREGS = 0xBDBB0009,
            CMD_DEBUG_GETFPREGS = 0xBDBB000A,
            CMD_DEBUG_SETFPREGS = 0xBDBB000B,
            CMD_DEBUG_GETDBGREGS = 0xBDBB000C,
            CMD_DEBUG_SETDBGREGS = 0xBDBB000D,
            CMD_DEBUG_STOPGO = 0xBDBB0010,
            CMD_DEBUG_THRINFO = 0xBDBB0011,
            CMD_DEBUG_SINGLESTEP = 0xBDBB0012,

            // Kernel? Related Command Values
            CMD_KERN_BASE = 0xBDCC0001,

            CMD_KERN_READ = 0xBDCC0002,
            CMD_KERN_WRITE = 0xBDCC0003,

            // PS4 Console Related Command Values
            CMD_CONSOLE_REBOOT = 0xBDDD0001,

            CMD_CONSOLE_END = 0xBDDD0002,
            CMD_CONSOLE_PRINT = 0xBDDD0003,
            CMD_CONSOLE_NOTIFY = 0xBDDD0004,
            CMD_CONSOLE_INFO = 0xBDDD0005,
        };

        /// <summary>
        /// VM (Virtual Memory) protection flags used for
        /// specifying memory protection attributes
        /// </summary>
        public enum VM_PROTECTIONS : uint {

            /// <summary>
            /// No access allowed
            /// </summary>
            VM_PROT_NONE = 0x00,

            /// <summary>
            /// Read access allowed
            /// </summary>
            VM_PROT_READ = 0x01,

            /// <summary>
            /// Write access allowed
            /// </summary>
            VM_PROT_WRITE = 0x02,

            /// <summary>
            /// Execute access allowed
            /// </summary>
            VM_PROT_EXECUTE = 0x04,

            /// <summary>
            /// Default access permissions for reading and writing
            /// </summary>
            VM_PROT_DEFAULT = VM_PROT_READ | VM_PROT_WRITE,

            /// <summary>
            /// Full access permissions for reading, writing, and executing
            /// </summary>
            VM_PROT_ALL = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,

            /// <summary>
            /// Do not change the current protection
            /// </summary>
            VM_PROT_NO_CHANGE = 0x08,

            /// <summary>
            /// Copy-on-write access allowed
            /// </summary>
            VM_PROT_COPY = 0x10,

            /// <summary>
            /// Copy-on-write access requested
            /// </summary>
            VM_PROT_WANTS_COPY = 0x10
        };

        /// <summary>
        /// WatchPoint (Break On) Flags for the Debugger
        /// </summary>
        public enum WATCHPT_BREAKTYPE : uint {

            /// <summary>
            /// Break on Execute.
            /// </summary>
            DBREG_DR7_EXEC = 0x00,

            /// <summary>
            /// Break on Write.
            /// </summary>
            DBREG_DR7_WRONLY = 0x01,

            /// <summary>
            /// Break on Read/Write.
            /// </summary>
            DBREG_DR7_RDWR = 0x03
        };

        /// <summary>
        /// WatchPoint Length Specifications for the Debugger
        /// </summary>
        public enum WATCHPT_LENGTH : uint {

            /// <summary>
            /// 1 byte length
            /// </summary>
            DBREG_DR7_LEN_1 = 0x00,

            /// <summary>
            /// 2 byte length
            /// </summary>
            DBREG_DR7_LEN_2 = 0x01,

            /// <summary>
            /// 4 byte length
            /// </summary>
            DBREG_DR7_LEN_4 = 0x03,

            /// <summary>
            /// 8 byte length
            /// </summary>
            DBREG_DR7_LEN_8 = 0x02
        };
    }
}