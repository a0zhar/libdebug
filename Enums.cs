namespace libdebug {

    public class PS4DBG_ENUMS {

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

            CMD_KERN_BASE = 0xBDCC0001,
            CMD_KERN_READ = 0xBDCC0002,
            CMD_KERN_WRITE = 0xBDCC0003,

            CMD_CONSOLE_REBOOT = 0xBDDD0001,
            CMD_CONSOLE_END = 0xBDDD0002,
            CMD_CONSOLE_PRINT = 0xBDDD0003,
            CMD_CONSOLE_NOTIFY = 0xBDDD0004,
            CMD_CONSOLE_INFO = 0xBDDD0005,
        };

        // enums
        public enum VM_PROTECTIONS : uint {
            VM_PROT_NONE = 0x00,
            VM_PROT_READ = 0x01,
            VM_PROT_WRITE = 0x02,
            VM_PROT_EXECUTE = 0x04,
            VM_PROT_DEFAULT = VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_ALL = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
            VM_PROT_NO_CHANGE = 0x08,
            VM_PROT_COPY = 0x10,
            VM_PROT_WANTS_COPY = 0x10
        };

        public enum WATCHPT_BREAKTYPE : uint {
            DBREG_DR7_EXEC = 0x00,	/* break on execute       */
            DBREG_DR7_WRONLY = 0x01,	/* break on write         */
            DBREG_DR7_RDWR = 0x03,	/* break on read or write */
        };

        public enum WATCHPT_LENGTH : uint {
            DBREG_DR7_LEN_1 = 0x00,	/* 1 byte length */
            DBREG_DR7_LEN_2 = 0x01,
            DBREG_DR7_LEN_4 = 0x03,
            DBREG_DR7_LEN_8 = 0x02,
        };
    }
}