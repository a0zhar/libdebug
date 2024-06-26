using System.Linq;
using System.Runtime.InteropServices;

namespace libdebug {

    /// <summary>
    /// Structure to contain information about a process
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct ProcessInfo {

        /// <summary>
        /// The Process ID (PID)
        /// </summary>
        public int pid;

        /// <summary>
        /// The Process Name
        /// </summary>
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 40)]
        public string name;

        /// <summary>
        /// The Path of the Process Executable?
        /// </summary>
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string path;

        /// <summary>
        /// The Process Title ID?
        /// </summary>
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string titleid;

        /// <summary>
        /// The Process Content ID?
        /// </summary>
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string contentid;
    }

    /// <summary>
    /// Structure to hold information about a thread related to a Process?
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct ThreadInfo {

        /// <summary>
        /// The Process ID (PID) of the Process where this thread is running in
        /// </summary>
        public int pid;

        /// <summary>
        /// Priority of the thread
        /// </summary>
        public int priority;

        /// <summary>
        /// Name of the thread
        /// </summary>
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string name;
    }

    /// <summary>
    /// Represents a memory entry within a Process?
    /// </summary>
    public class MemoryEntry {
        /// <summary>
        /// Start address of the memory region
        /// </summary>
        public ulong start;

        /// <summary>
        /// End address of the memory region
        /// </summary>
        public ulong end;

        /// <summary>
        /// Offset of the memory region
        /// </summary>
        public ulong offset;

        /// <summary>
        /// Protection attributes of the memory region
        /// </summary>
        public uint prot;

        /// <summary>
        /// Name of the memory region
        /// </summary>
        public string name;
    }

    public class Process {
        public string name;
        public int pid;

        /// <summary>
        /// Initializes Process class
        /// </summary>
        /// <param name="name">Process name</param>
        /// <param name="pid">Process ID</param>
        /// <returns></returns>
        public Process(string name, int pid) {
            this.name = name;
            this.pid = pid;
        }

        public override string ToString() {
            return $"[{pid}] {name}";
        }
    }

    public class ProcessList {

        /// <summary>
        /// An array of [Process-Class] based Processes
        /// </summary>
        public Process[] processes;

        /// <summary>
        /// Constructor that initializes a new ProcessList class instance
        /// </summary>
        /// <param name="number">Number of processes</param>
        /// <param name="names">Process names</param>
        /// <param name="pids">Process IDs</param>
        public ProcessList(int number, string[] names, int[] pids) {
            // Create and assign <processes> with a new <Process> array the size of
            // <number> number of elements
            processes = new Process[number];

            // Iterate through the <processes> array assigning each of it's entries
            // with a new <Process> instance, whose name is specified by <names[i]>
            // and whose PID is specified by <pids[i]>.
            for (int i = 0; i < number; i++) {
                processes[i] = new Process(
                    names[i], pids[i]
                );
            }
        }

        /// <summary>
        /// Finds a process based off name
        /// </summary>
        /// <param name="name">Process name</param>
        /// <param name="contains">Condition to check if process name contains name</param>
        /// <returns></returns>
        public Process FindProcess(string name, bool contains = false) {
            foreach (Process p in processes) {
                if (contains) {
                    if (p.name.Contains(name))
                        return p;
                }
                else {
                    if (p.name == name)
                        return p;
                }
            }

            return null;
        }
    }

    public class ProcessMap {
        public MemoryEntry[] entries;
        public int pid;

        /// <summary>
        /// Initializes ProcessMap class with memory entries and process ID
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="entries">Process memory entries</param>
        /// <returns></returns>
        public ProcessMap(int pid, MemoryEntry[] entries) {
            this.pid = pid;
            this.entries = entries;
        }

        /// <summary>
        /// Finds a virtual memory entry based off name
        /// </summary>
        /// <param name="name">Virtual memory entry name</param>
        /// <param name="contains">Condition to check if entry name contains name</param>
        /// <returns></returns>
        public MemoryEntry FindEntry(string name, bool contains = false) {
            foreach (MemoryEntry entry in entries) {
                if (contains) {
                    if (entry.name.Contains(name))
                        return entry;
                }
                else {
                    if (entry.name == name)
                        return entry;
                }
            }

            return null;
        }

        /// <summary>
        /// Finds a virtual memory entry based off size
        /// </summary>
        /// <param name="size">Virtual memory entry size</param>
        /// <returns></returns>
        public MemoryEntry FindEntry(ulong size) {
            foreach (MemoryEntry entry in entries) {
                if ((entry.start - entry.end) == size) {
                    return entry;
                }
            }

            return null;
        }
    }
}