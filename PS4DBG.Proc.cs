using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace libdebug {

    public partial class PS4DBG {
        private const int CMD_PROC_ALLOC_PACKET_SIZE = 8;
        private const int CMD_PROC_CALL_PACKET_SIZE = 68;
        private const int CMD_PROC_ELF_PACKET_SIZE = 8;
        private const int CMD_PROC_FREE_PACKET_SIZE = 16;
        private const int CMD_PROC_INFO_PACKET_SIZE = 4;
        private const int CMD_PROC_INSTALL_PACKET_SIZE = 4;
        private const int CMD_PROC_MAPS_PACKET_SIZE = 4;
        private const int CMD_PROC_PROTECT_PACKET_SIZE = 20;

        //proc
        // packet sizes
        // send size
        private const int CMD_PROC_READ_PACKET_SIZE = 16;

        private const int CMD_PROC_SCAN_PACKET_SIZE = 10;
        private const int CMD_PROC_WRITE_PACKET_SIZE = 16;
        private const int PROC_ALLOC_SIZE = 8;

        private const int PROC_CALL_SIZE = 12;

        private const int PROC_INSTALL_SIZE = 8;

        // receive size
        private const int PROC_LIST_ENTRY_SIZE = 36;

        private const int PROC_MAP_ENTRY_SIZE = 58;
        private const int PROC_PROC_INFO_SIZE = 188;

        /// <summary>
        /// Allocate RWX memory in the process space
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="length">Size of memory allocation</param>
        /// <returns></returns>
        public ulong AllocateMemory(int pid, int length) {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_PROC_ALLOC, CMD_PROC_ALLOC_PACKET_SIZE, pid, length);
            CheckStatus();
            return BitConverter.ToUInt64(ReceiveData(PROC_ALLOC_SIZE), 0);
        }

        /// <summary>
        /// Call function (returns rax)
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="rpcstub">Stub address from InstallRPC</param>
        /// <param name="address">Address to call</param>
        /// <param name="args">Arguments array</param>
        /// <returns></returns>
        public ulong Call(int pid, ulong rpcstub, ulong address, params object[] args) {
            CheckConnected(); // Check if the connection is active

            // Create a custom format packet
            CMDPacket packet = new CMDPacket {
                magic = CMD_PACKET_MAGIC,
                cmd = (uint)CMDS.CMD_PROC_CALL,
                datalen = (uint)CMD_PROC_CALL_PACKET_SIZE
            };
            SendData(GetBytesFromObject(packet), CMD_PACKET_SIZE); // Send the packet

            MemoryStream rs = new MemoryStream(); // Create a memory stream to store the arguments
            rs.Write(BitConverter.GetBytes(pid), 0, sizeof(int)); // Write PID to the stream
            rs.Write(BitConverter.GetBytes(rpcstub), 0, sizeof(ulong)); // Write RPC stub to the stream
            rs.Write(BitConverter.GetBytes(address), 0, sizeof(ulong)); // Write address to the stream

            int num = 0; // Counter to track the number of arguments processed

            byte[] tmp;      // Temporary byte array for argument conversion
            int size_to_use; // Size of the argument in bytes

            // Loop through each argument
            foreach (object arg in args) {
                byte[] bytes = new byte[8]; // Byte array to store the argument bytes

                // Determine the type of the argument and convert it to bytes
                switch (arg) {
                    case char c:
                        tmp = BitConverter.GetBytes(c);
                        size_to_use = sizeof(char);
                        break;

                    case byte b:
                        tmp = BitConverter.GetBytes(b);
                        size_to_use = sizeof(byte);
                        break;

                    case short s:
                        tmp = BitConverter.GetBytes(s);
                        size_to_use = sizeof(short);
                        break;

                    case ushort us:
                        tmp = BitConverter.GetBytes(us);
                        size_to_use = sizeof(ushort);
                        break;

                    case int i:
                        tmp = BitConverter.GetBytes(i);
                        size_to_use = sizeof(int);
                        break;

                    case uint ui:
                        tmp = BitConverter.GetBytes(ui);
                        size_to_use = sizeof(uint);
                        break;

                    case long l:
                        tmp = BitConverter.GetBytes(l);
                        size_to_use = sizeof(long);
                        break;

                    case ulong ul:
                        tmp = BitConverter.GetBytes(ul);
                        size_to_use = sizeof(ulong);
                        break;

                    default:
                        // Throw an exception for unsupported argument types
                        throw new NotSupportedException(
                            $"Warning!!! The Provided Argument Type ({arg.GetType()}) is Unsupported!!!\n" +
                            "Argument Type is neither one of the following types:\n" +
                            "char, byte, short, ushort, int, uint, long, ulong"
                        );
                };

                // Copy the argument bytes to the byte array
                Buffer.BlockCopy(tmp, 0, bytes, 0, size_to_use);

                // Create padding bytes to fill the remaining space in the ulong
                byte[] pad = new byte[sizeof(ulong) - size_to_use];

                // Copy the padding bytes to the byte array
                Buffer.BlockCopy(pad, 0, bytes, size_to_use, pad.Length);

                // Write the bytes to the memory stream
                rs.Write(bytes, 0, bytes.Length);
                num++; // Increment the argument counter
            }

            // Check the number of arguments
            if (num > 6) throw new Exception("libdebug: too many arguments");

            // If there are less than 6 arguments, pad the remaining slots with zeros
            if (num < 6) {
                for (int i = 0; i < (6 - num); i++) {
                    rs.Write(BitConverter.GetBytes((ulong)0), 0, sizeof(ulong));
                }
            }

            // Send the data
            SendData(rs.ToArray(), CMD_PROC_CALL_PACKET_SIZE);
            rs.Dispose(); // Dispose of the memory stream

            // Check the status
            CheckStatus();

            // Receive and return the result
            byte[] data = ReceiveData(PROC_CALL_SIZE);
            return BitConverter.ToUInt64(data, 4);
        }

        /// <summary>
        /// Changes protection on pages in range
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="address">Address</param>
        /// <param name="length">Length</param>
        /// <param name="newprot">New protection</param>
        /// <returns></returns>
        public void ChangeProtection(int pid, ulong address, uint length, VM_PROTECTIONS newProt) {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_PROC_PROTECT, CMD_PROC_PROTECT_PACKET_SIZE, pid, address, length, (uint)newProt);
            CheckStatus();
        }

        /// <summary>
        /// Free memory in the process space
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="address">Address of the memory allocation</param>
        /// <param name="length">Size of memory allocation</param>
        /// <returns></returns>
        public void FreeMemory(int pid, ulong address, int length) {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_PROC_FREE, CMD_PROC_FREE_PACKET_SIZE, pid, address, length);
            CheckStatus();
        }

        /// <summary>
        /// Get process information
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <returns></returns>
        public ProcessInfo GetProcessInfo(int pid) {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_PROC_INFO, CMD_PROC_INFO_PACKET_SIZE, pid);
            CheckStatus();

            byte[] data = ReceiveData(PROC_PROC_INFO_SIZE);
            return (ProcessInfo)GetObjectFromBytes(data, typeof(ProcessInfo));
        }

        /// <summary>
        /// Get current process list
        /// </summary>
        /// <returns>A ProcessList object containing process names and IDs</returns>
        public ProcessList GetProcessList() {
            CheckConnected();

            // Send command packet to request process list
            SendCMDPacket(CMDS.CMD_PROC_LIST, 0);
            CheckStatus();

            // Receive the count of processes
            byte[] countBytes = new byte[4];
            sock.Receive(countBytes, 4, SocketFlags.None);
            int number = BitConverter.ToInt32(countBytes, 0);

            // Receive data containing process names and IDs
            byte[] processData = ReceiveData(number * PROC_LIST_ENTRY_SIZE);

            // Array for Process Names
            string[] names = new string[number];
            // Array for Process IDs
            int[] pids = new int[number];

            // Begin Parsing process data, adding each one to both
            // the names array and pids array
            for (int i = 0; i < number; i++) {
                int offset = i * PROC_LIST_ENTRY_SIZE;
                // Save the Name of the Current Selected Process
                names[i] = ConvertASCII(processData, offset);

                // Save the Process ID of the Current Selected Process
                pids[i] = BitConverter.ToInt32(processData, offset + 32);
            }

            // Return a new ProcessList object
            return new ProcessList(number, names, pids);
        }

        /// <summary>
        /// Get process memory maps
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <returns></returns>
        public ProcessMap GetProcessMaps(int pid) {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_PROC_MAPS, CMD_PROC_MAPS_PACKET_SIZE, pid);
            CheckStatus();

            // recv count
            byte[] bnumber = new byte[4];
            sock.Receive(bnumber, 4, SocketFlags.None);
            int number = BitConverter.ToInt32(bnumber, 0);

            // recv data
            byte[] data = ReceiveData(number * PROC_MAP_ENTRY_SIZE);

            // parse data
            MemoryEntry[] entries = new MemoryEntry[number];
            for (int i = 0; i < number; i++) {
                int offset = i * PROC_MAP_ENTRY_SIZE;
                entries[i] = new MemoryEntry {
                    name = ConvertASCII(data, offset),
                    start = BitConverter.ToUInt64(data, offset + 32),
                    end = BitConverter.ToUInt64(data, offset + 40),
                    offset = BitConverter.ToUInt64(data, offset + 48),
                    prot = BitConverter.ToUInt16(data, offset + 56)
                };
            }

            return new ProcessMap(pid, entries);
        }

        /// <summary>
        /// Install RPC into a process, this returns a stub address that you should pass into call functions
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <returns></returns>
        public ulong InstallRPC(int pid) {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_PROC_INTALL, CMD_PROC_INSTALL_PACKET_SIZE, pid);
            CheckStatus();

            return BitConverter.ToUInt64(ReceiveData(PROC_INSTALL_SIZE), 0);
        }

        /// <summary>
        /// Load elf
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="elf">Elf</param>
        public void LoadElf(int pid, byte[] elf) {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_PROC_ELF, CMD_PROC_ELF_PACKET_SIZE, pid, (uint)elf.Length);
            CheckStatus();
            SendData(elf, elf.Length);
            CheckStatus();
        }

        /// <summary>
        /// Load elf
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="filename">Elf filename</param>
        public void LoadElf(int pid, string filename) {
            LoadElf(pid, File.ReadAllBytes(filename));
        }

        /// <summary>
        /// Read memory
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="address">Memory address</param>
        /// <param name="length">Data length</param>
        /// <returns></returns>
        public byte[] ReadMemory(int pid, ulong address, int length) {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_PROC_READ, CMD_PROC_READ_PACKET_SIZE, pid, address, length);
            CheckStatus();
            return ReceiveData(length);
        }

        public T ReadMemory<T>(int pid, ulong address) {
            if (typeof(T) == typeof(string)) {
                string str = "";
                ulong i = 0;

                while (true) {
                    byte value = ReadMemory(pid, address + i, sizeof(byte))[0];
                    if (value == 0) {
                        break;
                    }
                    str += Convert.ToChar(value);
                    i++;
                }

                return (T)(object)str;
            }

            if (typeof(T) == typeof(byte[])) {
                throw new NotSupportedException("byte arrays are not supported, use ReadMemory(int pid, ulong address, int size)");
            }

            return (T)GetObjectFromBytes(ReadMemory(pid, address, Marshal.SizeOf(typeof(T))), typeof(T));
        }

        /// <summary>
        /// Scans a process for a given value
        /// </summary>
        /// <typeparam name="T">The type of value to scan for</typeparam>
        /// <param name="pid">The process ID to scan</param>
        /// <param name="compareType">The comparison type</param>
        /// <param name="value">The value to scan for</param>
        /// <param name="extraValue">Optional extra value for comparison</param>
        /// <returns>A list of addresses where the value was found</returns>
        public List<ulong> ScanProcess<T>(int pid, ScanCompareType compareType, T value, T extraValue = default) {
            // Check if the connection from our PC to the PS4 System is established
            CheckConnected();

            // The value variable-size (same as that u would get by doing ex: sizeof(int))
            int typeLength = 0;

            // The value variable-type
            ScanValueType valueType;

            // Define byte array buffer for value and for extra value if needed
            byte[] valueBuffer;
            byte[] extraValueBuffer = null;

            // Determine the type of the value and fill in the corresponding variables
            switch (value) {
                // If the variable <value> is of boolean (true/false) type
                case bool b:
                    valueType = ScanValueType.valTypeUInt8;
                    typeLength = 1;
                    valueBuffer = BitConverter.GetBytes(b);
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((bool)(object)extraValue);
                    break;

                // If the variable <value> is of 8-bit signed integer (sbyte) type
                case sbyte sb:
                    valueType = ScanValueType.valTypeInt8;
                    valueBuffer = BitConverter.GetBytes(sb);
                    typeLength = 1;
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((sbyte)(object)extraValue);
                    break;

                // If the variable <value> is of 8-bit unsigned integer (byte) type
                case byte b:
                    valueType = ScanValueType.valTypeUInt8;
                    valueBuffer = BitConverter.GetBytes(b);
                    typeLength = 1;
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((byte)(object)extraValue);
                    break;

                // If the variable <value> is of 16-bit signed integer (short) type
                case short s:
                    valueType = ScanValueType.valTypeInt16;
                    valueBuffer = BitConverter.GetBytes(s);
                    typeLength = 2;
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((short)(object)extraValue);
                    break;

                // If the variable <value> is of 16-bit unsigned integer (ushort) type
                case ushort us:
                    valueType = ScanValueType.valTypeUInt16;
                    valueBuffer = BitConverter.GetBytes(us);
                    typeLength = 2;
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((ushort)(object)extraValue);
                    break;

                // If the variable <value> is of 32-bit signed integer (int) type
                case int i:
                    valueType = ScanValueType.valTypeInt32;
                    valueBuffer = BitConverter.GetBytes(i);
                    typeLength = 4;
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((int)(object)extraValue);
                    break;

                // If the variable <value> is of 32-bit unsigned integer (uint) type
                case uint ui:
                    valueType = ScanValueType.valTypeUInt32;
                    valueBuffer = BitConverter.GetBytes(ui);
                    typeLength = 4;
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((uint)(object)extraValue);
                    break;

                // If the variable <value> is of 64-bit signed integer (long) type
                case long l:
                    valueType = ScanValueType.valTypeInt64;
                    valueBuffer = BitConverter.GetBytes(l);
                    typeLength = 8;
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((long)(object)extraValue);
                    break;

                // If the variable <value> is of 64-bit unsigned integer (ulong) type
                case ulong ul:
                    valueType = ScanValueType.valTypeUInt64;
                    valueBuffer = BitConverter.GetBytes(ul);
                    typeLength = 8;
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((ulong)(object)extraValue);
                    break;

                // If the variable <value> is of single-precision floating-point (float) type
                case float f:
                    valueType = ScanValueType.valTypeFloat;
                    valueBuffer = BitConverter.GetBytes(f);
                    typeLength = 4;
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((float)(object)extraValue);
                    break;

                // If the variable <value> is of double-precision floating-point (double) type
                case double d:
                    valueType = ScanValueType.valTypeDouble;
                    valueBuffer = BitConverter.GetBytes(d);
                    typeLength = 8;
                    if (extraValue != null)
                        extraValueBuffer = BitConverter.GetBytes((double)(object)extraValue);
                    break;

                // If the variable <value> is of string type
                case string s:
                    valueType = ScanValueType.valTypeString;
                    valueBuffer = Encoding.ASCII.GetBytes(s);
                    typeLength = valueBuffer.Length;
                    break;

                // If the variable <value> is of byte array type
                case byte[] ba:
                    valueType = ScanValueType.valTypeArrBytes;
                    valueBuffer = ba;
                    typeLength = valueBuffer.Length;
                    break;

                // If the variable <value> is neither one of the above, we throw a new exception
                default:
                    throw new NotSupportedException(
                        "The Requested scan value variable type is unsupported! it's neither one of below:\n" +
                        "bool,sbyte,byte,byte[],string,double,float,ulong,long,uint,int,ushort,short...\n\n" +
                        "Feed in Byte[] instead!"
                    );
            };

            // Build a new CMD (Command) Packet, and try to send it to our PS4 System!
            SendCMDPacket(
                CMDS.CMD_PROC_SCAN,
                CMD_PROC_SCAN_PACKET_SIZE,
                pid,
                (byte)valueType,
                (byte)compareType,
                (int)(extraValue == null ? typeLength : typeLength * 2)
            );

            // Check the status of the just-sent packet
            CheckStatus();

            SendData(valueBuffer, typeLength);
            if (extraValueBuffer != null) {
                SendData(extraValueBuffer, typeLength);
            }

            CheckStatus();

            // receive results
            int save = sock.ReceiveTimeout;
            sock.ReceiveTimeout = Int32.MaxValue;
            List<ulong> results = new List<ulong>();
            while (true) {
                ulong result = BitConverter.ToUInt64(ReceiveData(sizeof(ulong)), 0);
                if (result == 0xFFFFFFFFFFFFFFFF)
                    break;

                results.Add(result);
            }

            sock.ReceiveTimeout = save;

            return results;
        }

        /// <summary>
        /// Write memory
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="address">Memory address</param>
        /// <param name="data">Data</param>
        public void WriteMemory(int pid, ulong address, byte[] data) {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_PROC_WRITE, CMD_PROC_WRITE_PACKET_SIZE, pid, address, data.Length);
            CheckStatus();
            SendData(data, data.Length);
            CheckStatus();
        }

        public void WriteMemory<T>(int pid, ulong address, T value) {
            if (typeof(T) == typeof(string)) {
                WriteMemory(pid, address, Encoding.ASCII.GetBytes((string)(object)value + (char)0x0));
                return;
            }

            if (typeof(T) == typeof(byte[])) {
                WriteMemory(pid, address, (byte[])(object)value);
                return;
            }

            WriteMemory(pid, address, GetBytesFromObject(value));
        }
    }
}
