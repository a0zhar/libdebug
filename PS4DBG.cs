using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace libdebug {

    public partial class PS4DBG {

        // Taken from: ps4debug->debug.h
        // struct debug_breakpoint {
        //    uint32_t valid;
        //    uint64_t address;
        //    uint8_t original;
        // };
        public static uint MAX_BREAKPOINTS = 10;

        public static uint MAX_WATCHPOINTS = 4;
        private const uint BROADCAST_MAGIC = 0xFFFFAAAA;
        private const int BROADCAST_PORT = 1010;

        // Taken from: ps4debug-> protocol.h
        // each packet starts with the magic
        // each C# base type can translate into a packet field
        // some packets, such as write take an additional data whose length will be specified in the cmd packet data field structure specific to that cmd type
        // ushort - 2 bytes | uint - 4 bytes | ulong - 8 bytes
        private const uint CMD_PACKET_MAGIC = 0xFFAABBCC;

        //  struct cmd_packet {
        //    uint32_t magic;
        //    uint32_t cmd;
        //    uint32_t datalen;
        //    // (field not actually part of packet, comes after)
        //    uint8_t* data;
        //  }
        //  __attribute__((packed));
        //  #define CMD_PACKET_SIZE 12
        private const int CMD_PACKET_SIZE = 12;

        // some global values
        private const string LIBRARY_VERSION = "1.3";

        private const int NET_MAX_LENGTH = 0x20000;
        private const int PS4DBG_DEBUG_PORT = 755;
        private const int PS4DBG_PORT = 744;
        private Thread debugThread = null;
        private IPEndPoint enp = null;
        private Socket sock = null;

        /// <summary>
        /// Initializes PS4DBG class
        /// </summary>
        /// <param name="addr">PlayStation 4 address</param>
        public PS4DBG(IPAddress addr) {
            enp = new IPEndPoint(addr, PS4DBG_PORT);
            sock = new Socket(enp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        }

        /// <summary>
        /// Initializes PS4DBG class
        /// </summary>
        /// <param name="ip">PlayStation 4 ip address</param>
        public PS4DBG(string ip) {
            // Try to initialize the <enp> global endpoint variable and
            // the <sock> global socket variable, and in case of an
            // exception occuring throw it
            try {
                enp = new IPEndPoint(IPAddress.Parse(ip), PS4DBG_PORT);
                sock = new Socket(enp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            }
            catch (FormatException ex) {
                throw new FormatException(
                    "Unable to initialize PS4DBG Class!!!\n" +
                    $"Exception: {ex.Message}"
                 );
            }
        }

        public enum CMD_STATUS : uint {
            CMD_SUCCESS = 0x80000000,
            CMD_ERROR = 0xF0000001,
            CMD_TOO_MUCH_DATA = 0xF0000002,
            CMD_DATA_NULL = 0xF0000003,
            CMD_ALREADY_DEBUG = 0xF0000004,
            CMD_INVALID_INDEX = 0xF0000005
        };

        // 128kb
        public enum CMDS : uint {
            CMD_VERSION = 0xBD000001,
            CMD_EXT_FW_VERSION = 0xBD000500,

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
            CMD_DEBUG_EXT_STOPGO = 0xBDBB0500,

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
            VM_PROT_DEFAULT = (VM_PROT_READ | VM_PROT_WRITE),
            VM_PROT_ALL = (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE),
            VM_PROT_NO_CHANGE = 0x08,
            VM_PROT_COPY = 0x10,
            VM_PROT_WANTS_COPY = 0x10
        };

        public enum WATCHPT_BREAKTYPE : uint {
            DBREG_DR7_EXEC = 0x00,   // break on execute
            DBREG_DR7_WRONLY = 0x01, // break on write
            DBREG_DR7_RDWR = 0x03,   // break on read or write
        };

        public enum WATCHPT_LENGTH : uint {
            DBREG_DR7_LEN_1 = 0x00, // 1 byte length
            DBREG_DR7_LEN_2 = 0x01, // 2 byte length
            DBREG_DR7_LEN_4 = 0x03, // 4 byte length
            DBREG_DR7_LEN_8 = 0x02, // 8 byte length
        };

        public int ExtFWVersion {
            get; private set;
        } = 0;

        public bool IsConnected {
            get; private set;
        } = false;

        public bool IsDebugging {
            get; private set;
        } = false;

        public string Version {
            get; private set;
        } = "";

        // General helper functions, make code cleaner
        public static string ConvertASCII(byte[] data, int offset) {
            int length = Array.IndexOf<byte>(data, 0, offset) - offset;
            if (length < 0) {
                length = data.Length - offset;
            }

            return Encoding.ASCII.GetString(data, offset, length);
        }

        /// <summary>
        /// Finds the PlayStation 4 system's IP on the network.
        /// </summary>
        public static string FindPlayStation(int timeout = 100, string subnet_mask = "255.255.255.0") {
            // Create a new IPEndPoint for the server
            IPEndPoint server = new IPEndPoint(IPAddress.Any, 0);

            // Create a new UdpClient
            UdpClient uc = new UdpClient();
            uc.EnableBroadcast = true;           // Enable broadcast for the UdpClient
            uc.Client.ReceiveTimeout = timeout;  // Set the receive timeout for the UdpClient

            // Convert the Broadcast magic to a byte array
            byte[] magic = BitConverter.GetBytes(BROADCAST_MAGIC);

            // Get the local host entry
            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());

            // Iterate through each IP address in the host entry
            foreach (IPAddress ip in host.AddressList) {
                try {
                    // Check if the IP address is of InterNetwork type (IPv4), and if
                    // not, we skip to the next ip address
                    if (ip.AddressFamily != AddressFamily.InterNetwork)
                        continue;

                    // Try to send the broadcast packet to the PlayStation 4 on the network
                    uc.Send(magic, magic.Length, new IPEndPoint(GetBroadcastAddress(ip, IPAddress.Parse(subnet_mask)), BROADCAST_PORT));

                    // Receive the response from the PlayStation 4, then check if the received
                    // magic value matches the expected broadcast magic
                    if (BitConverter.ToUInt32(uc.Receive(ref server), 0) == BROADCAST_MAGIC) {
                        uc.Dispose(); // Cleanup

                        // Return the IP address if matched
                        return server.Address.ToString();
                    }
                }
                // Handle any exceptions and continue
                catch (Exception ex) {
                    Console.WriteLine("Wrong IP Trying Next One");
                    Console.WriteLine($"Exception {ex.Message}, Source {ex.Source}");
                }
            }
            // Cleanup
            uc.Dispose();

            // Return an empty string if the PlayStation IP is not found
            return "";
        }

        /// <summary>
        /// Function to convert an object to a byte array, the parameter [obj] is the object to convert
        /// </summary>
        /// <returns> A byte array representation of the object </returns>
        public static byte[] GetBytesFromObject(object obj) {
            // Calculate the size of the object in bytes
            int size = Marshal.SizeOf(obj);

            // Allocate memory to hold the byte representation of the object
            byte[] bytes = new byte[size];

            // Allocate unmanaged memory to hold the object
            IntPtr ptr = Marshal.AllocHGlobal(size);

            // Convert the object to a pointer and copy its bytes to the allocated memory
            Marshal.StructureToPtr(obj, ptr, false);
            Marshal.Copy(ptr, bytes, 0, size);

            // Free the allocated unmanaged memory
            Marshal.FreeHGlobal(ptr);

            return bytes;
        }

        /// <summary>
        /// Function to convert a byte array to an object of the specified type
        /// </summary>
        /// <param name="buffer">The byte array to convert</param>
        /// <param name="type">The type of the object to create</param>
        /// <returns>An object created from the byte array</returns>
        public static object GetObjectFromBytes(byte[] buffer, Type type) {
            // Calculate the size of the object in bytes based on the type
            int size = Marshal.SizeOf(type);

            // Allocate unmanaged memory to hold the byte array
            IntPtr ptr = Marshal.AllocHGlobal(size);

            // Copy the byte array to the allocated unmanaged memory
            Marshal.Copy(buffer, 0, ptr, size);

            // Convert the unmanaged memory back to an object of the specified type
            object obj = Marshal.PtrToStructure(ptr, type);

            // Free the allocated unmanaged memory
            Marshal.FreeHGlobal(ptr);

            return obj;
        }

        public static byte[] SubArray(byte[] data, int offset, int length) {
            byte[] bytes = new byte[length];
            Buffer.BlockCopy(data, offset, bytes, 0, length);
            return bytes;
        }

        /// <summary>
        /// Function attempts to establish a connection to the PS4 if not already connected
        /// </summary>
        /// <returns>True if successfully connected or if already connected, otherwise false</returns>
        public bool Connect() {
            if (IsConnected) return true;

            // Attempt to connect to the PS4 System, and in case of an exception occuring
            // handle it, and return false
            try {
                // Configure socket settings
                sock.NoDelay = true;
                sock.ReceiveBufferSize = NET_MAX_LENGTH;
                sock.SendBufferSize = NET_MAX_LENGTH;
                sock.ReceiveTimeout = 10000; // 1000*10

                // Connect to the PS4
                sock.Connect(enp);
                IsConnected = true;
                Console.WriteLine("Successfully connected to the PS4!");
            }
            catch (Exception ex) {
                Console.WriteLine($"Failed to connect to PS4: {ex.Message}");
                return false;
            }

            return IsConnected;
        }

        /// <summary>
        /// Function closes the connection to the PS4 if a connection is currently open
        /// </summary>
        /// <returns>True if disconnected successfully or if not connected, otherwise false</returns>
        public bool Disconnect() {
            if (!IsConnected) return true;

            // Attempt to disconnect from the PS4, and in case of an exception occuring
            // we handle it, and return false
            try {
                // Send the command packet responsible for closing the connection to the PS4
                SendCMDPacket(CMDS.CMD_CONSOLE_END, 0);

                // Close the socket
                sock.Shutdown(SocketShutdown.Both);
                sock.Close();
                IsConnected = false;
                Console.WriteLine("Successfully disconnected from the PS4!");
            }
            catch (Exception ex) {
                Console.WriteLine($"Failed to disconnect from PS4: {ex.Message}");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Get the current ps4debug version from console
        /// </summary>
        public string GetConsoleDebugVersion() {
            if (Version != "")
                return Version;

            CheckConnected();

            SendCMDPacket(CMDS.CMD_VERSION, 0);

            byte[] ldata = new byte[4];
            sock.Receive(ldata, 4, SocketFlags.None);

            int length = BitConverter.ToInt32(ldata, 0);

            byte[] data = new byte[length];
            sock.Receive(data, length, SocketFlags.None);

            Version = ConvertASCII(data, 0);
            return Version;
        }

        /// <summary>
        /// Get current ps4debug version from library
        /// </summary>
        public string GetLibraryDebugVersion() => LIBRARY_VERSION;

        // General networking functions
        private static IPAddress GetBroadcastAddress(IPAddress address, IPAddress subnetMask) {
            byte[] ipAdressBytes = address.GetAddressBytes();
            byte[] subnetMaskBytes = subnetMask.GetAddressBytes();

            byte[] broadcastAddress = new byte[ipAdressBytes.Length];
            for (int i = 0; i < broadcastAddress.Length; i++) {
                broadcastAddress[i] = (byte)(ipAdressBytes[i] | (subnetMaskBytes[i] ^ 255));
            }

            return new IPAddress(broadcastAddress);
        }

        private void CheckConnected() {
            if (!IsConnected) {
                throw new Exception("libdebug: not connected");
            }
        }

        private void CheckDebugging() {
            if (!IsDebugging) {
                throw new Exception("libdebug: not debugging");
            }
        }

        private void CheckStatus(string str = "") {
            CMD_STATUS status = ReceiveStatus();
            if (status != CMD_STATUS.CMD_SUCCESS) {
                throw new Exception($"libdebug status: {(uint)status:X} {str}");
            }
        }

        private byte[] ReceiveData(int length) {
            MemoryStream s = new MemoryStream();

            int left = length;
            int recv = 0;
            byte[] b = new byte[NET_MAX_LENGTH];
            while (left > 0) {
                // adhere to length
                recv = sock.Receive(b, Math.Min(left, NET_MAX_LENGTH), SocketFlags.None);
                s.Write(b, 0, recv);
                left -= recv;
            }

            byte[] data = s.ToArray();

            s.Dispose();
            //GC.Collect();

            return data;
        }

        private CMD_STATUS ReceiveStatus() {
            byte[] status = new byte[4];
            sock.Receive(status, 4, SocketFlags.None);
            return (CMD_STATUS)BitConverter.ToUInt32(status, 0);
        }

        private void SendCMDPacket(CMDS cmd, int length, params object[] fields) {
            CMDPacket packet = new CMDPacket();
            packet.magic = CMD_PACKET_MAGIC;
            packet.cmd = (uint)cmd;
            packet.datalen = (uint)length;

            byte[] data = null;

            if (length > 0) {
                // Initialize a MemoryStream to store the packet data
                using (MemoryStream rs = new MemoryStream()) {
                    // Iterate through each field in the provided fields
                    foreach (object field in fields) {
                        byte[] bytes = null;

                        // Determine the type of the field and convert it to bytes accordingly
                        switch (field) {
                            case char c: bytes = new byte[1] { BitConverter.GetBytes(c)[0] }; break;
                            case byte b: bytes = new byte[1] { b }; break;
                            case short s: bytes = BitConverter.GetBytes(s); break;
                            case ushort us: bytes = BitConverter.GetBytes(us); break;
                            case int i: bytes = BitConverter.GetBytes(i); break;
                            case uint u: bytes = BitConverter.GetBytes(u); break;
                            case long l: bytes = BitConverter.GetBytes(l); break;
                            case ulong ul: bytes = BitConverter.GetBytes(ul); break;
                            case byte[] ba: bytes = ba; break;
                        };

                        // Write the bytes to the MemoryStream
                        if (bytes != null)
                            rs.Write(bytes, 0, bytes.Length);
                    }

                    // Convert the MemoryStream to byte array?
                    data = rs.ToArray();
                    rs.Dispose();
                }
            }

            // Send the packet size?
            SendData(GetBytesFromObject(packet), CMD_PACKET_SIZE);

            // Send the packet data if present?
            if (data != null) SendData(data, length);
        }

        private void SendData(byte[] data, int length) {
            int left = length;
            int offset = 0;
            int sent = 0;

            while (left > 0) {
                if (left > NET_MAX_LENGTH) {
                    byte[] bytes = SubArray(data, offset, NET_MAX_LENGTH);
                    sent = sock.Send(bytes, NET_MAX_LENGTH, SocketFlags.None);
                }
                else {
                    byte[] bytes = SubArray(data, offset, left);
                    sent = sock.Send(bytes, left, SocketFlags.None);
                }

                offset += sent;
                left -= sent;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CMDPacket {
            public uint magic;
            public uint cmd;
            public uint datalen;
        }
    }
}
