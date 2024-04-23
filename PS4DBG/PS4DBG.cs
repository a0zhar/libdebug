using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace libdebug {
    public partial class PS4DBG {
        // from debug.h
        //struct debug_breakpoint {
        //    uint32_t valid;
        //    uint64_t address;
        //    uint8_t original;
        //};
        public static uint MAX_BREAKPOINTS = 10;

        public static uint MAX_WATCHPOINTS = 4;
        private const uint BROADCAST_MAGIC = 0xFFFFAAAA;
        private const int BROADCAST_PORT = 1010;
        // from protocol.h
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
        private const string LIBRARY_VERSION = "1.2";
        private const int NET_MAX_LENGTH = 8192;
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
            IPAddress addr = null;
            try { addr = IPAddress.Parse(ip); }
            catch (FormatException ex) {
                throw ex;
            }

            enp = new IPEndPoint(addr, PS4DBG_PORT);
            sock = new Socket(enp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        }


        public bool IsConnected { 
            get; private set; 
        } = false;

        public bool IsDebugging { 
            get; private set; 
        } = false;
        
        // General helper functions, make code cleaner
        public static string ConvertASCII(byte[] data, int offset) {
            int length = Array.IndexOf<byte>(data, 0, offset) - offset;
            if (length < 0) {
                length = data.Length - offset;
            }

            return Encoding.ASCII.GetString(data, offset, length);
        }

        /// <summary>
        /// Find the playstation ip
        /// </summary>
        public static string FindPlayStation() {
            UdpClient uc = new UdpClient();
            IPEndPoint server = new IPEndPoint(IPAddress.Any, 0);
            uc.EnableBroadcast = true;
            uc.Client.ReceiveTimeout = 4000;

            byte[] magic = BitConverter.GetBytes(BROADCAST_MAGIC);

            IPAddress addr = null;
            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (IPAddress ip in host.AddressList) {
                if (ip.AddressFamily == AddressFamily.InterNetwork) {
                    addr = ip;
                }
            }

            if (addr == null) {
                throw new Exception("libdbg broadcast error: could not get host ip");
            }

            uc.Send(magic, magic.Length, new IPEndPoint(GetBroadcastAddress(addr, IPAddress.Parse("255.255.255.0")), BROADCAST_PORT));

            byte[] resp = uc.Receive(ref server);
            if (BitConverter.ToUInt32(resp, 0) != BROADCAST_MAGIC) {
                throw new Exception("libdbg broadcast error: wrong magic on udp server");
            }

            return server.Address.ToString();
        }

        public static byte[] GetBytesFromObject(object obj) {
            int size = Marshal.SizeOf(obj);

            byte[] bytes = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);

            Marshal.StructureToPtr(obj, ptr, false);
            Marshal.Copy(ptr, bytes, 0, size);

            Marshal.FreeHGlobal(ptr);

            return bytes;
        }

        public static object GetObjectFromBytes(byte[] buffer, Type type) {
            int size = Marshal.SizeOf(type);

            IntPtr ptr = Marshal.AllocHGlobal(size);

            Marshal.Copy(buffer, 0, ptr, size);
            object r = Marshal.PtrToStructure(ptr, type);

            Marshal.FreeHGlobal(ptr);

            return r;
        }

        public static byte[] SubArray(byte[] data, int offset, int length) {
            byte[] bytes = new byte[length];
            Buffer.BlockCopy(data, offset, bytes, 0, length);
            return bytes;
        }

        /// <summary>
        /// Connects to PlayStation 4
        /// </summary>
        public void Connect() {
            // Before trying to open the connection between our PC and the
            // PS4 System, we first check if it's already been opened.
            if (IsConnected) {
                DebugPrintWarning("Oops, the connection is already open!");
                return;
            }

            sock.NoDelay = true;
            sock.ReceiveBufferSize = NET_MAX_LENGTH;
            sock.SendBufferSize = NET_MAX_LENGTH;
            sock.ReceiveTimeout = 1000 * 10;

            sock.Connect(enp);
            IsConnected = true;
        }

        /// <summary>
        /// Disconnects from PlayStation 4
        /// </summary>
        public void Disconnect() {
            // Before trying to close the connection we first check if
            // the connection is currently open
            if (!IsConnected) {
                DebugPrintWarning("Oops, the PS4 connection is not active!");
                return;
            }

            SendCMDPacket(CMDS.CMD_CONSOLE_END, 0);
            sock.Shutdown(SocketShutdown.Both);
            sock.Close();
            IsConnected = false;
        }

        /// <summary>
        /// Get the current ps4debug version from console
        /// </summary>
        public string GetConsoleDebugVersion() {
            CheckConnected();
            SendCMDPacket(CMDS.CMD_VERSION, 0);


            byte[] ldata = new byte[4];
            sock.Receive(ldata, 4, SocketFlags.None);

            int length = BitConverter.ToInt32(ldata, 0);

            byte[] data = new byte[length];
            sock.Receive(data, length, SocketFlags.None);

            return ConvertASCII(data, 0);
        }

        /// <summary>
        /// Get current ps4debug version from library
        /// </summary>
        public string GetLibraryDebugVersion() => LIBRARY_VERSION;



        // General networking functions
        private static IPAddress GetBroadcastAddress(IPAddress address, IPAddress subnetMask) {
            byte[] ipAdressBytes   = address.GetAddressBytes();
            byte[] subnetMaskBytes = subnetMask.GetAddressBytes();

            byte[] broadcastAddress = new byte[ipAdressBytes.Length];
            for (int i = 0; i < broadcastAddress.Length; i++) {
                broadcastAddress[i] = (byte)(ipAdressBytes[i] | (subnetMaskBytes[i] ^ 255));
            }

            return new IPAddress(broadcastAddress);
        }


        private void CheckConnected() {
            if (!IsConnected) {
                throw new Exception("libdbg: not connected");
            }
        }

        private void CheckDebugging() {
            if (!IsDebugging) {
                throw new Exception("libdbg: not debugging");
            }
        }

        private void CheckStatus() {
            CMD_STATUS status = ReceiveStatus();
            if (status != CMD_STATUS.CMD_SUCCESS) {
                throw new Exception(
                    $"libdebug: Exception in CheckStatus()!\n"+
                    $"Status ({(uint)status:X})"
                );
            }
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

        private byte[] ReceiveData(int length) {
            MemoryStream s = new MemoryStream();

            int left = length;
            int recv = 0;
            while (left > 0) {
                byte[] b = new byte[NET_MAX_LENGTH];
                recv = sock.Receive(b, NET_MAX_LENGTH, SocketFlags.None);
                s.Write(b, 0, recv);
                left -= recv;
            }

            byte[] data = s.ToArray();

            s.Dispose();
            GC.Collect();

            return data;
        }

        private CMD_STATUS ReceiveStatus() {
            byte[] status = new byte[4];
            sock.Receive(status, 4, SocketFlags.None);
            return (CMD_STATUS)BitConverter.ToUInt32(status, 0);
        }

        /// <summary>
        /// Function used to build a new CMD Packet before sending it to the PS4 System.
        /// </summary>
        private void SendCMDPacket(CMDS cmd, int length, params object[] fields) {
            // Create a new Command (CMD) Packet object and initialize its members
            CMDPacket packet = new CMDPacket();
            packet.magic = CMD_PACKET_MAGIC; // Set the magic number for the packet
            packet.cmd = (uint)cmd;          // Set the command identifier
            packet.datalen = (uint)length;   // Set the data length of the packet

            // Create a byte array to hold the packet data
            byte[] data = null;

            // Check if the length of the data is greater than 0
            if (length > 0) {
                // Create a new memory stream to hold ?
                MemoryStream rs = new MemoryStream();

                // Iterate through each field object in the fields parameter
                foreach (object field in fields) {
                    // Create a new byte array to hold converted filed? or
                    // the bytes representing the field?
                    byte[] bytes = null;

                    // Check the type of the field variable and obtain an array of bytes from it
                    switch (field) {
                        case char c: bytes = BitConverter.GetBytes(c); break;
                        case byte b: bytes = new byte[] { b }; break;
                        case short s: bytes = BitConverter.GetBytes(s); break;
                        case ushort us: bytes = BitConverter.GetBytes(us); break;
                        case int i: bytes = BitConverter.GetBytes(i); break;
                        case uint u: bytes = BitConverter.GetBytes(u); break;
                        case long l: bytes = BitConverter.GetBytes(l); break;
                        case ulong ul: bytes = BitConverter.GetBytes(ul); break;
                        case byte[] ba: bytes = ba; break;
                        // If the field type is anything else other than the above cases, handle it by printing out the warning
                        default:
                            DebugPrintWarning($"field variable is of non-supported type ({field.GetType()})");
                            // Should we return early?
                            break;
                    };

                    // Write the bytes representing the field to the memory stream
                    if (bytes != null) rs.Write(bytes, 0, bytes.Length);
                }

                // Convert the memory stream to a byte array
                data = rs.ToArray();

                // Perform cleanup for the memory stream
                rs.Dispose();
            }

            // Send the Command (CMD) Packet header? to the PS4 System
            SendData(GetBytesFromObject(packet), CMD_PACKET_SIZE);

            // Check if the data byte array is not null, and in case of it not being
            // null, use it and send it's content to the PS4
            if (data != null) SendData(data, length);
        }
        private void DebuggerThread(object obj) {
            PS4DBG.DebuggerInterruptCallback debuggerInterruptCallback = (PS4DBG.DebuggerInterruptCallback)obj;
            IPAddress ipaddress = IPAddress.Parse("0.0.0.0");
            IPEndPoint ipendPoint = new IPEndPoint(ipaddress, 755);
            Socket socket = new Socket(ipaddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(ipendPoint);
            socket.Listen(0);
            this.IsDebugging = true;
            Socket socket2 = socket.Accept();
            socket2.NoDelay = true;
            socket2.Blocking = false;
            while (this.IsDebugging) {
                if (socket2.Available == 1184) {
                    byte[] array = new byte[1184];
                    if (socket2.Receive(array, 1184, SocketFlags.None) == 1184) {
                        DebuggerInterruptPacket debuggerInterruptPacket;
                        debuggerInterruptPacket = (DebuggerInterruptPacket)GetObjectFromBytes(
                            array, typeof(DebuggerInterruptPacket)
                        );
                        
                        debuggerInterruptCallback(
                            debuggerInterruptPacket.lwpid,
                            debuggerInterruptPacket.status,
                            debuggerInterruptPacket.tdname,
                            debuggerInterruptPacket.reg64,
                            debuggerInterruptPacket.savefpu,
                            debuggerInterruptPacket.dbreg64
                        );
                    }
                }
                Thread.Sleep(100);
            }
            socket.Close();
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CMDPacket {
            public uint magic;
            public uint cmd;
            public uint datalen;
        }
    }
}