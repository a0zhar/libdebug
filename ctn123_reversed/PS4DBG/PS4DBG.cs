using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace libdebug {

    // Token: 0x02000008 RID: 8
    public class PS4DBG {

        // Token: 0x17000001 RID: 1
        // (get) Token: 0x06000009 RID: 9 RVA: 0x000020A1 File Offset: 0x000002A1
        // (set) Token: 0x0600000A RID: 10 RVA: 0x000020A9 File Offset: 0x000002A9
        public bool IsConnected { get; private set; }

        // Token: 0x17000002 RID: 2
        // (get) Token: 0x0600000B RID: 11 RVA: 0x000020B2 File Offset: 0x000002B2
        // (set) Token: 0x0600000C RID: 12 RVA: 0x000020BA File Offset: 0x000002BA
        public bool IsDebugging { get; private set; }

        // Token: 0x17000003 RID: 3
        // (get) Token: 0x0600000D RID: 13 RVA: 0x000020C3 File Offset: 0x000002C3
        // (set) Token: 0x0600000E RID: 14 RVA: 0x000020CB File Offset: 0x000002CB
        public string Version { get; private set; } = "";

        // Token: 0x17000004 RID: 4
        // (get) Token: 0x0600000F RID: 15 RVA: 0x000020D4 File Offset: 0x000002D4
        // (set) Token: 0x06000010 RID: 16 RVA: 0x000020DC File Offset: 0x000002DC
        public int ExtFWVersion { get; private set; }

        // Token: 0x06000011 RID: 17 RVA: 0x000024A8 File Offset: 0x000006A8
        public static string ConvertASCII(byte[] data, int offset) {
            int num = Array.IndexOf<byte>(data, 0, offset) - offset;
            if (num < 0) {
                num = data.Length - offset;
            }
            return Encoding.ASCII.GetString(data, offset, num);
        }

        // Token: 0x06000012 RID: 18 RVA: 0x000024D8 File Offset: 0x000006D8
        public static byte[] SubArray(byte[] data, int offset, int length) {
            byte[] array = new byte[length];
            Buffer.BlockCopy(data, offset, array, 0, length);
            return array;
        }

        // Token: 0x06000013 RID: 19 RVA: 0x000024F8 File Offset: 0x000006F8
        public static object GetObjectFromBytes(byte[] buffer, Type type) {
            int num = Marshal.SizeOf(type);
            IntPtr intPtr = Marshal.AllocHGlobal(num);
            Marshal.Copy(buffer, 0, intPtr, num);
            object obj = Marshal.PtrToStructure(intPtr, type);
            Marshal.FreeHGlobal(intPtr);
            return obj;
        }

        // Token: 0x06000014 RID: 20 RVA: 0x0000252C File Offset: 0x0000072C
        public static byte[] GetBytesFromObject(object obj) {
            int num = Marshal.SizeOf(obj);
            byte[] array = new byte[num];
            IntPtr intPtr = Marshal.AllocHGlobal(num);
            Marshal.StructureToPtr(obj, intPtr, false);
            Marshal.Copy(intPtr, array, 0, num);
            Marshal.FreeHGlobal(intPtr);
            return array;
        }

        // Token: 0x06000015 RID: 21 RVA: 0x00002568 File Offset: 0x00000768
        private static IPAddress GetBroadcastAddress(IPAddress address, IPAddress subnetMask) {
            byte[] addressBytes = address.GetAddressBytes();
            byte[] addressBytes2 = subnetMask.GetAddressBytes();
            byte[] array = new byte[addressBytes.Length];
            for (int i = 0; i < array.Length; i++) {
                array[i] = (byte)(addressBytes[i] | (addressBytes2[i] ^ byte.MaxValue));
            }
            return new IPAddress(array);
        }

        // Token: 0x06000016 RID: 22 RVA: 0x000025B4 File Offset: 0x000007B4
        private void SendCMDPacket(PS4DBG.CMDS cmd, int length, params object[] fields) {
            PS4DBG.CMDPacket cmdpacket = new PS4DBG.CMDPacket
            {
                magic = 4289379276U,
                cmd = (uint)cmd,
                datalen = (uint)length
            };
            byte[] array = null;
            if (length > 0) {
                MemoryStream memoryStream = new MemoryStream();
                foreach (object obj in fields) {
                    byte[] array2 = null;
                    if (obj is char) {
                        char c = (char)obj;
                        array2 = new byte[] { BitConverter.GetBytes(c)[0] };
                    }
                    else if (obj is byte) {
                        byte b = (byte)obj;
                        array2 = new byte[] { BitConverter.GetBytes((short)b)[0] };
                    }
                    else if (obj is short) {
                        short num = (short)obj;
                        array2 = BitConverter.GetBytes(num);
                    }
                    else if (obj is ushort) {
                        ushort num2 = (ushort)obj;
                        array2 = BitConverter.GetBytes(num2);
                    }
                    else if (obj is int) {
                        int num3 = (int)obj;
                        array2 = BitConverter.GetBytes(num3);
                    }
                    else if (obj is uint) {
                        uint num4 = (uint)obj;
                        array2 = BitConverter.GetBytes(num4);
                    }
                    else if (obj is long) {
                        long num5 = (long)obj;
                        array2 = BitConverter.GetBytes(num5);
                    }
                    else if (obj is ulong) {
                        ulong num6 = (ulong)obj;
                        array2 = BitConverter.GetBytes(num6);
                    }
                    else {
                        byte[] array3 = obj as byte[];
                        if (array3 != null) {
                            array2 = array3;
                        }
                    }
                    if (array2 != null) {
                        memoryStream.Write(array2, 0, array2.Length);
                    }
                }
                array = memoryStream.ToArray();
                memoryStream.Dispose();
            }
            this.SendData(PS4DBG.GetBytesFromObject(cmdpacket), 12);
            if (array != null) {
                this.SendData(array, length);
            }
        }

        // Token: 0x06000017 RID: 23 RVA: 0x00002778 File Offset: 0x00000978
        private void SendData(byte[] data, int length) {
            int i = length;
            int num = 0;
            while (i > 0) {
                int num2;
                if (i > 131072) {
                    byte[] array = PS4DBG.SubArray(data, num, 131072);
                    num2 = this.sock.Send(array, 131072, SocketFlags.None);
                }
                else {
                    byte[] array2 = PS4DBG.SubArray(data, num, i);
                    num2 = this.sock.Send(array2, i, SocketFlags.None);
                }
                num += num2;
                i -= num2;
            }
        }

        // Token: 0x06000018 RID: 24 RVA: 0x000027E0 File Offset: 0x000009E0
        private byte[] ReceiveData(int length) {
            MemoryStream memoryStream = new MemoryStream();
            int i = length;
            byte[] array = new byte[131072];
            while (i > 0) {
                int num = this.sock.Receive(array, Math.Min(i, 131072), SocketFlags.None);
                memoryStream.Write(array, 0, num);
                i -= num;
            }
            byte[] array2 = memoryStream.ToArray();
            memoryStream.Dispose();
            return array2;
        }

        // Token: 0x06000019 RID: 25 RVA: 0x00002840 File Offset: 0x00000A40
        private PS4DBG.CMD_STATUS ReceiveStatus() {
            byte[] array = new byte[4];
            this.sock.Receive(array, 4, SocketFlags.None);
            return (PS4DBG.CMD_STATUS)BitConverter.ToUInt32(array, 0);
        }

        // Token: 0x0600001A RID: 26 RVA: 0x0000286C File Offset: 0x00000A6C
        private void CheckStatus(string str = "") {
            PS4DBG.CMD_STATUS cmd_STATUS = this.ReceiveStatus();
            if (cmd_STATUS != (PS4DBG.CMD_STATUS)2147483648U) {
                string text = "libdbg status ";
                uint num = (uint)cmd_STATUS;
                throw new Exception(text + num.ToString("X") + " " + str);
            }
        }

        // Token: 0x0600001B RID: 27 RVA: 0x000020E5 File Offset: 0x000002E5
        private void CheckConnected() {
            if (!this.IsConnected) {
                throw new Exception("libdbg: not connected");
            }
        }

        // Token: 0x0600001C RID: 28 RVA: 0x000020FA File Offset: 0x000002FA
        private void CheckDebugging() {
            if (!this.IsDebugging) {
                throw new Exception("libdbg: not debugging");
            }
        }

        // Token: 0x0600001D RID: 29 RVA: 0x0000210F File Offset: 0x0000030F
        public PS4DBG(IPAddress addr) {
            this.enp = new IPEndPoint(addr, 744);
            this.sock = new Socket(this.enp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        }

        // Token: 0x0600001E RID: 30 RVA: 0x000028AC File Offset: 0x00000AAC
        public PS4DBG(string ip) {
            IPAddress ipaddress = null;
            try {
                ipaddress = IPAddress.Parse(ip);
            }
            catch (FormatException ex) {
                throw ex;
            }
            this.enp = new IPEndPoint(ipaddress, 744);
            this.sock = new Socket(this.enp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        }

        // Token: 0x0600001F RID: 31 RVA: 0x00002910 File Offset: 0x00000B10
        public static string FindPlayStation() {
            UdpClient udpClient = new UdpClient();
            IPEndPoint ipendPoint = new IPEndPoint(IPAddress.Any, 0);
            udpClient.EnableBroadcast = true;
            udpClient.Client.ReceiveTimeout = 4000;
            byte[] bytes = BitConverter.GetBytes(4294945450U);
            IPAddress ipaddress = null;
            foreach (IPAddress ipaddress2 in Dns.GetHostEntry(Dns.GetHostName()).AddressList) {
                if (ipaddress2.AddressFamily == AddressFamily.InterNetwork) {
                    ipaddress = ipaddress2;
                }
            }
            if (ipaddress == null) {
                throw new Exception("libdbg broadcast error: could not get host ip");
            }
            udpClient.Send(bytes, bytes.Length, new IPEndPoint(PS4DBG.GetBroadcastAddress(ipaddress, IPAddress.Parse("255.255.255.0")), 1010));
            if (BitConverter.ToUInt32(udpClient.Receive(ref ipendPoint), 0) != 4294945450U) {
                throw new Exception("libdbg broadcast error: wrong magic on udp server");
            }
            return ipendPoint.Address.ToString();
        }

        // Token: 0x06000020 RID: 32 RVA: 0x000029EC File Offset: 0x00000BEC
        public bool Connect() {
            if (!this.IsConnected) {
                this.sock.NoDelay = true;
                this.sock.ReceiveBufferSize = 131072;
                this.sock.SendBufferSize = 131072;
                this.sock.NoDelay = true;
                this.sock.ReceiveTimeout = 10000;
                bool flag;
                try {
                    this.sock.Connect(this.enp);
                    this.IsConnected = true;
                    Console.WriteLine("Connected!");
                    goto IL_84;
                }
                catch (Exception ex) {
                    Console.WriteLine(ex.ToString());
                    flag = false;
                }
                return flag;
            }
        IL_84:
            return this.IsConnected;
        }

        // Token: 0x06000021 RID: 33 RVA: 0x00002A94 File Offset: 0x00000C94
        public bool Disconnect() {
            this.SendCMDPacket((PS4DBG.CMDS)3185377282U, 0, new object[0]);
            bool flag;
            try {
                this.sock.Shutdown(SocketShutdown.Both);
                this.sock.Close();
                goto IL_3B;
            }
            catch (Exception ex) {
                Console.WriteLine(ex.ToString());
                flag = false;
            }
            return flag;
        IL_3B:
            this.IsConnected = false;
            return true;
        }

        // Token: 0x06000022 RID: 34 RVA: 0x0000214B File Offset: 0x0000034B
        public string GetLibraryDebugVersion() {
            return "1.3";
        }

        // Token: 0x06000023 RID: 35 RVA: 0x00002AF4 File Offset: 0x00000CF4
        public string GetConsoleDebugVersion() {
            if (this.Version != "") {
                return this.Version;
            }
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3170893825U, 0, new object[0]);
            byte[] array = new byte[4];
            this.sock.Receive(array, 4, SocketFlags.None);
            int num = BitConverter.ToInt32(array, 0);
            byte[] array2 = new byte[num];
            this.sock.Receive(array2, num, SocketFlags.None);
            this.Version = PS4DBG.ConvertASCII(array2, 0);
            return this.Version;
        }

        // Token: 0x06000024 RID: 36 RVA: 0x00002152 File Offset: 0x00000352
        public void Reboot() {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3185377281U, 0, new object[0]);
            this.IsConnected = false;
        }

        // Token: 0x06000025 RID: 37 RVA: 0x00002B7C File Offset: 0x00000D7C
        public void Print(string str) {
            this.CheckConnected();
            string text = str + "\0";
            this.SendCMDPacket((PS4DBG.CMDS)3185377283U, 4, new object[] { text.Length });
            this.SendData(Encoding.ASCII.GetBytes(text), text.Length);
            this.CheckStatus("");
        }

        // Token: 0x06000026 RID: 38 RVA: 0x00002BE0 File Offset: 0x00000DE0
        public void Notify(int messageType, string message) {
            this.CheckConnected();
            string text = message + "\0";
            this.SendCMDPacket((PS4DBG.CMDS)3185377284U, 8, new object[] { messageType, text.Length });
            this.SendData(Encoding.ASCII.GetBytes(text), text.Length);
            this.CheckStatus("");
        }

        // Token: 0x06000027 RID: 39 RVA: 0x00002173 File Offset: 0x00000373
        public void GetConsoleInformation() {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3185377285U, 0, new object[0]);
            this.CheckStatus("");
        }

        // Token: 0x06000028 RID: 40 RVA: 0x00002198 File Offset: 0x00000398
        public ulong KernelBase() {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3184263169U, 0, new object[0]);
            this.CheckStatus("");
            return BitConverter.ToUInt64(this.ReceiveData(8), 0);
        }

        // Token: 0x06000029 RID: 41 RVA: 0x000021CA File Offset: 0x000003CA
        public byte[] KernelReadMemory(ulong address, int length) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3184263170U, 12, new object[] { address, length });
            this.CheckStatus("");
            return this.ReceiveData(length);
        }

        // Token: 0x0600002A RID: 42 RVA: 0x00002C4C File Offset: 0x00000E4C
        public void KernelWriteMemory(ulong address, byte[] data) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3184263171U, 12, new object[] { address, data.Length });
            this.CheckStatus("");
            this.SendData(data, data.Length);
            this.CheckStatus("");
        }

        // Token: 0x0600002B RID: 43 RVA: 0x00002CA8 File Offset: 0x00000EA8
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
                        PS4DBG.DebuggerInterruptPacket debuggerInterruptPacket = (PS4DBG.DebuggerInterruptPacket)PS4DBG.GetObjectFromBytes(array, typeof(PS4DBG.DebuggerInterruptPacket));
                        debuggerInterruptCallback(debuggerInterruptPacket.lwpid, debuggerInterruptPacket.status, debuggerInterruptPacket.tdname, debuggerInterruptPacket.reg64, debuggerInterruptPacket.savefpu, debuggerInterruptPacket.dbreg64);
                    }
                }
                Thread.Sleep(100);
            }
            socket.Close();
        }

        // Token: 0x0600002C RID: 44 RVA: 0x00002D9C File Offset: 0x00000F9C
        public void AttachDebugger(int pid, PS4DBG.DebuggerInterruptCallback callback) {
            this.CheckConnected();
            if (!this.IsDebugging && this.debugThread == null) {
                this.IsDebugging = false;
                this.debugThread = new Thread(new ParameterizedThreadStart(this.DebuggerThread)) {
                    IsBackground = true
                };
                this.debugThread.Start(callback);
                while (!this.IsDebugging) {
                    Thread.Sleep(100);
                }
                this.SendCMDPacket((PS4DBG.CMDS)3183149057U, 4, new object[] { pid });
                this.CheckStatus("");
                return;
            }
            throw new Exception("libdbg: debugger already running?");
        }

        // Token: 0x0600002D RID: 45 RVA: 0x00002E34 File Offset: 0x00001034
        public void DetachDebugger() {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3183149058U, 0, new object[0]);
            this.CheckStatus("");
            if (this.IsDebugging && this.debugThread != null) {
                this.IsDebugging = false;
                this.debugThread.Join();
                this.debugThread = null;
            }
        }

        // Token: 0x0600002E RID: 46 RVA: 0x00002209 File Offset: 0x00000409
        public void ProcessStop() {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149072U, 4, new object[] { 1 });
            this.CheckStatus("");
        }

        // Token: 0x0600002F RID: 47 RVA: 0x0000223D File Offset: 0x0000043D
        public void ProcessKill() {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149072U, 4, new object[] { 2 });
            this.CheckStatus("");
        }

        // Token: 0x06000030 RID: 48 RVA: 0x00002271 File Offset: 0x00000471
        public void ProcessResume() {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149072U, 4, new object[] { 0 });
            this.CheckStatus("");
        }

        // Token: 0x06000031 RID: 49 RVA: 0x00002E90 File Offset: 0x00001090
        public int GetExtFWVersion() {
            if (this.ExtFWVersion != 0) {
                return this.ExtFWVersion;
            }
            int num;
            try {
                this.CheckConnected();
                this.SendCMDPacket((PS4DBG.CMDS)3170893826U, 0, new object[0]);
                int receiveTimeout = this.sock.ReceiveTimeout;
                this.sock.ReceiveTimeout = 4000;
                byte[] array = new byte[2];
                this.sock.Receive(array, 2, SocketFlags.None);
                this.ExtFWVersion = (int)BitConverter.ToUInt16(array, 0);
                string text = "Console Version: ";
                num = this.ExtFWVersion;
                Console.WriteLine(text + num.ToString());
                this.sock.ReceiveTimeout = receiveTimeout;
                num = this.ExtFWVersion;
            }
            catch (Exception) {
                num = 0;
            }
            return num;
        }

        // Token: 0x06000032 RID: 50 RVA: 0x00002F4C File Offset: 0x0000114C
        public void ChangeBreakpoint(int index, bool enabled, ulong address) {
            this.CheckConnected();
            this.CheckDebugging();
            if ((long)index >= (long)((ulong)PS4DBG.MAX_BREAKPOINTS)) {
                throw new Exception("libdbg: breakpoint index out of range");
            }
            this.SendCMDPacket((PS4DBG.CMDS)3183149059U, 16, new object[]
            {
                index,
                Convert.ToInt32(enabled),
                address
            });
            this.CheckStatus("");
        }

        // Token: 0x06000033 RID: 51 RVA: 0x00002FB8 File Offset: 0x000011B8
        public void ChangeWatchpoint(int index, bool enabled, PS4DBG.WATCHPT_LENGTH length, PS4DBG.WATCHPT_BREAKTYPE breaktype, ulong address) {
            this.CheckConnected();
            this.CheckDebugging();
            if ((long)index >= (long)((ulong)PS4DBG.MAX_WATCHPOINTS)) {
                throw new Exception("libdbg: watchpoint index out of range");
            }
            this.SendCMDPacket((PS4DBG.CMDS)3183149060U, 24, new object[]
            {
                index,
                Convert.ToInt32(enabled),
                (uint)length,
                (uint)breaktype,
                address
            });
            this.CheckStatus("");
        }

        // Token: 0x06000034 RID: 52 RVA: 0x00003038 File Offset: 0x00001238
        public uint[] GetThreadList() {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149061U, 0, new object[0]);
            this.CheckStatus("");
            byte[] array = new byte[4];
            this.sock.Receive(array, 4, SocketFlags.None);
            int num = BitConverter.ToInt32(array, 0);
            byte[] array2 = this.ReceiveData(num * 4);
            uint[] array3 = new uint[num];
            for (int i = 0; i < num; i++) {
                array3[i] = BitConverter.ToUInt32(array2, i * 4);
            }
            return array3;
        }

        // Token: 0x06000035 RID: 53 RVA: 0x000030BC File Offset: 0x000012BC
        public ThreadInfo GetThreadInfo(uint lwpid) {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149073U, 4, new object[] { lwpid });
            this.CheckStatus("");
            return (ThreadInfo)PS4DBG.GetObjectFromBytes(this.ReceiveData(40), typeof(ThreadInfo));
        }

        // Token: 0x06000036 RID: 54 RVA: 0x000022A5 File Offset: 0x000004A5
        public void StopThread(uint lwpid) {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149062U, 4, new object[] { lwpid });
            this.CheckStatus("");
        }

        // Token: 0x06000037 RID: 55 RVA: 0x000022D9 File Offset: 0x000004D9
        public void ResumeThread(uint lwpid) {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149063U, 4, new object[] { lwpid });
            this.CheckStatus("");
        }

        // Token: 0x06000038 RID: 56 RVA: 0x00003118 File Offset: 0x00001318
        public regs GetRegisters(uint lwpid) {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149064U, 4, new object[] { lwpid });
            this.CheckStatus("");
            return (regs)PS4DBG.GetObjectFromBytes(this.ReceiveData(176), typeof(regs));
        }

        // Token: 0x06000039 RID: 57 RVA: 0x00003178 File Offset: 0x00001378
        public void SetRegisters(uint lwpid, regs regs) {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149065U, 8, new object[] { lwpid, 176 });
            this.CheckStatus("");
            this.SendData(PS4DBG.GetBytesFromObject(regs), 176);
            this.CheckStatus("");
        }

        // Token: 0x0600003A RID: 58 RVA: 0x000031E8 File Offset: 0x000013E8
        public fpregs GetFloatRegisters(uint lwpid) {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149066U, 4, new object[] { lwpid });
            this.CheckStatus("");
            return (fpregs)PS4DBG.GetObjectFromBytes(this.ReceiveData(832), typeof(fpregs));
        }

        // Token: 0x0600003B RID: 59 RVA: 0x00003248 File Offset: 0x00001448
        public void SetFloatRegisters(uint lwpid, fpregs fpregs) {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149067U, 8, new object[] { lwpid, 832 });
            this.CheckStatus("");
            this.SendData(PS4DBG.GetBytesFromObject(fpregs), 832);
            this.CheckStatus("");
        }

        // Token: 0x0600003C RID: 60 RVA: 0x000032B8 File Offset: 0x000014B8
        public dbregs GetDebugRegisters(uint lwpid) {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149068U, 4, new object[] { lwpid });
            this.CheckStatus("");
            return (dbregs)PS4DBG.GetObjectFromBytes(this.ReceiveData(128), typeof(dbregs));
        }

        // Token: 0x0600003D RID: 61 RVA: 0x00003318 File Offset: 0x00001518
        public void SetDebugRegisters(uint lwpid, dbregs dbregs) {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149069U, 8, new object[] { lwpid, 128 });
            this.CheckStatus("");
            this.SendData(PS4DBG.GetBytesFromObject(dbregs), 128);
            this.CheckStatus("");
        }

        // Token: 0x0600003E RID: 62 RVA: 0x0000230D File Offset: 0x0000050D
        public void SingleStep() {
            this.CheckConnected();
            this.CheckDebugging();
            this.SendCMDPacket((PS4DBG.CMDS)3183149074U, 0, new object[0]);
            this.CheckStatus("");
        }

        // Token: 0x0600003F RID: 63 RVA: 0x00003388 File Offset: 0x00001588
        public ProcessList GetProcessList() {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3182034945U, 0, new object[0]);
            this.CheckStatus("");
            byte[] array = new byte[4];
            this.sock.Receive(array, 4, SocketFlags.None);
            int num = BitConverter.ToInt32(array, 0);
            byte[] array2 = this.ReceiveData(num * 36);
            string[] array3 = new string[num];
            int[] array4 = new int[num];
            for (int i = 0; i < num; i++) {
                int num2 = i * 36;
                array3[i] = PS4DBG.ConvertASCII(array2, num2);
                array4[i] = BitConverter.ToInt32(array2, num2 + 32);
            }
            return new ProcessList(num, array3, array4);
        }

        // Token: 0x06000040 RID: 64 RVA: 0x0000342C File Offset: 0x0000162C
        public byte[] ReadMemory(int pid, ulong address, int length) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3182034946U, 16, new object[] { pid, address, length });
            this.CheckStatus("");
            return this.ReceiveData(length);
        }

        // Token: 0x06000041 RID: 65 RVA: 0x00003480 File Offset: 0x00001680
        public void WriteMemory(int pid, ulong address, byte[] data) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3182034947U, 16, new object[] { pid, address, data.Length });
            this.CheckStatus("");
            this.SendData(data, data.Length);
            this.CheckStatus("");
        }

        // Token: 0x06000042 RID: 66 RVA: 0x000034E4 File Offset: 0x000016E4
        public ProcessMap GetProcessMaps(int pid) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3182034948U, 4, new object[] { pid });
            this.CheckStatus("");
            byte[] array = new byte[4];
            this.sock.Receive(array, 4, SocketFlags.None);
            int num = BitConverter.ToInt32(array, 0);
            byte[] array2 = this.ReceiveData(num * 58);
            MemoryEntry[] array3 = new MemoryEntry[num];
            for (int i = 0; i < num; i++) {
                int num2 = i * 58;
                array3[i] = new MemoryEntry {
                    name = PS4DBG.ConvertASCII(array2, num2),
                    start = BitConverter.ToUInt64(array2, num2 + 32),
                    end = BitConverter.ToUInt64(array2, num2 + 40),
                    offset = BitConverter.ToUInt64(array2, num2 + 48),
                    prot = (uint)BitConverter.ToUInt16(array2, num2 + 56)
                };
            }
            return new ProcessMap(pid, array3);
        }

        // Token: 0x06000043 RID: 67 RVA: 0x00002338 File Offset: 0x00000538
        public ulong InstallRPC(int pid) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3182034949U, 4, new object[] { pid });
            this.CheckStatus("");
            return BitConverter.ToUInt64(this.ReceiveData(8), 0);
        }

        // Token: 0x06000044 RID: 68 RVA: 0x000035C8 File Offset: 0x000017C8
        public ulong Call(int pid, ulong rpcstub, ulong address, params object[] args) {
            this.CheckConnected();
            PS4DBG.CMDPacket cmdpacket = new PS4DBG.CMDPacket
            {
                magic = 4289379276U,
                cmd = 3182034950U,
                datalen = 68U
            };
            this.SendData(PS4DBG.GetBytesFromObject(cmdpacket), 12);
            MemoryStream memoryStream = new MemoryStream();
            memoryStream.Write(BitConverter.GetBytes(pid), 0, 4);
            memoryStream.Write(BitConverter.GetBytes(rpcstub), 0, 8);
            memoryStream.Write(BitConverter.GetBytes(address), 0, 8);
            int num = 0;
            foreach (object obj in args) {
                byte[] array = new byte[8];
                if (obj is char) {
                    char c = (char)obj;
                    Buffer.BlockCopy(BitConverter.GetBytes(c), 0, array, 0, 2);
                    byte[] array2 = new byte[6];
                    Buffer.BlockCopy(array2, 0, array, 2, array2.Length);
                }
                else if (obj is byte) {
                    byte b = (byte)obj;
                    Buffer.BlockCopy(BitConverter.GetBytes((short)b), 0, array, 0, 1);
                    byte[] array3 = new byte[7];
                    Buffer.BlockCopy(array3, 0, array, 1, array3.Length);
                }
                else if (obj is short) {
                    short num2 = (short)obj;
                    Buffer.BlockCopy(BitConverter.GetBytes(num2), 0, array, 0, 2);
                    byte[] array4 = new byte[6];
                    Buffer.BlockCopy(array4, 0, array, 2, array4.Length);
                }
                else if (obj is ushort) {
                    ushort num3 = (ushort)obj;
                    Buffer.BlockCopy(BitConverter.GetBytes(num3), 0, array, 0, 2);
                    byte[] array5 = new byte[6];
                    Buffer.BlockCopy(array5, 0, array, 2, array5.Length);
                }
                else if (obj is int) {
                    int num4 = (int)obj;
                    Buffer.BlockCopy(BitConverter.GetBytes(num4), 0, array, 0, 4);
                    byte[] array6 = new byte[4];
                    Buffer.BlockCopy(array6, 0, array, 4, array6.Length);
                }
                else if (obj is uint) {
                    uint num5 = (uint)obj;
                    Buffer.BlockCopy(BitConverter.GetBytes(num5), 0, array, 0, 4);
                    byte[] array7 = new byte[4];
                    Buffer.BlockCopy(array7, 0, array, 4, array7.Length);
                }
                else if (obj is long) {
                    long num6 = (long)obj;
                    Buffer.BlockCopy(BitConverter.GetBytes(num6), 0, array, 0, 8);
                }
                else if (obj is ulong) {
                    ulong num7 = (ulong)obj;
                    Buffer.BlockCopy(BitConverter.GetBytes(num7), 0, array, 0, 8);
                }
                memoryStream.Write(array, 0, array.Length);
                num++;
            }
            if (num > 6) {
                throw new Exception("libdbg: too many arguments");
            }
            if (num < 6) {
                for (int j = 0; j < 6 - num; j++) {
                    memoryStream.Write(BitConverter.GetBytes(0UL), 0, 8);
                }
            }
            this.SendData(memoryStream.ToArray(), 68);
            memoryStream.Dispose();
            this.CheckStatus("");
            return BitConverter.ToUInt64(this.ReceiveData(12), 4);
        }

        // Token: 0x06000045 RID: 69 RVA: 0x000038B0 File Offset: 0x00001AB0
        public void LoadElf(int pid, byte[] elf) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3182034951U, 8, new object[]
            {
                pid,
                (uint)elf.Length
            });
            this.CheckStatus("");
            this.SendData(elf, elf.Length);
            this.CheckStatus("");
        }

        // Token: 0x06000046 RID: 70 RVA: 0x00002373 File Offset: 0x00000573
        public void LoadElf(int pid, string filename) {
            this.LoadElf(pid, File.ReadAllBytes(filename));
        }

        // Token: 0x06000047 RID: 71 RVA: 0x0000390C File Offset: 0x00001B0C
        public List<ulong> ScanProcess<T>(int pid, PS4DBG.ScanCompareType compareType, T value, T extraValue = default(T)) {
            this.CheckConnected();
            byte[] array = null;
            PS4DBG.ScanValueType scanValueType;
            int num;
            byte[] array2;
            switch (value) {
                case bool flag:
                    scanValueType = PS4DBG.ScanValueType.valTypeUInt8;
                    num = 1;
                    array2 = BitConverter.GetBytes(flag);
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((bool)((object)extraValue));
                    }
                    break;

                case sbyte b:
                    scanValueType = PS4DBG.ScanValueType.valTypeInt8;
                    array2 = BitConverter.GetBytes((short)b);
                    num = 1;
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((short)((sbyte)((object)extraValue)));
                    }
                    break;

                case byte b2:
                    scanValueType = PS4DBG.ScanValueType.valTypeUInt8;
                    array2 = BitConverter.GetBytes((short)b2);
                    num = 1;
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((short)((byte)((object)extraValue)));
                    }
                    break;

                case short num2:
                    scanValueType = PS4DBG.ScanValueType.valTypeInt16;
                    array2 = BitConverter.GetBytes(num2);
                    num = 2;
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((short)((object)extraValue));
                    }
                    break;

                case ushort num3:
                    scanValueType = PS4DBG.ScanValueType.valTypeUInt16;
                    array2 = BitConverter.GetBytes(num3);
                    num = 2;
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((ushort)((object)extraValue));
                    }
                    break;

                case int num4:
                    scanValueType = PS4DBG.ScanValueType.valTypeInt32;
                    array2 = BitConverter.GetBytes(num4);
                    num = 4;
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((int)((object)extraValue));
                    }
                    break;

                case uint num5:
                    scanValueType = PS4DBG.ScanValueType.valTypeUInt32;
                    array2 = BitConverter.GetBytes(num5);
                    num = 4;
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((uint)((object)extraValue));
                    }
                    break;

                case long num6:
                    scanValueType = PS4DBG.ScanValueType.valTypeInt64;
                    array2 = BitConverter.GetBytes(num6);
                    num = 8;
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((long)((object)extraValue));
                    }
                    break;

                case ulong num7:
                    scanValueType = PS4DBG.ScanValueType.valTypeUInt64;
                    array2 = BitConverter.GetBytes(num7);
                    num = 8;
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((ulong)((object)extraValue));
                    }
                    break;

                case float num8:
                    scanValueType = PS4DBG.ScanValueType.valTypeFloat;
                    array2 = BitConverter.GetBytes(num8);
                    num = 4;
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((float)((object)extraValue));
                    }
                    break;

                case double num9:
                    scanValueType = PS4DBG.ScanValueType.valTypeDouble;
                    array2 = BitConverter.GetBytes(num9);
                    num = 8;
                    if (extraValue != null) {
                        array = BitConverter.GetBytes((double)((object)extraValue));
                    }
                    break;

                default:
                    string text = value as string;
                    if (text == null) {
                        byte[] array3 = value as byte[];
                        if (array3 == null) {
                            throw new NotSupportedException("Requested scan value type is not supported! (Feed in Byte[] instead.)");
                        }
                        scanValueType = PS4DBG.ScanValueType.valTypeArrBytes;
                        array2 = array3;
                        num = array2.Length;
                    }
                    else {
                        scanValueType = PS4DBG.ScanValueType.valTypeString;
                        array2 = Encoding.ASCII.GetBytes(text);
                        num = array2.Length;
                    }
                    break;
            };
            this.SendCMDPacket((PS4DBG.CMDS)3182034953U, 10, new object[]
            {
                pid,
                (byte)scanValueType,
                (byte)compareType,
                (extraValue == null) ? num : (num * 2)
            });
            this.CheckStatus("");
            this.SendData(array2, num);
            if (array != null) {
                this.SendData(array, num);
            }
            this.CheckStatus("");
            int receiveTimeout = this.sock.ReceiveTimeout;
            this.sock.ReceiveTimeout = int.MaxValue;

            List<ulong> list = new List<ulong>();
            for (; ; ) {
                ulong num10 = BitConverter.ToUInt64(this.ReceiveData(8), 0);
                if (num10 == 18446744073709551615UL) {
                    break;
                }
                list.Add(num10);
            }
            this.sock.ReceiveTimeout = receiveTimeout;
            return list;
        }

        // Token: 0x06000048 RID: 72 RVA: 0x00003D90 File Offset: 0x00001F90
        public void ChangeProtection(int pid, ulong address, uint length, PS4DBG.VM_PROTECTIONS newProt) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3182034952U, 20, new object[]
            {
                pid,
                address,
                length,
                (uint)newProt
            });
            this.CheckStatus("");
        }

        // Token: 0x06000049 RID: 73 RVA: 0x00003DE8 File Offset: 0x00001FE8
        public ProcessInfo GetProcessInfo(int pid) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3182034954U, 4, new object[] { pid });
            this.CheckStatus("");
            return (ProcessInfo)PS4DBG.GetObjectFromBytes(this.ReceiveData(188), typeof(ProcessInfo));
        }

        // Token: 0x0600004A RID: 74 RVA: 0x00003E40 File Offset: 0x00002040
        public ulong AllocateMemory(int pid, int length) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3182034955U, 8, new object[] { pid, length });
            this.CheckStatus("");
            return BitConverter.ToUInt64(this.ReceiveData(8), 0);
        }

        // Token: 0x0600004B RID: 75 RVA: 0x00003E90 File Offset: 0x00002090
        public void FreeMemory(int pid, ulong address, int length) {
            this.CheckConnected();
            this.SendCMDPacket((PS4DBG.CMDS)3182034956U, 16, new object[] { pid, address, length });
            this.CheckStatus("");
        }

        // Token: 0x0600004C RID: 76 RVA: 0x00003EDC File Offset: 0x000020DC
        public T ReadMemory<T>(int pid, ulong address) {
            if (typeof(T) == typeof(string)) {
                string text = "";
                ulong num = 0UL;
                for (; ; )
                {
                    byte b = this.ReadMemory(pid, address + num, 1)[0];
                    if (b == 0) {
                        break;
                    }
                    text += Convert.ToChar(b).ToString();
                    num += 1UL;
                }
                return (T)((object)text);
            }
            if (typeof(T) == typeof(byte[])) {
                throw new NotSupportedException("byte arrays are not supported, use ReadMemory(int pid, ulong address, int size)");
            }
            return (T)((object)PS4DBG.GetObjectFromBytes(this.ReadMemory(pid, address, Marshal.SizeOf(typeof(T))), typeof(T)));
        }

        // Token: 0x0600004D RID: 77 RVA: 0x00003F98 File Offset: 0x00002198
        public void WriteMemory<T>(int pid, ulong address, T value) {
            if (typeof(T) == typeof(string)) {
                this.WriteMemory(pid, address, Encoding.ASCII.GetBytes((string)((object)value) + "\0"));
                return;
            }
            if (typeof(T) == typeof(byte[])) {
                this.WriteMemory(pid, address, (byte[])((object)value));
                return;
            }
            this.WriteMemory(pid, address, PS4DBG.GetBytesFromObject(value));
        }

        // Token: 0x04000013 RID: 19
        private Socket sock;

        // Token: 0x04000014 RID: 20
        private IPEndPoint enp;

        // Token: 0x04000019 RID: 25
        private Thread debugThread;

        // Token: 0x0400001A RID: 26
        private const string LIBRARY_VERSION = "1.3";

        // Token: 0x0400001B RID: 27
        private const int PS4DBG_PORT = 744;

        // Token: 0x0400001C RID: 28
        private const int PS4DBG_DEBUG_PORT = 755;

        // Token: 0x0400001D RID: 29
        private const int NET_MAX_LENGTH = 131072;

        // Token: 0x0400001E RID: 30
        private const int BROADCAST_PORT = 1010;

        // Token: 0x0400001F RID: 31
        private const uint BROADCAST_MAGIC = 4294945450U;

        // Token: 0x04000020 RID: 32
        private const uint CMD_PACKET_MAGIC = 4289379276U;

        // Token: 0x04000021 RID: 33
        public static uint MAX_BREAKPOINTS = 10U;

        // Token: 0x04000022 RID: 34
        public static uint MAX_WATCHPOINTS = 4U;

        // Token: 0x04000023 RID: 35
        private const int CMD_PACKET_SIZE = 12;

        // Token: 0x04000024 RID: 36
        private const int CMD_CONSOLE_PRINT_PACKET_SIZE = 4;

        // Token: 0x04000025 RID: 37
        private const int CMD_CONSOLE_NOTIFY_PACKET_SIZE = 8;

        // Token: 0x04000026 RID: 38
        private const int CMD_KERN_READ_PACKET_SIZE = 12;

        // Token: 0x04000027 RID: 39
        private const int CMD_KERN_WRITE_PACKET_SIZE = 12;

        // Token: 0x04000028 RID: 40
        private const int KERN_BASE_SIZE = 8;

        // Token: 0x04000029 RID: 41
        private const int CMD_DEBUG_ATTACH_PACKET_SIZE = 4;

        // Token: 0x0400002A RID: 42
        private const int CMD_DEBUG_BREAKPT_PACKET_SIZE = 16;

        // Token: 0x0400002B RID: 43
        private const int CMD_DEBUG_WATCHPT_PACKET_SIZE = 24;

        // Token: 0x0400002C RID: 44
        private const int CMD_DEBUG_STOPTHR_PACKET_SIZE = 4;

        // Token: 0x0400002D RID: 45
        private const int CMD_DEBUG_RESUMETHR_PACKET_SIZE = 4;

        // Token: 0x0400002E RID: 46
        private const int CMD_DEBUG_GETREGS_PACKET_SIZE = 4;

        // Token: 0x0400002F RID: 47
        private const int CMD_DEBUG_SETREGS_PACKET_SIZE = 8;

        // Token: 0x04000030 RID: 48
        private const int CMD_DEBUG_STOPGO_PACKET_SIZE = 4;

        // Token: 0x04000031 RID: 49
        private const int CMD_DEBUG_THRINFO_PACKET_SIZE = 4;

        // Token: 0x04000032 RID: 50
        private const int DEBUG_INTERRUPT_SIZE = 1184;

        // Token: 0x04000033 RID: 51
        private const int DEBUG_THRINFO_SIZE = 40;

        // Token: 0x04000034 RID: 52
        private const int DEBUG_REGS_SIZE = 176;

        // Token: 0x04000035 RID: 53
        private const int DEBUG_FPREGS_SIZE = 832;

        // Token: 0x04000036 RID: 54
        private const int DEBUG_DBGREGS_SIZE = 128;

        // Token: 0x04000037 RID: 55
        private const int CMD_PROC_READ_PACKET_SIZE = 16;

        // Token: 0x04000038 RID: 56
        private const int CMD_PROC_WRITE_PACKET_SIZE = 16;

        // Token: 0x04000039 RID: 57
        private const int CMD_PROC_MAPS_PACKET_SIZE = 4;

        // Token: 0x0400003A RID: 58
        private const int CMD_PROC_INSTALL_PACKET_SIZE = 4;

        // Token: 0x0400003B RID: 59
        private const int CMD_PROC_CALL_PACKET_SIZE = 68;

        // Token: 0x0400003C RID: 60
        private const int CMD_PROC_ELF_PACKET_SIZE = 8;

        // Token: 0x0400003D RID: 61
        private const int CMD_PROC_PROTECT_PACKET_SIZE = 20;

        // Token: 0x0400003E RID: 62
        private const int CMD_PROC_SCAN_PACKET_SIZE = 10;

        // Token: 0x0400003F RID: 63
        private const int CMD_PROC_INFO_PACKET_SIZE = 4;

        // Token: 0x04000040 RID: 64
        private const int CMD_PROC_ALLOC_PACKET_SIZE = 8;

        // Token: 0x04000041 RID: 65
        private const int CMD_PROC_FREE_PACKET_SIZE = 16;

        // Token: 0x04000042 RID: 66
        private const int PROC_LIST_ENTRY_SIZE = 36;

        // Token: 0x04000043 RID: 67
        private const int PROC_MAP_ENTRY_SIZE = 58;

        // Token: 0x04000044 RID: 68
        private const int PROC_INSTALL_SIZE = 8;

        // Token: 0x04000045 RID: 69
        private const int PROC_CALL_SIZE = 12;

        // Token: 0x04000046 RID: 70
        private const int PROC_PROC_INFO_SIZE = 188;

        // Token: 0x04000047 RID: 71
        private const int PROC_ALLOC_SIZE = 8;

        // Token: 0x02000012 RID: 18
        public enum CMDS : uint {

            // Token: 0x0400008A RID: 138
            CMD_VERSION = 3170893825U,

            // Token: 0x0400008B RID: 139
            CMD_EXT_FW_VERSION,

            // Token: 0x0400008C RID: 140
            CMD_PROC_LIST = 3182034945U,

            // Token: 0x0400008D RID: 141
            CMD_PROC_READ,

            // Token: 0x0400008E RID: 142
            CMD_PROC_WRITE,

            // Token: 0x0400008F RID: 143
            CMD_PROC_MAPS,

            // Token: 0x04000090 RID: 144
            CMD_PROC_INTALL,

            // Token: 0x04000091 RID: 145
            CMD_PROC_CALL,

            // Token: 0x04000092 RID: 146
            CMD_PROC_ELF,

            // Token: 0x04000093 RID: 147
            CMD_PROC_PROTECT,

            // Token: 0x04000094 RID: 148
            CMD_PROC_SCAN,

            // Token: 0x04000095 RID: 149
            CMD_PROC_INFO,

            // Token: 0x04000096 RID: 150
            CMD_PROC_ALLOC,

            // Token: 0x04000097 RID: 151
            CMD_PROC_FREE,

            // Token: 0x04000098 RID: 152
            CMD_DEBUG_ATTACH = 3183149057U,

            // Token: 0x04000099 RID: 153
            CMD_DEBUG_DETACH,

            // Token: 0x0400009A RID: 154
            CMD_DEBUG_BREAKPT,

            // Token: 0x0400009B RID: 155
            CMD_DEBUG_WATCHPT,

            // Token: 0x0400009C RID: 156
            CMD_DEBUG_THREADS,

            // Token: 0x0400009D RID: 157
            CMD_DEBUG_STOPTHR,

            // Token: 0x0400009E RID: 158
            CMD_DEBUG_RESUMETHR,

            // Token: 0x0400009F RID: 159
            CMD_DEBUG_GETREGS,

            // Token: 0x040000A0 RID: 160
            CMD_DEBUG_SETREGS,

            // Token: 0x040000A1 RID: 161
            CMD_DEBUG_GETFPREGS,

            // Token: 0x040000A2 RID: 162
            CMD_DEBUG_SETFPREGS,

            // Token: 0x040000A3 RID: 163
            CMD_DEBUG_GETDBGREGS,

            // Token: 0x040000A4 RID: 164
            CMD_DEBUG_SETDBGREGS,

            // Token: 0x040000A5 RID: 165
            CMD_DEBUG_STOPGO = 3183149072U,

            // Token: 0x040000A6 RID: 166
            CMD_DEBUG_THRINFO,

            // Token: 0x040000A7 RID: 167
            CMD_DEBUG_SINGLESTEP,

            // Token: 0x040000A8 RID: 168
            CMD_KERN_BASE = 3184263169U,

            // Token: 0x040000A9 RID: 169
            CMD_KERN_READ,

            // Token: 0x040000AA RID: 170
            CMD_KERN_WRITE,

            // Token: 0x040000AB RID: 171
            CMD_CONSOLE_REBOOT = 3185377281U,

            // Token: 0x040000AC RID: 172
            CMD_CONSOLE_END,

            // Token: 0x040000AD RID: 173
            CMD_CONSOLE_PRINT,

            // Token: 0x040000AE RID: 174
            CMD_CONSOLE_NOTIFY,

            // Token: 0x040000AF RID: 175
            CMD_CONSOLE_INFO
        }

        // Token: 0x02000013 RID: 19
        public enum CMD_STATUS : uint {

            // Token: 0x040000B1 RID: 177
            CMD_SUCCESS = 2147483648U,

            // Token: 0x040000B2 RID: 178
            CMD_ERROR = 4026531841U,

            // Token: 0x040000B3 RID: 179
            CMD_TOO_MUCH_DATA,

            // Token: 0x040000B4 RID: 180
            CMD_DATA_NULL,

            // Token: 0x040000B5 RID: 181
            CMD_ALREADY_DEBUG,

            // Token: 0x040000B6 RID: 182
            CMD_INVALID_INDEX
        }

        // Token: 0x02000014 RID: 20
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CMDPacket {

            // Token: 0x040000B7 RID: 183
            public uint magic;

            // Token: 0x040000B8 RID: 184
            public uint cmd;

            // Token: 0x040000B9 RID: 185
            public uint datalen;
        }

        // Token: 0x02000015 RID: 21
        public enum VM_PROTECTIONS : uint {

            // Token: 0x040000BB RID: 187
            VM_PROT_NONE,

            // Token: 0x040000BC RID: 188
            VM_PROT_READ,

            // Token: 0x040000BD RID: 189
            VM_PROT_WRITE,

            // Token: 0x040000BE RID: 190
            VM_PROT_EXECUTE = 4U,

            // Token: 0x040000BF RID: 191
            VM_PROT_DEFAULT = 3U,

            // Token: 0x040000C0 RID: 192
            VM_PROT_ALL = 7U,

            // Token: 0x040000C1 RID: 193
            VM_PROT_NO_CHANGE,

            // Token: 0x040000C2 RID: 194
            VM_PROT_COPY = 16U,

            // Token: 0x040000C3 RID: 195
            VM_PROT_WANTS_COPY = 16U
        }

        // Token: 0x02000016 RID: 22
        public enum WATCHPT_LENGTH : uint {

            // Token: 0x040000C5 RID: 197
            DBREG_DR7_LEN_1,

            // Token: 0x040000C6 RID: 198
            DBREG_DR7_LEN_2,

            // Token: 0x040000C7 RID: 199
            DBREG_DR7_LEN_4 = 3U,

            // Token: 0x040000C8 RID: 200
            DBREG_DR7_LEN_8 = 2U
        }

        // Token: 0x02000017 RID: 23
        public enum WATCHPT_BREAKTYPE : uint {

            // Token: 0x040000CA RID: 202
            DBREG_DR7_EXEC,

            // Token: 0x040000CB RID: 203
            DBREG_DR7_WRONLY,

            // Token: 0x040000CC RID: 204
            DBREG_DR7_RDWR = 3U
        }

        // Token: 0x02000018 RID: 24
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct DebuggerInterruptPacket {

            // Token: 0x040000CD RID: 205
            public uint lwpid;

            // Token: 0x040000CE RID: 206
            public uint status;

            // Token: 0x040000CF RID: 207
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 40)]
            public string tdname;

            // Token: 0x040000D0 RID: 208
            public regs reg64;

            // Token: 0x040000D1 RID: 209
            public fpregs savefpu;

            // Token: 0x040000D2 RID: 210
            public dbregs dbreg64;
        }

        // Token: 0x02000019 RID: 25
        // (Invoke) Token: 0x06000050 RID: 80
        public delegate void DebuggerInterruptCallback(uint lwpid, uint status, string tdname, regs regs, fpregs fpregs, dbregs dbregs);

        // Token: 0x0200001A RID: 26
        public enum ScanValueType : byte {

            // Token: 0x040000D4 RID: 212
            valTypeUInt8,

            // Token: 0x040000D5 RID: 213
            valTypeInt8,

            // Token: 0x040000D6 RID: 214
            valTypeUInt16,

            // Token: 0x040000D7 RID: 215
            valTypeInt16,

            // Token: 0x040000D8 RID: 216
            valTypeUInt32,

            // Token: 0x040000D9 RID: 217
            valTypeInt32,

            // Token: 0x040000DA RID: 218
            valTypeUInt64,

            // Token: 0x040000DB RID: 219
            valTypeInt64,

            // Token: 0x040000DC RID: 220
            valTypeFloat,

            // Token: 0x040000DD RID: 221
            valTypeDouble,

            // Token: 0x040000DE RID: 222
            valTypeArrBytes,

            // Token: 0x040000DF RID: 223
            valTypeString
        }

        // Token: 0x0200001B RID: 27
        public enum ScanCompareType : byte {

            // Token: 0x040000E1 RID: 225
            ExactValue,

            // Token: 0x040000E2 RID: 226
            FuzzyValue,

            // Token: 0x040000E3 RID: 227
            BiggerThan,

            // Token: 0x040000E4 RID: 228
            SmallerThan,

            // Token: 0x040000E5 RID: 229
            ValueBetween,

            // Token: 0x040000E6 RID: 230
            IncreasedValue,

            // Token: 0x040000E7 RID: 231
            IncreasedValueBy,

            // Token: 0x040000E8 RID: 232
            DecreasedValue,

            // Token: 0x040000E9 RID: 233
            DecreasedValueBy,

            // Token: 0x040000EA RID: 234
            ChangedValue,

            // Token: 0x040000EB RID: 235
            UnchangedValue,

            // Token: 0x040000EC RID: 236
            UnknownInitialValue
        }
    }
}
