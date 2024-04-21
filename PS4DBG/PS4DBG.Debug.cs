using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace libdebug {

    public partial class PS4DBG {

        //debug
        // packet sizes
        //send size
        private const int CMD_DEBUG_ATTACH_PACKET_SIZE = 4;

        private const int CMD_DEBUG_BREAKPT_PACKET_SIZE = 16;
        private const int CMD_DEBUG_WATCHPT_PACKET_SIZE = 24;
        private const int CMD_DEBUG_STOPTHR_PACKET_SIZE = 4;
        private const int CMD_DEBUG_RESUMETHR_PACKET_SIZE = 4;
        private const int CMD_DEBUG_GETREGS_PACKET_SIZE = 4;
        private const int CMD_DEBUG_SETREGS_PACKET_SIZE = 8;
        private const int CMD_DEBUG_STOPGO_PACKET_SIZE = 4;
        private const int CMD_DEBUG_THRINFO_PACKET_SIZE = 4;

        //receive size
        private const int DEBUG_INTERRUPT_SIZE = 0x4A0;

        private const int DEBUG_THRINFO_SIZE = 40;
        private const int DEBUG_REGS_SIZE = 0xB0;
        private const int DEBUG_FPREGS_SIZE = 0x340;
        private const int DEBUG_DBGREGS_SIZE = 0x80;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct DebuggerInterruptPacket {
            public uint lwpid;
            public uint status;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 40)]
            public string tdname;

            public regs reg64;
            public fpregs savefpu;
            public dbregs dbreg64;
        }

        /// <summary>
        /// Debugger interrupt callback
        /// </summary>
        /// <param name="lwpid">Thread identifier</param>
        /// <param name="status">status</param>
        /// <param name="tdname">Thread name</param>
        /// <param name="regs">Registers</param>
        /// <param name="fpregs">Floating point registers</param>
        /// <param name="dbregs">Debug registers</param>
        public delegate void DebuggerInterruptCallback(uint lwpid, uint status, string tdname, regs regs, fpregs fpregs, dbregs dbregs);

        private void DebuggerThread(object obj) {
            DebuggerInterruptCallback callback = (DebuggerInterruptCallback)obj;

            IPAddress ip = IPAddress.Parse("0.0.0.0");
            IPEndPoint endpoint = new IPEndPoint(ip, PS4DBG_DEBUG_PORT);

            Socket server = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            server.Bind(endpoint);
            server.Listen(0);

            IsDebugging = true;

            Socket cl = server.Accept();

            cl.NoDelay = true;
            cl.Blocking = false;

            while (IsDebugging) {
                if (cl.Available == DEBUG_INTERRUPT_SIZE) {
                    byte[] data = new byte[DEBUG_INTERRUPT_SIZE];
                    int bytes = cl.Receive(data, DEBUG_INTERRUPT_SIZE, SocketFlags.None);
                    if (bytes == DEBUG_INTERRUPT_SIZE) {
                        DebuggerInterruptPacket packet = (DebuggerInterruptPacket)GetObjectFromBytes(data, typeof(DebuggerInterruptPacket));
                        callback(packet.lwpid, packet.status, packet.tdname, packet.reg64, packet.savefpu, packet.dbreg64);
                    }
                }

                Thread.Sleep(100);
            }

            server.Close();
        }

        /// <summary>
        /// Attach the debugger
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="callback">DebuggerInterruptCallback implementation</param>
        /// <returns></returns>
        public void AttachDebugger(int pid, DebuggerInterruptCallback callback) {
            CheckConnected();

            if (IsDebugging || debugThread != null) {
                throw new Exception("libdbg: debugger already running?");
            }

            IsDebugging = false;

            debugThread = new Thread(DebuggerThread) { IsBackground = true };
            debugThread.Start(callback);

            // wait until server is started
            while (!IsDebugging) {
                Thread.Sleep(100);
            }

            SendCMDPacket(CMDS.CMD_DEBUG_ATTACH, CMD_DEBUG_ATTACH_PACKET_SIZE, pid);
            CheckStatus();
        }

        /// <summary>
        /// Function used to cause PS4Debug Payload running on the connected PS4 System 
        /// to Detach the debugger from the Process
        /// </summary>
        public void DetachDebugger() {
            CheckConnected();

            SendCMDPacket(CMDS.CMD_DEBUG_DETACH, 0);
            CheckStatus();


            if (IsDebugging && debugThread != null) {
                IsDebugging = false;

                debugThread.Join();
                debugThread = null;
            }
        }

        /// <summary>
        /// Function used to cause PS4Debug Payload running on the connected PS4 System 
        /// to cause the Process Execution to Stop (Pausing it)
        /// </summary>
        public void ProcessStop() {
            CheckConnected();
            CheckDebugging();

            // Build the CMD Packet/Command Packet, and send it to the Connected
            // Remote PS4 System's running PS4Debug Payload
            SendCMDPacket(CMDS.CMD_DEBUG_STOPGO, CMD_DEBUG_STOPGO_PACKET_SIZE, 1);

            CheckStatus();
        }

        /// <summary>
        /// Function used to cause PS4Debug Payload running on the connected PS4 System 
        /// to IF ATTACHED! detach the debugger from the Process then kill the Process 
        /// </summary>
        public void ProcessKill() {
            CheckConnected();
            CheckDebugging();

            // Build the CMD Packet/Command Packet, and send it to the Connected
            // Remote PS4 System's running PS4Debug Payload
            SendCMDPacket(CMDS.CMD_DEBUG_STOPGO, CMD_DEBUG_STOPGO_PACKET_SIZE, 2);

            // Check the status/response after sending the command
            CheckStatus();
        }

        /// <summary>
        /// Function used to cause PS4Debug Payload running on the connected PS4 System 
        /// to IF ATTACHED! detach the debugger from the Process then kill the Process 
        /// </summary>
        public void ProcessResume() {
            CheckConnected();
            CheckDebugging();

            // Build the CMD Packet/Command Packet, and send it to the Connected
            // Remote PS4 System's running PS4Debug Payload
            SendCMDPacket(CMDS.CMD_DEBUG_STOPGO, CMD_DEBUG_STOPGO_PACKET_SIZE, 0);

            // Then we check the status of the sent packet?
            CheckStatus();
        }

        /// <summary>
        /// Change breakpoint, to remove said breakpoint send the same index but disable it (address is ignored)
        /// </summary>
        /// <param name="index">Index</param>
        /// <param name="enabled">Enabled</param>
        /// <param name="address">Address</param>
        /// <returns></returns>
        public void ChangeBreakpoint(int index, bool enabled, ulong address) {
            CheckConnected();
            CheckDebugging();

            // Check if the breakpoint index is out of range, meaning it's either larger
            // or equal to maximum allowed number of breakpoints, then let the user know
            // about it by throwing a new exception
            if (index >= MAX_BREAKPOINTS) {
                throw new Exception(
                    $"libdebug: the Break Point index ({index}) is out of range!\n" +
                    $"Maximum allowed index is {MAX_BREAKPOINTS}!"
                );
            }

            // Send a new command packet to the PS4 system which tells the debugger to
            // change a certain breakpoint set for the process
            SendCMDPacket(
                CMDS.CMD_DEBUG_BREAKPT,
                CMD_DEBUG_BREAKPT_PACKET_SIZE,
                index,
                Convert.ToInt32(enabled),
                address
            );

            // Then we check the response/status told by the PS4
            CheckStatus();
        }

        /// <summary>
        /// Change watchpoint
        /// </summary>
        /// <param name="index">Index</param>
        /// <param name="enabled">Enabled</param>
        /// <param name="length">Length</param>
        /// <param name="breaktype">Break type</param>
        /// <param name="address">Address</param>
        /// <returns></returns>
        public void ChangeWatchpoint(int index, bool enabled, WATCHPT_LENGTH length, WATCHPT_BREAKTYPE breaktype, ulong address) {
            CheckConnected();
            CheckDebugging();

            // Check if the watchpoint index is out of range, meaning it's either larger
            // or equal to maximum allowed number of breakpoints, then let the user know
            // about it by throwing a new exception
            if (index >= MAX_WATCHPOINTS) {
                throw new Exception(
                    $"libdebug: the Watch Point index ({index}) is out of range!\n" +
                    $"Maximum allowed index is {MAX_WATCHPOINTS}!"
                );
            }

            // Send a new command packet to the PS4 system which tells the debugger to
            // change a certain watchpoint set for the process
            SendCMDPacket(
                CMDS.CMD_DEBUG_WATCHPT,
                CMD_DEBUG_WATCHPT_PACKET_SIZE,
                index, Convert.ToInt32(enabled),
                (uint)length,
                (uint)breaktype,
                address
            );

            // Then we check the response/status told by the PS4
            CheckStatus();
        }

        /// <summary>
        /// Get a list of threads from the current process
        /// </summary>
        /// <returns>A list of descriptor values for current threads in process</returns>
        public uint[] GetThreadList() {
            // Check if the PC and PS4 has an established connection,
            // and check if we are currently debugging the process?
            CheckConnected();
            CheckDebugging();

            // Send CMD_DEBUG_THREADS PACKET to the PS4Debug Payload Running,
            // on the remote PS4 system, to get it to send back list of all
            // current threads in the process?
            SendCMDPacket(CMDS.CMD_DEBUG_THREADS, 0);

            // Check the response status from the PS4 system
            CheckStatus();

            // Receive the number of threads from the PS4 system
            byte[] data = new byte[sizeof(int)];
            sock.Receive(data, sizeof(int), SocketFlags.None);
            int number = BitConverter.ToInt32(data, 0);

            // Receive the thread data from the PS4 system
            byte[] threads = ReceiveData(number * sizeof(uint));

            // Convert the thread data to an array of unsigned integers.
            // possibly thread descriptors?
            uint[] thrlist = new uint[number];
            for (int i = 0; i < number; i++) {
                thrlist[i] = BitConverter.ToUInt32(
                    threads, i * sizeof(uint));
            }

            return thrlist;
        }

        /// <summary>
        /// Get thread information
        /// </summary>
        /// <returns></returns>
        /// <param name="lwpid">Thread identifier</param>
        public ThreadInfo GetThreadInfo(uint lwpid) {
            CheckConnected();
            CheckDebugging();

            SendCMDPacket(CMDS.CMD_DEBUG_THRINFO, CMD_DEBUG_THRINFO_PACKET_SIZE, lwpid);
            CheckStatus();

            return (ThreadInfo)GetObjectFromBytes(ReceiveData(DEBUG_THRINFO_SIZE), typeof(ThreadInfo));
        }

        /// <summary>
        /// Stop a thread from running
        /// </summary>
        /// <param name="lwpid">Thread id</param>
        /// <returns></returns>
        public void StopThread(uint lwpid) {
            CheckConnected();
            CheckDebugging();

            SendCMDPacket(CMDS.CMD_DEBUG_STOPTHR, CMD_DEBUG_STOPTHR_PACKET_SIZE, lwpid);
            CheckStatus();
        }

        /// <summary>
        /// Resume a thread from being stopped
        /// </summary>
        /// <param name="lwpid">Thread id</param>
        /// <returns></returns>
        public void ResumeThread(uint lwpid) {
            CheckConnected();
            CheckDebugging();

            SendCMDPacket(CMDS.CMD_DEBUG_RESUMETHR, CMD_DEBUG_RESUMETHR_PACKET_SIZE, lwpid);
            CheckStatus();
        }

        /// <summary>
        /// Get registers from thread
        /// </summary>
        /// <param name="lwpid">Thread id</param>
        /// <returns></returns>
        public regs GetRegisters(uint lwpid) {
            CheckConnected();
            CheckDebugging();

            SendCMDPacket(CMDS.CMD_DEBUG_GETREGS, CMD_DEBUG_GETREGS_PACKET_SIZE, lwpid);
            CheckStatus();

            return (regs)GetObjectFromBytes(ReceiveData(DEBUG_REGS_SIZE), typeof(regs));
        }

        /// <summary>
        /// Set thread registers
        /// </summary>
        /// <param name="lwpid">Thread id</param>
        /// <param name="regs">Register data</param>
        /// <returns></returns>
        public void SetRegisters(uint lwpid, regs regs) {
            CheckConnected();
            CheckDebugging();

            SendCMDPacket(CMDS.CMD_DEBUG_SETREGS, CMD_DEBUG_SETREGS_PACKET_SIZE, lwpid, DEBUG_REGS_SIZE);
            CheckStatus();
            SendData(GetBytesFromObject(regs), DEBUG_REGS_SIZE);
            CheckStatus();
        }

        /// <summary>
        /// Get floating point registers from thread
        /// </summary>
        /// <param name="lwpid">Thread id</param>
        /// <returns></returns>
        public fpregs GetFloatRegisters(uint lwpid) {
            CheckConnected();
            CheckDebugging();

            SendCMDPacket(CMDS.CMD_DEBUG_GETFPREGS, CMD_DEBUG_GETREGS_PACKET_SIZE, lwpid);
            CheckStatus();

            return (fpregs)GetObjectFromBytes(ReceiveData(DEBUG_FPREGS_SIZE), typeof(fpregs));
        }

        /// <summary>
        /// Set floating point thread registers
        /// </summary>
        /// <param name="lwpid">Thread id</param>
        /// <param name="fpregs">Floating point register data</param>
        /// <returns></returns>
        public void SetFloatRegisters(uint lwpid, fpregs fpregs) {
            CheckConnected();
            CheckDebugging();

            SendCMDPacket(CMDS.CMD_DEBUG_SETFPREGS, CMD_DEBUG_SETREGS_PACKET_SIZE, lwpid, DEBUG_FPREGS_SIZE);
            CheckStatus();
            SendData(GetBytesFromObject(fpregs), DEBUG_FPREGS_SIZE);
            CheckStatus();
        }

        /// <summary>
        /// Get debug registers from thread
        /// </summary>
        /// <param name="lwpid">Thread id</param>
        /// <returns></returns>
        public dbregs GetDebugRegisters(uint lwpid) {
            CheckConnected();
            CheckDebugging();

            SendCMDPacket(CMDS.CMD_DEBUG_GETDBGREGS, CMD_DEBUG_GETREGS_PACKET_SIZE, lwpid);
            CheckStatus();

            return (dbregs)GetObjectFromBytes(ReceiveData(DEBUG_DBGREGS_SIZE), typeof(dbregs));
        }

        /// <summary>
        /// Set debug thread registers
        /// </summary>
        /// <param name="lwpid">Thread id</param>
        /// <param name="dbregs">debug register data</param>
        /// <returns></returns>
        public void SetDebugRegisters(uint lwpid, dbregs dbregs) {
            CheckConnected();
            CheckDebugging();

            SendCMDPacket(CMDS.CMD_DEBUG_SETDBGREGS, CMD_DEBUG_SETREGS_PACKET_SIZE, lwpid, DEBUG_DBGREGS_SIZE);
            CheckStatus();
            SendData(GetBytesFromObject(dbregs), DEBUG_DBGREGS_SIZE);
            CheckStatus();
        }

        /// <summary>
        /// Executes a single instruction
        /// </summary>
        public void SingleStep() {
            CheckConnected();
            CheckDebugging();

            SendCMDPacket(CMDS.CMD_DEBUG_SINGLESTEP, 0);
            CheckStatus();
        }
    }
}