# ctn123's libdebug - related
These functions has been originally taken from the latest libdebug.dll release by ctn123.
This (**.dll**) was deobfuscated twice, before being decompiled!
The functions have been worked on by myself, such as refactoring to make them more workable



### FindPlaystation function
```cs
public static string FindPlayStation() {
    IPEndPoint ipendPoint = new IPEndPoint(IPAddress.Any, 0);
    UdpClient udpClient = new UdpClient();
    udpClient.EnableBroadcast = true;
    udpClient.Client.ReceiveTimeout = 4000;

    byte[] magic_bytes = BitConverter.GetBytes(BROADCAST_MAGIC);
    string result_ip;
    
    IPAddress ipaddress = null;
    foreach (IPAddress ipaddress2 in Dns.GetHostEntry(Dns.GetHostName()).AddressList) {
        if (ipaddress2.AddressFamily == AddressFamily.InterNetwork)
            ipaddress = ipaddress2;
    }

    if (ipaddress == null) {
        // Cleanup, before throwing exception
        udpClient.Close();
        throw new Exception(
            "libdebug exception: Broadcast error! - Could not get host ip"
        );
    }

    udpClient.Send(
        magic_bytes,
        magic_bytes.Length,
        new IPEndPoint(
            GetBroadcastAddress(ipaddress, IPAddress.Parse("255.255.255.0")),
            BROADCAST_PORT
        )
     );

    byte[] udpResponse = udpClient.Receive(ref ipendPoint);
    if (BitConverter.ToUInt32(udpResponse, 0) != BROADCAST_MAGIC) {
        // Cleanup, before throwing exception
        udpClient.Close();
        throw new Exception(
            "libdebug exception: Broadcast error! - Wrong magic on udp server"
        );
    }

    // Save the PS4 IP address, before cleaning up
    result_ip = ipendPoint.Address.ToString();

    // Peform some cleanup
    udpClient.Close();

    // Return the PS4 IP address
    return result_ip;
}
```

### GetProcessList Function
```cs
public ProcessList GetProcessList() {
    CheckConnected();
    SendCMDPacket(CMDS.CMD_PROC_LIST, 0, new object[0]);
    CheckStatus("");

    // Receive the Process List Count
    byte[] array = new byte[4];
    sock.Receive(array, 4, SocketFlags.None);
    int number = BitConverter.ToInt32(array, 0);

    // Receive the Process List Data
    byte[] data = ReceiveData(PROC_LIST_ENTRY_SIZE*number);

    // Create an array for the Process IDs, and an array for the
    // Process names, present in the received process list
    string[] names = new string[number];
    int[] pids = new int[number];

    // Current offset in the Process List
    int proc_list_offset;

    // Parse the Process list data (Process Names and Process IDs)
    for (int i = 0; i < number; i++) {
        proc_list_offset = PROC_LIST_ENTRY_SIZE * i;
        names[i] = ConvertASCII(data, proc_list_offset);
        pids[i] = BitConverter.ToInt32(data, proc_list_offset + 32);
    }

    return new ProcessList(number, names, pids);
}
```
