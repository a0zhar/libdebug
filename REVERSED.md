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
