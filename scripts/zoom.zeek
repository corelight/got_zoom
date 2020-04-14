module zoom_TLS; 
    # This script raises a notice for when:
    #   1) Traffic generated when a Zoom client connects
    #   2) Traffic generated when a meeting is joined
    # Tested against Zoom Version: 4.6.10 (20041.0408) ; zeek version 3.2.0-dev.277
     
export {
    global zoom_JA3_client_connect: set[string] = set(
        "fdf59db13f79da45024018dabda7080d",
        "c51de225944b7d58d48c0f99f86ba8e6"
        );
    global zoom_JA3S_client_connect: set[string] = set(
        "c47ac3dc74b5ef88f4e96e184c552098",
        "367b681f4d7aa89f8609c6fe7d1fa774",
        "7c9a36ef25ae55e481acdf7c96c1ca15",
        "0b8e478e42c89eaa602e5a29af6f639a",
        "f6e234011390444c303f74d09d87322d"
        );
    # Commented out but left here for reference if required later.
    # global zoom_JA3_in_meeting: set[string] = set(
    #     "8e6eceee7fcf02fec8fd6cbfcb9c4de9"
    #     );
    global zoom_JA3S_in_meeting: set[string] = set(
        "ada793d0f02b028a6c840504edccb652"
        );

    redef enum Notice::Type += {
        LoggedIn,
        MeetingJoined
    };
}

event ssl_established(c:connection)
    {
    local notice_message: string = "";

    if (c$ssl$ja3 in zoom_JA3_client_connect && c$ssl$ja3s in zoom_JA3S_client_connect &&
            /\.zoom\.us$/ in c$ssl$server_name &&
            /^CN\=\*\.zoom\./ in c$ssl$cert_chain[0]$x509$certificate$subject) 
        {
        # print "You Got Zoom Client running";
        notice_message = fmt("Zoom Client connected to %s. Only the first connection generates this notice (there may be numerous connections)", c$ssl$server_name);
        NOTICE([$note=LoggedIn,
                $conn=c, 
                $identifier=cat(c$id$orig_h),
                $sub=c$ssl$server_name,
                $msg=notice_message]);
        return;
        }
    # Note that the JA3 (stored for reference in set zoom_JA3_in_meeting), is not used here. 
    # This should make for more resilience to variations in client flavours.
    if (c$ssl$ja3s in zoom_JA3S_in_meeting &&
            /\.zoom\.us$/ in c$ssl$server_name &&
            /^CN\=\*\.zoom\./ in c$ssl$cert_chain[0]$x509$certificate$subject) 
        {
        # print "You Got a Zoom Video/Audio session";
        notice_message = fmt("Zoom Meeting traffic to %s. Only the first meeting connection generates this notice (there are often numerous such connections for a single Zoom meeting)", c$ssl$server_name);
        NOTICE([$note=MeetingJoined,
                    $conn=c, 
                    $identifier=cat(c$id$orig_h),
                    $sub=c$ssl$server_name,
                    $msg=notice_message]);
        }
    }
