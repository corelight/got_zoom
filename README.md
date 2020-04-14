# Got Zoom ?
- Raises a notice when the Zoom client initially connects. The name of the server included in the notice indicates the authentication method - being Facebook, Google, SSO, or Zoom itself. 
- Raises a separate notice when the Zoom client joins a meeting. Only the name of the first meeting server connected to is included in the notice - there may be several meeting servers, each used for different purposes but all associated with the same meeting.

## Requires   
JA3 and JA3S. Errors will occur if you don't have JA3 loaded *prior* to got_zoom.  Get JA3 [here](https://github.com/salesforce/ja3 "JA3"). 
  
## Logic at a glance      
  
**Client Login:**   
*   JA3 of Zoom client AND  
*   JA3S of Zoom Login Servers AND  
*   Zoom server_name AND  
*   Zoom certificate  

**Meeting Join**  
*   JA3S of Zoom Meeting Server AND  
*   Zoom server_name AND  
*   Zoom certificate  

## Usage
### Stand alone mode:  
Make sure you have JA3 loaded prior got_zoom being loaded, you can do this by editing the commented out line in `scripts/__load__.zeek` to point to your local copy of the JA3 files. 

You can then use got_zoom on your pcap:  
```zeek -Cr your.pcap scripts/__load__.zeek```

### As a package: 
To install the package.  
```zkg install .```  
Once again, you must ensure that JA3 is loaded prior to the got_zoom load.  


## Tested against
- Zoom 4.6.10 (20041.0408) on OSX 10.15.3 
- zeek version 3.2.0-dev.277

## Output notice.log

### Connection.  
In this example the Zoom client is authenticated with Facebook, indicated by a server_name of facebook.zoom.us.  
  
`
1586823459.142204       ChMw6p3tKAfiyHngs3      192.168.13.37   57426   52.202.62.237   443     -       -       -       tcp     zoom_TLS::LoggedIn      Zoom Client connected to facebook.zoom.us. Only the first connection generates this notice (there may be numerous connections)  -       192.168.13.37    52.202.62.237   443     -       -       Notice::ACTION_LOG      3600.000000     -       -       -       -       -
`


### Meeting traffic. 
In this example, the first meeting server connected to is zoomca54150137226zc.zoom.us. There may be many other meeting servers associated with the same meeting which bear similar names.   
  
`1586498392.012030       CfIPEz2Aj3WAM2g072      192.168.13.37    63350   54.190.137.246  443     -       -       -       tcp     zoom_TLS::MeetingJoined    Zoom Meeting traffic via a connection to zoomca54150137226zc.zoom.us. Only the first server connection generates this notice. There are often numerous such connections for a single Zoom meeting       -       192.168.13.37    54.190.137.246  443     -       -       Notice::ACTION_LOG      3600.000000     -       -       -       -       -`




