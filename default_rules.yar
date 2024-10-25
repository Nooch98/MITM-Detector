rule Detect_Executable_Files
{
    meta:
        description = "Detects common executable file formats such as EXE, DLL, and ELF"
        author = "Nooch98"
        date = "2024-10-25"
        version = "1.0"

    strings:
        // Detect PE (Portable Executable) files (Windows)
        $mz = { 4D 5A }  // MZ Header (EXE files)
        // Detect ELF (Executable and Linkable Format) files (Linux)
        $elf = { 7F 45 4C 46 }  // ELF Header

    condition:
        $mz or $elf
}

rule Detect_Shellcode
{
    meta:
        description = "Detects common shellcode patterns"
        author = "Nooch98"
        date = "2024-10-25"
        version = "1.0"

    strings:
        // Common shellcode patterns
        $xor = { 31 C0 31 DB 31 C9 31 D2 }
        $jmp = { E9 ?? ?? ?? ?? }  // JMP instruction
        $nop_sled = { 90 90 90 90 90 90 90 90 }  // NOP sled

    condition:
        $xor or $jmp or $nop_sled
}

rule Detect_Powershell_Scripts
{
    meta:
        description = "Detects encoded or obfuscated PowerShell scripts"
        author = "Nooch98"
        date = "2024-10-25"
        version = "1.0"

    strings:
        $encoded_cmd = "-encodedCommand"
        $bypass = "-ExecutionPolicy Bypass"
        $download = "IEX (New-Object Net.WebClient).DownloadString"

    condition:
        $encoded_cmd or $bypass or $download
}

rule Detect_Suspicious_Documents
{
    meta:
        description = "Detects suspicious document formats with potential macro or OLE objects"
        author = "Nooch98"
        date = "2024-10-25"
        version = "1.0"

    strings:
        $doc = { D0 CF 11 E0 A1 B1 1A E1 }  // Compound File Binary Format (e.g., DOC, XLS)
        $ole = "OLE"  // Presence of OLE objects
        $vba = "VBA"  // Presence of VBA macros

    condition:
        $doc and ($ole or $vba)
}

rule Detect_Suspicious_Network_Connections
{
    meta:
        description = "Detects common indicators of network connections often used in malware"
        author = "Nooch98"
        date = "2024-10-25"
        version = "1.0"

    strings:
        $http = "http://"  // HTTP protocol
        $https = "https://"  // HTTPS protocol
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/  // IP addresses
        $user_agent = "User-Agent:"  // Common in HTTP requests

    condition:
        $http or $https or $ip or $user_agent
}

rule Detect_Ransomware_Artifacts
{
    meta:
        description = "Detects common ransomware strings and behaviors"
        author = "Nooch98"
        date = "2024-10-25"
        version = "1.0"

    strings:
        $ransom_note = "Your files have been encrypted"
        $bitcoin = "bitcoin"
        $tor = ".onion"
        $extension = /(\.locked|\.encrypted|\.crypt)$/  // Ransomware file extensions

    condition:
        $ransom_note or $bitcoin or $tor or $extension
}
