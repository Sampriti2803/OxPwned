rule Akira
{
    meta:
        author = "rivitna"
        family = "ransomware.akira.windows"
        description = "Akira ransomware Windows payload"
        severity = 10
        score = 100

    // String patterns from Akira ransomware, such as arguments, error messages, and paths
    strings:
        $s0 = "\x00--encryption_path\x00" ascii wide
        $s1 = "\x00--share_file\x00" ascii wide
        $s2 = "\x00--encryption_percent\x00" ascii wide
        $s3 = "\x00-fork\x00" ascii
        $s4 = "\x00-localonly\x00" ascii wide
        $s5 = "\x00Failed to read share files\x00" ascii wide
        $s6 = ":\\akira\\asio\\include\\" ascii
        $s7 = "\x00write_encrypt_info error: \x00" ascii
        $s8 = "\x00encrypt_part error: \x00" ascii
        $s9 = "\x00Detected number of cpus = \x00" ascii
        $s10 = "\x00No path to encrypt\x00" ascii
        $s11 = "Paste this link - https://akira" ascii
        $s12 = "\x00Trend Micro\x00" wide
        $s13 = "Failed to make full encrypt" ascii wide
        $s14 = "Failed to make spot encrypt" ascii wide
        $s15 = "Failed to make part encrypt" ascii wide
        $s16 = "Failed to write header" ascii wide
        $s17 = "file rename failed. System error:" ascii wide
        $s18 = "Number of thread to folder parsers = \x00" ascii
        $s19 = "Number of threads to encrypt = \x00" ascii
        $s20 = "Number of thread to root folder parsers = \x00" ascii
        $s21 = "Failed to read share files!\x00" ascii

        // Matches binary patterns in the ransomware executable.
        $h0 = { 41 BA 05 00 00 00 41 80 FB 32 44 0F 42 D0 33 D2 48 8B C?
                49 F7 F2 4C 8B C8
                ( B? 02 00 00 00 [0-4] 41 B? 04 00 00 00 |
                  41 B? 04 00 00 00 [0-4] B? 02 00 00 00 )
                41 80 FB 32 44 0F 42 C? 41 8B C8 4? 0F AF C? 48 2B F9 33 D2
                48 8B C7 49 F7 F2 }
        $h1 = { C7 45 ?? 03 00 00 00 80 7D ?? 31 76 07 C7 45 ?? 05 00 00 00
                0F B6 45 ?? 48 0F AF 45 ?? 48 C1 E8 02
                48 B? C3 F5 28 5C 8F C2 F5 28 48 F7 E? 48 89 ?? 48 C1 E8 02 }

    // Detects Windows PE files (0x5A4D and 0x4550) or ELF files (0x464C457F) containing specific patterns
    condition:
        (((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) or
         (uint32(0) == 0x464C457F)) and
        (
            (7 of ($s*)) or
            (1 of ($h*))
        )
}

rule ecrime_AKIRA_strings {
    meta:
        id = "8c59c35d-8fb8-4644-9fa4-ce05b30e91c3"
        version = "1.0"
        author = "Paul Jaramillo"
        intrusion_set = "AKIRA"
        description = "Detects common strings"
        source = "PE binaries"
        creation_date = "2023-05-03"
        modification_date = "2023-05-09"
        classification = "TLP:CLEAR"

    // Matches ransomware-specific file extensions, file names, and unique strings
    strings:
        $s1 = ".akira" ascii nocase
        $s2 = "akira_readme.txt" ascii nocase
        $s3 = ".onion" ascii nocase
        $s4 = /\\akira\\asio\\include\\asio\\impl\\co_spawn\.hpp/
        $s5 = /MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAylJbjtFvzHapC/

    condition:
        (filesize>250KB and filesize<1MB) and
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x4550 and
        (($s1 and $s2 and $s3) or
        $s4 or $s5)
}

rule Akira_Ransomware
{
  meta:
        author = "Martin Jakobsson"
        version = "1.0"
        date = "10/02/2024"
        md5 = "3ec242d578bc135cb825c9eb655e63eb"
        description = "YARA Rule to hunt Akira Ransomware."
      
  strings: 

        $s1 = ".akira"
        $s2 = "powershell.exe -Command \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\""
        $s3 = "akira_readme.txt"
        $h1 = {E8 F2 F6 FF FF} // Get-WMIObject function
        $h2 = {FF 15 D1 B1 03 00} // EnumerateHostProcess 
        
        $h3_exception = {48 8D 15 D7 78 07 00} //System Volume Information
        $h4_exception = {48 8D 15 10 79 07 00} //temp
        $h5_exception = {48 8D 15 49 79 07 00} //tmp
        $h6_exception = {48 8D 15 AC 78 07 00} //ProgramData
        
        $h7_tightstring = { // CMD TightString
            45 20 3B C6 45 21 74 C6  45 22 3B C6 45 23 37 C6
            45 24 3B C6 45 25 45 C6  45 26 3B C6 45 27 53 C6
            45 28 3B C6 45 29 6B C6  45 2A 3B C6 45 2B 53 C6
            45 2C 3B C6 45 2D 3E C6  45 2E 3B C6 45 2F 6B C6
            45 30 3B C6 45 31 6F C6  45 32 3B C6 45 33 6B C6
            45 34 3B C6 45 35 3B C6  45 36 3B 0F B6 45 1D 0F
            B6 45 1C 84 C0 75 5A 4C  8B C7 66 0F 1F 44 00 00
        }
        $h8_tightstring = { //ihost TightString
            C6 45 AE 3D C6 45 AF 6E  C6 45 B0 58 C6 45 B1 6E
            C6 45 B2 41 C6 45 B3 6E  C6 45 B4 58 C6 45 B5 6E
            C6 45 B6 6E C6 45 B7 6E  0F B6 45 A2 0F B6 45 A1
            84 C0 75 5D 4C 8B C7 66  0F 1F 84 00 00 00 00 00
        }
        $h9_tightstring = { //fontdrvhost TightString
            00 00 00 C6 85 A6 00 00  00 10 C6 85 A7 00 00 00
            3F C6 85 A8 00 00 00 26  C6 85 A9 00 00 00 3F C6
            85 AA 00 00 00 5C C6 85  AB 00 00 00 3F C6 85 AC
            00 00 00 16 C6 85 AD 00  00 00 3F C6 85 AE 00 00
            00 7C C6 85 AF 00 00 00  3F C6 85 B0 00 00 00 03
            C6 85 B1 00 00 00 3F C6  85 B2 00 00 00 29 C6 85
            B3 00 00 00 3F C6 85 B4  00 00 00 23 C6 85 B5 00
            00 00 3F C6 85 B6 00 00  00 26 C6 85 B7 00 00 00
            3F C6 85 B8 00 00 00 4C  C6 85 B9 00 00 00 3F C6
        }
        
 condition: 
 
        uint16(0) == 0x5A4D  // Checks for the Windows version of Akira.
        and $s1 and $s3
        and $s2
        and $h1 and $h2 
        and $h3_exception or $h4_exception or $h5_exception or $h6_exception
        and $h7_tightstring or $h8_tightstring or $h9_tightstring
        
}
