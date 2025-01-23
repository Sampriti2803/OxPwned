rule MAL_Backdoor_DLL_Nov23_1 {
   meta:
      author = "X__Junior"
      description = "Detects a backdoor DLL, that was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "cc21c77e1ee7e916c9c48194fad083b2d4b2023df703e544ffb2d6a0bfc90a63"
      hash2 = "0eb66eebb9b4d671f759fb2e8b239e8a6ab193a732da8583e6e8721a2670a96d"
      score = 80
      id = "3588d437-b561-5380-8dac-73a31f4cdb5a"
   strings:
      $s1 = "ERROR GET INTERVAL" ascii
      $s2 = "OFF HIDDEN MODE" ascii
      $s3 = "commandMod:" ascii
      $s4 = "RESULT:" ascii

      $op1 = { C7 44 24 ?? 01 00 00 00 C7 84 24 ?? ?? ?? ?? FF FF FF FF 83 7C 24 ?? 00 74 ?? 83 BC 24 ?? ?? ?? ?? 00 74 ?? 4C 8D 8C 24 ?? ?? ?? ?? 41 B8 00 04 00 00 48 8D 94 24 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 }
      $op2 = { 48 C7 44 24 ?? 00 00 00 00 C7 44 24 ?? 00 00 00 00 C7 44 24 ?? 03 00 00 00 48 8D 0D ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8D 0D ?? ?? ?? ?? 44 0F B7 05 ?? ?? ?? ?? 48 8B D0 48 8B 4C 24 ?? FF 15 }
   condition:
      uint16(0) == 0x5a4d
      and ( all of ($s*) or all of ($op*) )
}

rule MAL_Trojan_DLL_Nov23 {
   meta:
      author = "X__Junior"
      description = "Detects a trojan DLL that installs other components - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "e557e1440e394537cca71ed3d61372106c3c70eb6ef9f07521768f23a0974068"
      score = 80
      id = "1dd87d0a-2b8b-5386-8fdd-40d184c731a4"
   strings:
      $op1 = { C7 84 24 ?? ?? ?? ?? 52 70 63 53 C7 84 24 ?? ?? ?? ?? 74 72 69 6E C7 84 24 ?? ?? ?? ?? 67 42 69 6E C7 84 24 ?? ?? ?? ?? 64 69 6E 67 C7 84 24 ?? ?? ?? ?? 43 6F 6D 70 C7 84 24 ?? ?? ?? ?? 6F 73 65 41 C7 84 24 ?? ?? ?? ?? 00 40 01 01 }
      $op2 = { C7 84 24 ?? ?? ?? ?? 6C 73 61 73 C7 84 24 ?? ?? ?? ?? 73 70 69 72 66 C7 84 24 ?? ?? 00 00 70 63 }
      $op3 = { C7 84 24 ?? ?? ?? ?? 4E 64 72 43 C7 84 24 ?? ?? ?? ?? 6C 69 65 6E C7 84 24 ?? ?? ?? ?? 74 43 61 6C C7 84 24 ?? ?? ?? ?? 6C 33 00 8D }
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule MAL_DLL_Stealer_Nov23 {
   meta:
      author = "X__Junior"
      description = "Detects a DLL that steals authentication credentials - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "17a27b1759f10d1f6f1f51a11c0efea550e2075c2c394259af4d3f855bbcc994"
      score = 80
      id = "9cfed8ec-1d04-53d7-88ef-2576075cfc33"
   strings:
      $op1 = { C7 45 ?? 4D 69 6E 69 C7 45 ?? 44 75 6D 70 C7 45 ?? 57 72 69 74 C7 45 ?? 65 44 75 6D C7 45 ?? 70 00 27 00 C7 45 ?? 44 00 62 00 C7 45 ?? 67 00 68 00 C7 45 ?? 65 00 6C 00 C7 45 ?? 70 00 2E 00 C7 45 ?? 64 00 6C 00 C7 45 ?? 6C 00 00 00}
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule MAL_Python_Backdoor_Script_Nov23 {
   meta:
      author = "X__Junior"
      description = "Detects a trojan (written in Python) that communicates with c2 - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "906602ea3c887af67bcb4531bbbb459d7c24a2efcb866bcb1e3b028a51f12ae6"
      score = 80
      id = "861f9ce3-3c54-5c56-b50b-2b7536783f6e"
   strings:
      $s1 = "port = 443 if \"https\"" ascii
      $s2 = "winrm.Session basic error" ascii
      $s3 = "Windwoscmd.run_cmd(str(cmd))" ascii
   condition:
      filesize < 50KB and all of them
}

rule APT_RANSOM_Lockbit_ForensicArtifacts_Nov23 {
   meta:
      description = "Detects patterns found in Lockbit TA attacks exploiting Citrixbleed vulnerability CVE 2023-4966"
      author = "Florian Roth"
      date = "2023-11-22"
      score = 75
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      id = "04bde599-2a5b-5a33-a6f1-67d57a564946"
   strings:
      $x1 = "taskkill /f /im sqlwriter.exe /im winmysqladmin.exe /im w3sqlmgr.exe"
      $x2 = " 1> \\\\127.0.0.1\\admin$\\__"
   condition:
      1 of ($x*)
}

rule MAL_RANSOM_Stealbit_Aug21 {
	meta:
		description = "Detects Stealbit used by Lockbit 2.0 Ransomware Gang"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/Lockbit2.Stealbit.yar"
		date = "2021-08-12"
		hash1 = "3407f26b3d69f1dfce76782fee1256274cf92f744c65aa1ff2d3eaaaf61b0b1d"
		hash2 = "bd14872dd9fdead89fc074fdc5832caea4ceac02983ec41f814278130b3f943e"
		id = "07b466cb-92b3-51f2-a702-2930bb7038c6"
	strings:
		$C2Decryption = {33 C9 8B C1 83 E0 0F 8A 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 F9 7C 72 E9 E8}
	condition:
		uint16(0) == 0x5A4D and filesize < 100KB and $C2Decryption
}

rule MAL_RANSOM_LNX_macOS_LockBit_Apr23_1 {
   meta:
      description = "Detects LockBit ransomware samples for Linux and macOS"
      author = "Florian Roth"
      reference = "https://twitter.com/malwrhunterteam/status/1647384505550876675?s=20"
      date = "2023-04-15"
      hash1 = "0a2bffa0a30ec609d80591eef1d0994d8b37ab1f6a6bad7260d9d435067fb48e"
      hash2 = "9ebcbaf3c9e2bbce6b2331238ab584f95f7ced326ca4aba2ddcc8aa8ee964f66"
      hash3 = "a405d034c01a357a89c9988ffe8a46a165915df18fd297469b2bcaaf97578442"
      hash4 = "c9cac06c9093e9026c169adc3650b018d29c8b209e3ec511bbe34cbe1638a0d8"
      hash5 = "dc3d08480f5e18062a0643f9c4319e5c3f55a2e7e93cd8eddd5e0c02634df7cf"
      hash6 = "e77124c2e9b691dbe41d83672d3636411aaebc0aff9a300111a90017420ff096"
      hash7 = "0be6f1e927f973df35dad6fc661048236d46879ad59f824233d757ec6e722bde"
      hash8 = "3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"
      score = 85
      id = "c01cb907-7d30-5487-b908-51f69ddb914c"
   strings:
      $x1 = "restore-my-files.txt" ascii fullword

      $s1 = "ntuser.dat.log" ascii fullword
      $s2 = "bootsect.bak" ascii fullword
      $s3 = "autorun.inf" ascii fullword
      $s4 = "lockbit" ascii fullword 

      $xc1 = { 33 38 36 00 63 6D 64 00 61 6E 69 00 61 64 76 00 6D 73 69 00 6D 73 70 00 63 6F 6D 00 6E 6C 73 } /* extensions that get encrypted */
      $xc2 = { 6E 74 6C 64 72 00 6E 74 75 73 65 72 2E 64 61 74 2E 6C 6F 67 00 62 6F 6F 74 73 65 63 74 2E 62 61 6B } /* file name list */
      $xc3 = { 76 6D 2E 73 74 61 74 73 2E 76 6D 2E 76 5F 66 72 65 65 5F 63 6F 75 6E 74 00 61 2B 00 2F 2A } /* vm.stats + short strings */

      $op1 = { 84 e5 f0 00 f0 e7 10 40 2d e9 2e 10 a0 e3 00 40 a0 e1 ?? fe ff }
      $op2 = { 00 90 a0 e3 40 20 58 e2 3f 80 08 e2 3f 30 c2 e3 09 20 98 e1 08 20 9d }
      $op3 = { 2d e9 01 70 43 e2 07 00 13 e1 01 60 a0 e1 08 d0 4d e2 02 40 }
   condition:
      ( uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca )
      and ( 
         1 of ($x*)
         or 3 of them
      ) 
      or 2 of ($x*)
      or 5 of them
}

rule MAL_RANSOM_LockBit_Apr23_1 {
   meta:
      description = "Detects indicators found in LockBit ransomware"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17"
      score = 75
      id = "75dc8b95-16f0-5170-a7d6-fc10bb778348"
   strings:
      $xe1 = "-i '/path/to/crypt'" xor
      $xe2 = "http://lockbit" xor
      
      $s1 = "idelayinmin" ascii
      $s2 = "bVMDKmode" ascii
      $s3 = "bSelfRemove" ascii
      $s4 = "iSpotMaximum" ascii

      $fp1 = "<html"
   condition:
      (
         1 of ($x*)
         or 4 of them
      )
      and not 1 of ($fp*)
}

rule MAL_RANSOM_LockBit_Locker_LOG_Apr23_1 {
   meta:
      description = "Detects indicators found in LockBit ransomware log files"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17"
      score = 75
      id = "aa0a2393-e5a2-5151-8afb-91a9bb922179"
   strings:
      $s1 = " is encrypted. Checksum after encryption "
      $s2 = "~~~~~Hardware~~~~"
      $s3 = "[+] Add directory to encrypt:"
      $s4 = "][+] Launch parameters: "
   condition:
      2 of them
}

rule MAL_RANSOM_LockBit_ForensicArtifacts_Apr23_1 {
   meta:
      description = "Detects forensic artifacts found in LockBit intrusions"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17"
      score = 75
      id = "e716030c-ee78-51dc-919c-cf59e93da976"
   strings:
      $x1 = "/tmp/locker.log" ascii fullword
      $x2 = "Executable=LockBit/locker_" ascii
      /* Tor Browser Links:\x0d\x0ahttp://lockbit */
      $xc1 = { 54 6F 72 20 42 72 6F 77 73 65 72 20 4C 69 6E 6B 73 3A 0D 0A 68 74 74 70 3A 2F 2F 6C 6F 63 6B 62 69 74 }
   condition:
      1 of ($x*)
}

rule LockBit3 {
    meta:
        author = "rivitna"
        family = "ransomware.lockbit3.windows"
        description = "BlackMatter/LockBit3 ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $h0 = { 64 A1 30 00 00 00 8B B0 A4 00 00 00 8B B8 A8 00 00 00
                83 FE 05 75 05 83 FF 01 }
        $h1 = { 02 F1 2A F1 [2-16] D3 CA 03 D0 }
        $h2 = { 3C 2B 75 04 B0 78 EB 0E 3C 2F 75 04 B0 69 EB 06 3C 3D
                75 02 B0 7A }
        $h3 = { 33 C0 40 40 8D 0C C5 01 00 00 00 83 7D 0? 00 75 04 F7 D8
                EB 0? }
        $h4 = { C1 C0 09 33 ?8 8D 04 ?? C1 C0 0D 33 ?8 8D 04 ?? C1 C8 0E
                33 ?8 83 6C 24 ?? 01 }
        $h5 = { 3D B2 EB AA D4 74 07 3D C0 18 20 01 75 }
        $h6 = { B9 0D 66 19 00 [0-16] F7 E1 [0-16] 05 5F F3 6E 3C [0-16]
                25 FF FF FF 07 }
        $h7 = { 3D 75 BA 0E 64 75 ?? 83 C7 02 66 83 3F 20 74 F7 }
        $h8 = { 3D 75 80 91 76 74 0E 3D 1B A4 04 00 74 07 3D 9B B4 84 0B 75 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (3 of ($h*))
        )
}