param(
    [string]$dllPath = ".\output.dll",
    [string]$outPath = ".\shellcode.bin",
    [switch]$CArray
)

$bytes = [System.IO.File]::ReadAllBytes($dllPath)

# Parse DOS header
$e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)

# Parse PE header
$numberOfSections = [BitConverter]::ToUInt16($bytes, $e_lfanew + 0x06)
$sizeOfOptionalHeader = [BitConverter]::ToUInt16($bytes, $e_lfanew + 0x14)

# First section header starts after optional header
$sectionHeaderOffset = $e_lfanew + 0x18 + $sizeOfOptionalHeader

for ($i = 0; $i -lt $numberOfSections; $i++) {
    $offset = $sectionHeaderOffset + ($i * 40)
    
    # Section name is first 8 bytes
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $offset, 8).Trim("`0")
    
    if ($name -eq ".text") {
        $virtualSize = [BitConverter]::ToUInt32($bytes, $offset + 0x08)
        $rawDataOffset = [BitConverter]::ToUInt32($bytes, $offset + 0x14)
        $rawDataSize = [BitConverter]::ToUInt32($bytes, $offset + 0x10)
        
        $actualSize = [Math]::min($virtualSize, $rawDataSize)

        Write-Host "[+] Found .text section"
        Write-Host "    Raw offset: 0x$($rawDataOffset.ToString('X'))"
        Write-Host "    Raw size:   0x$($rawDataSize.ToString('X'))" 
        Write-Host "    Virtual size: 0x$($virtualSize.ToString('X'))"
        Write-Host "    Using size: 0x$($actualSize.ToString('X'))"
        
        $shellcode = New-Object byte[] $rawDataSize
        [Array]::Copy($bytes, $rawDataOffset, $shellcode, 0, $rawDataSize)

        if ($CArray) {
            $outHeaderPath = [System.IO.Path]::ChangeExtension($outPath, ".h")
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("#pragma once")
            [void]$sb.AppendLine("unsigned char shellcode[$actualSize] = {")

            for ($j = 0; $j -lt $actualSize; $j++) {
                if ($j % 16 -eq 0) {
                    [void]$sb.Append("    ")
                }

                [void]$sb.Append("0x$($shellcode[$j].ToString('X2'))")

                if ($j -lt $actualSize - 1) {
                    [void]$sb.Append(", ")
                }

                if (($j + 1) % 16 -eq 0) {
                    [void]$sb.AppendLine()
                }
            }

            [void]$sb.AppendLine()
            [void]$sb.AppendLine("};")

            [System.IO.File]::WriteAllText($outHeaderPath, $sb.ToString())
            Write-Host "[+] Wrote C array ($actualSize bytes) to $outHeaderPath"
        }
        else {
            [System.IO.File]::WriteAllBytes($outPath, $shellcode)
            Write-Host "[+] Wrote $actualSize bytes to $outPath"
        }
        exit
    }
}

Write-Host "[-] .text section not found"