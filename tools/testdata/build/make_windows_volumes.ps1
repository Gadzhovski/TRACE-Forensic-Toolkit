# Builds ReFS and Storage Spaces disks with Windows itself, and an answer
# key from Windows' own reads, for tests/test_refs.py and
# tests/test_storage_spaces.py (local only: never in CI -- GitHub's Windows
# runners cannot attach VHDX files).
#
#   Run in an elevated PowerShell (Windows 10 1709+ / 11; a Dev Drive needs
#   Windows 11 22H2 or later):
#     powershell -ExecutionPolicy Bypass -File tools\testdata\build\make_windows_volumes.ps1
#
# Writes into test_images\local\windows-built\:
#   refs-devdrive.vhdx           a Dev Drive (ReFS 3.x as this Windows makes it)
#   spaces-<n>.vhdx              three disks of one storage pool, holding a
#                                simple, a mirror and a parity space (NTFS)
#   windows-volumes-key.json     every file's path, size and SHA-256, the
#                                ReFS version, the spaces' layouts
#
# Every disk is detached at the end. Nothing else on the machine is touched;
# the pool goes away with its disks. Pure ASCII (PowerShell 5.1).

[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $PSScriptRoot '..\..\..\test_images\local\windows-built')
)

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell (Run as administrator).'
}
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$key = [ordered]@{ windows = [Environment]::OSVersion.Version.ToString(); volumes = [ordered]@{} }

function New-Vhdx([string]$Path, [int]$SizeMB) {
    if (Test-Path $Path) { throw "$Path exists: delete it first." }
    $script = Join-Path $env:TEMP 'trace-vhdx.txt'
    "create vdisk file=`"$Path`" maximum=$SizeMB type=expandable" |
        Set-Content -Encoding ASCII $script
    diskpart /s $script | Out-Null
    Remove-Item $script
    Mount-DiskImage -ImagePath $Path -StorageType VHDX -NoDriveLetter | Out-Null
    return (Get-DiskImage -ImagePath $Path | Get-Disk)
}

function Dismount-Vhdx([string]$Path) {
    Dismount-DiskImage -ImagePath $Path -ErrorAction SilentlyContinue | Out-Null
}

# Known content: a mix of sizes (resident, one cluster, many clusters), a
# deep folder, a folder big enough to need more than one table page, a
# sparse file, an alternate stream, a hard link and a deleted file.
function Write-KnownFiles([string]$Root) {
    $rng = [Random]::new(20261012)
    $bytes = { param($n) $b = New-Object byte[] $n; $rng.NextBytes($b); $b }
    New-Item -ItemType Directory -Force "$Root\Docs\Deep\Deeper" | Out-Null
    [IO.File]::WriteAllText("$Root\Docs\hello.txt", "Hello from Windows`r`n")
    [IO.File]::WriteAllBytes("$Root\Docs\Deep\Deeper\random-1MB.bin", (& $bytes 1048576))
    [IO.File]::WriteAllBytes("$Root\random-40MB.bin", (& $bytes 41943040))
    [IO.File]::WriteAllBytes("$Root\one-cluster.bin", (& $bytes 4096))
    New-Item -ItemType Directory -Force "$Root\Many" | Out-Null
    for ($i = 0; $i -lt 600; $i++) {
        [IO.File]::WriteAllText(("$Root\Many\file-{0:D4}.txt" -f $i), "file $i`r`n")
    }
    # Sparse: 64 MB long, 1 MB written in the middle.
    $sparse = "$Root\sparse.bin"
    [IO.File]::WriteAllBytes($sparse, [byte[]]@())
    fsutil sparse setflag $sparse | Out-Null
    $fs = [IO.File]::Open($sparse, 'Open', 'Write')
    $fs.SetLength(67108864); $fs.Position = 33554432
    $chunk = & $bytes 1048576; $fs.Write($chunk, 0, $chunk.Length); $fs.Close()
    fsutil sparse setrange $sparse 0 33554432 | Out-Null
    # Alternate data stream.
    Set-Content -Path "$Root\Docs\hello.txt" -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII
    # Hard link.
    fsutil hardlink create "$Root\Docs\hello-link.txt" "$Root\Docs\hello.txt" | Out-Null
    # Deleted.
    [IO.File]::WriteAllText("$Root\deleted-later.txt", "This file was deleted`r`n")
    Remove-Item "$Root\deleted-later.txt"
}

function Get-FileKey([string]$Root) {
    $files = [ordered]@{}
    Get-ChildItem -LiteralPath $Root -Recurse -Force -File |
        Where-Object { $_.FullName -notlike "$Root\System Volume Information*" -and
                       $_.FullName -notlike "$Root\`$RECYCLE.BIN*" } |
        Sort-Object FullName | ForEach-Object {
            $rel = $_.FullName.Substring($Root.Length).Replace('\', '/')
            $files[$rel] = [ordered]@{
                size = $_.Length
                sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLower()
                modified = $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            }
        }
    $files['/Docs/hello.txt']['streams'] = [ordered]@{
        'Zone.Identifier' = (Get-Content -LiteralPath "$Root\Docs\hello.txt" -Stream 'Zone.Identifier' -Raw)
    }
    return [ordered]@{ files = $files; deleted = @('/deleted-later.txt') }
}

function Mount-NewVolume($Disk, [string]$FileSystem, [string]$Label, [switch]$DevDrive) {
    if ($Disk.PartitionStyle -eq 'RAW') { Initialize-Disk -Number $Disk.Number -PartitionStyle GPT }
    $part = New-Partition -DiskNumber $Disk.Number -UseMaximumSize
    if ($DevDrive) {
        Format-Volume -Partition $part -DevDrive -NewFileSystemLabel $Label -Confirm:$false -Force | Out-Null
    } else {
        Format-Volume -Partition $part -FileSystem $FileSystem -NewFileSystemLabel $Label -Confirm:$false -Force | Out-Null
    }
    $dir = Join-Path $env:TEMP ("trace-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $dir | Out-Null
    Add-PartitionAccessPath -DiskNumber $Disk.Number -PartitionNumber $part.PartitionNumber -AccessPath "$dir\"
    return [pscustomobject]@{ Root = $dir; Partition = $part; Disk = $Disk }
}

function Dismount-Volume($Vol) {
    Remove-PartitionAccessPath -DiskNumber $Vol.Disk.Number -PartitionNumber $Vol.Partition.PartitionNumber -AccessPath "$($Vol.Root)\"
    Remove-Item $Vol.Root
}

# --- ReFS (Dev Drive) ------------------------------------------------------

$refsPath = Join-Path $OutDir 'refs-devdrive.vhdx'
Write-Host 'Dev Drive (ReFS)...'
$disk = New-Vhdx $refsPath 4096
try {
    try {
        $vol = Mount-NewVolume $disk 'ReFS' 'TRACEREFS' -DevDrive
    } catch {
        Write-Host "  Dev Drive refused ($($_.Exception.Message)); trying plain ReFS"
        $vol = Mount-NewVolume (Get-Disk -Number $disk.Number) 'ReFS' 'TRACEREFS'
    }
    Write-KnownFiles $vol.Root
    $entry = Get-FileKey $vol.Root
    $entry['refsinfo'] = (fsutil fsinfo refsinfo "$($vol.Root)\" | Out-String)
    $entry['partition_offset'] = $vol.Partition.Offset
    $entry['label'] = 'TRACEREFS'
    $key.volumes['refs-devdrive.vhdx'] = $entry
    Dismount-Volume $vol
} finally {
    Dismount-Vhdx $refsPath
}

# --- Storage Spaces ----------------------------------------------------------

Write-Host 'Storage Spaces...'
$members = 1..3 | ForEach-Object { Join-Path $OutDir "spaces-$_.vhdx" }
$disks = @()
$pool = $null
try {
    foreach ($m in $members) { $disks += New-Vhdx $m 6144 }
    $numbers = $disks | ForEach-Object { $_.Number }
    $physical = Get-PhysicalDisk -CanPool $true |
        Where-Object { $numbers -contains [int]$_.DeviceId }
    if (@($physical).Count -ne 3) {
        throw 'Windows will not pool these VHDX disks (CanPool false).'
    }
    $sub = Get-StorageSubSystem | Where-Object FriendlyName -like '*Windows Storage*' | Select-Object -First 1
    $pool = New-StoragePool -FriendlyName 'TRACEPOOL' -StorageSubSystemUniqueId $sub.UniqueId -PhysicalDisks $physical
    $key['pool'] = [ordered]@{ name = 'TRACEPOOL'; members = @('spaces-1.vhdx', 'spaces-2.vhdx', 'spaces-3.vhdx'); spaces = [ordered]@{} }
    $layouts = @(
        @{ Name = 'SIMPLE'; Resiliency = 'Simple'; Columns = 3 },
        @{ Name = 'MIRROR'; Resiliency = 'Mirror'; Columns = 1 },
        @{ Name = 'PARITY'; Resiliency = 'Parity'; Columns = 3 }
    )
    foreach ($l in $layouts) {
        $vd = New-VirtualDisk -StoragePoolFriendlyName 'TRACEPOOL' -FriendlyName $l.Name `
            -ResiliencySettingName $l.Resiliency -NumberOfColumns $l.Columns `
            -ProvisioningType Fixed -Size 1GB
        $vdisk = $vd | Get-Disk
        $vol = Mount-NewVolume $vdisk 'NTFS' $l.Name
        $root = $vol.Root
        New-Item -ItemType Directory -Force "$root\Docs" | Out-Null
        [IO.File]::WriteAllText("$root\Docs\hello.txt", "Hello from the $($l.Name) space`r`n")
        $rng = [Random]::new($l.Columns * 7 + $l.Name.Length)
        $b = New-Object byte[] 50331648; $rng.NextBytes($b)
        [IO.File]::WriteAllBytes("$root\random-48MB.bin", $b)
        $entry = Get-FileKey $root
        $entry.Remove('deleted')
        $entry['resiliency'] = $l.Resiliency
        $entry['columns'] = $vd.NumberOfColumns
        $entry['interleave'] = $vd.Interleave
        $entry['copies'] = $vd.NumberOfDataCopies
        $entry['size'] = $vd.Size
        $entry['partition_offset'] = $vol.Partition.Offset
        $key.pool.spaces[$l.Name] = $entry
        Dismount-Volume $vol
    }
} finally {
    foreach ($m in $members) { Dismount-Vhdx $m }
}

$json = $key | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText((Join-Path $OutDir 'windows-volumes-key.json'), $json, [Text.UTF8Encoding]::new($false))
Write-Host "Done: $OutDir"
