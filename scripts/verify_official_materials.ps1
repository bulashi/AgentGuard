param(
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputPath = [System.IO.Path]::GetFullPath($Output)
if (-not $outputPath.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $outputPath)) {
    throw 'Allocate a new evidence file inside this project.'
}
$sourceRecord = Get-Content -LiteralPath (Join-Path $root 'evidence/native-windows/release-20261008/official-source.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$archiveRecord = Get-Content -LiteralPath (Join-Path $root 'evidence/native-windows/release-20261008/official-archive.json') -Raw -Encoding UTF8 | ConvertFrom-Json

function Read-WordStream([System.IO.Stream]$Stream) {
    $package = [System.IO.Compression.ZipArchive]::new($Stream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        $entry = $package.GetEntry('word/document.xml')
        $reader = [System.IO.StreamReader]::new($entry.Open())
        try { $xmlText = $reader.ReadToEnd() } finally { $reader.Dispose() }
        [xml]$document = $xmlText
        $paragraphs = @($document.GetElementsByTagName('w:p') | ForEach-Object {
            (@($_.GetElementsByTagName('w:t') | ForEach-Object { $_.InnerText }) -join '')
        })
        return [pscustomobject]@{ Xml = $xmlText; Text = ($paragraphs -join "`n") }
    } finally { $package.Dispose() }
}

$share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
$stream = [System.IO.File]::Open($sourceRecord.path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
$archiveStream = [System.IO.File]::Open($archiveRecord.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $currentHash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
    $stream.Position = 0
    $current = Read-WordStream $stream
    $archiveHash = [BitConverter]::ToString($sha.ComputeHash($archiveStream)).Replace('-', '').ToLowerInvariant()
    $archiveStream.Position = 0
    $archive = [System.IO.Compression.ZipArchive]::new($archiveStream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        $entries = @($archive.Entries | Where-Object { $_.Name -like '*.docx' -and $_.Name -notlike '~*' })
        if ($entries.Count -ne 1) { throw 'Expected one official DOCX inside the original archive.' }
        $embedded = [System.IO.MemoryStream]::new()
        $entryStream = $entries[0].Open()
        try { $entryStream.CopyTo($embedded) } finally { $entryStream.Dispose() }
        try {
            $embedded.Position = 0
            $embeddedHash = [BitConverter]::ToString($sha.ComputeHash($embedded)).Replace('-', '').ToLowerInvariant()
            $embedded.Position = 0
            $original = Read-WordStream $embedded
            $passed = ($currentHash -eq $sourceRecord.sha256) -and ($archiveHash -eq $archiveRecord.Hash) -and ($current.Text -ceq $original.Text)
            $report = [ordered]@{
                status = $(if ($passed) { 'PASS' } else { 'FAIL' })
                checked_at_utc = [DateTime]::UtcNow.ToString('o')
                source_path = $sourceRecord.path
                current_docx_sha256 = $currentHash
                matches_recorded_source = ($currentHash -eq $sourceRecord.sha256)
                archive_path = $archiveRecord.Path
                archive_sha256 = $archiveHash
                matches_recorded_archive = ($archiveHash -eq $archiveRecord.Hash)
                zip_docx_sha256 = $embeddedHash
                document_xml_equal = ($current.Xml -ceq $original.Xml)
                paragraph_text_equal = ($current.Text -ceq $original.Text)
                scope = 'read_only_source_identity_and_paragraph_text_not_full_visual_equivalence'
                originals_modified = $false
            }
        } finally { $embedded.Dispose() }
    } finally { $archive.Dispose() }
} finally { $sha.Dispose(); $stream.Dispose(); $archiveStream.Dispose() }
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($outputPath)) | Out-Null
$report | ConvertTo-Json | Set-Content -LiteralPath $outputPath -Encoding UTF8
$report | ConvertTo-Json
if (-not $passed) { exit 1 }
