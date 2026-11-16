# Deletes only self-created files inside target; never a Windows/user cache.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$work=Join-Path $root ('target/thumbnail-fixtures/'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $root 'embedded/WinStateDiag/ThumbnailCleanup.cs')))
$n=0
function Check($yes,$label){if(!$yes){throw $label};$script:n++}
function File($name,$body='CMMM fixture content'){ $p=Join-Path $work $name;[IO.File]::WriteAllText($p,$body,[Text.Encoding]::ASCII);$p }
$p=File 'thumbcache_1.db'
$item=[WinDiagThumbnailCleanup]::Inspect($work,$p,'','',$false)
Check ([IO.File]::Exists($p)) 'analysis retains source'
Check ($item.Hash.Length -eq 64 -and $item.Bytes -gt 4) 'hash and size available'
[IO.File]::AppendAllText($p,'changed')
$rejected=$false;try{[void][WinDiagThumbnailCleanup]::Inspect($work,$p,$item.Hash,$item.Identity,$true)}catch{$rejected=$true}
Check ($rejected -and [IO.File]::Exists($p)) 'changed file preserved'
$item=[WinDiagThumbnailCleanup]::Inspect($work,$p,'','',$false)
$r=[WinDiagThumbnailCleanup]::Inspect($work,$p,$item.Hash,$item.Identity,$true)
Check ($r.Deleted -and ![IO.File]::Exists($p)) 'selected fixture removed by handle'
$p=File 'thumbcache_2.db'
$held=[IO.File]::Open($p,'Open','ReadWrite','None')
try{$rejected=$false;try{[void][WinDiagThumbnailCleanup]::Inspect($work,$p,'','',$false)}catch{$rejected=$true};Check $rejected 'locked file rejected'}finally{$held.Dispose()}
$p=File 'document.txt'
$rejected=$false;try{[void][WinDiagThumbnailCleanup]::Inspect($work,$p,'','',$false)}catch{$rejected=$true}
Check ($rejected -and [IO.File]::Exists($p)) 'document preserved'
$p=File 'thumbcache_false.db' 'PRIVATE DOCUMENT'
$rejected=$false;try{[void][WinDiagThumbnailCleanup]::Inspect($work,$p,'','',$false)}catch{$rejected=$true}
Check ($rejected -and [IO.File]::Exists($p)) 'unknown content rejected'
$p=File 'thumbcache_hardlink.db'
$link=Join-Path $work 'hardlink.db'
[void](New-Item -ItemType HardLink -Path $link -Target $p -ErrorAction Stop)
$rejected=$false;try{[void][WinDiagThumbnailCleanup]::Inspect($work,$p,'','',$false)}catch{$rejected=$true}
Check ($rejected -and [IO.File]::Exists($p) -and [IO.File]::Exists($link)) 'hardlinks preserved'
$outside=Join-Path (Split-Path $work -Parent) 'thumbcache_outside.db'
[IO.File]::WriteAllText($outside,'CMMM outside fixture')
$rejected=$false;try{[void][WinDiagThumbnailCleanup]::Inspect($work,$outside,'','',$false)}catch{$rejected=$true}
Check ($rejected -and [IO.File]::Exists($outside)) 'outside root preserved'
# Junction fixture targets only this same project fixture directory.
$junction=Join-Path $work 'junction'
[void](New-Item -ItemType Junction -Path $junction -Target $work -ErrorAction Stop)
$rejected=$false;try{[void][WinDiagThumbnailCleanup]::Inspect($junction,(Join-Path $junction 'thumbcache_2.db'),'','',$false)}catch{$rejected=$true}
Check ($rejected -and [IO.File]::Exists((Join-Path $work 'thumbcache_2.db'))) 'reparse ancestor rejected'
'PASS thumbnail fixture assertions: '+$n+'; real user caches untouched; fixtures retained'
