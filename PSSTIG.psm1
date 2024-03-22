# load public functions/classes
$PUBLIC_PATH    = Join-Path $PSScriptRoot "Public"
$public_files   = Get-ChildItem -Path $PUBLIC_PATH -File -Filter "*.ps1" -Recurse
foreach($file in $public_files){
    . $file.FullName
}