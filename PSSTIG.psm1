# load private functions/classes
$PRIVATE_PATH = Join-Path $PSScriptRoot "Private"
$private_files = Get-ChildItem -Path $PRIVATE_PATH -File -Filter "*.ps1" -Recurse
foreach($file in $private_files){
    . $file.FullName
}

# load public functions/classes
$PRIVATE_PATH = Join-Path $PSScriptRoot "Public"
$private_files = Get-ChildItem -Path $PRIVATE_PATH -File -Filter "*.ps1" -Recurse
foreach($file in $private_files){
    . $file.FullName
}