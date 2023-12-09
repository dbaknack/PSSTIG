if(Get-Module "PSSTIG"){
    Remove-Module PSSTIG
}else{
    Import-Module ./PSSTIG.psm1
}