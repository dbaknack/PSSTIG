
Import-Module .\PSCONNECT

$PSCONNECT_PARAMS = @{
    SourceFolderName 	= "$env:HOMEPATH\Documents\Knowledge_Base\Sources_Library\PSCONNECT-Data"
    SourceFileName		= "HOSTDATA.csv"
}
$PSCONNECT = PSCONNECT @PSCONNECT_PARAMS
$PSCONNECT.GetHostData(@{ALL = $true}) | Format-Table -Autosize

$myCreds = Get-Credential
$PSCONNECT.StashCredentials(@{CredentialAlias = "DEVLAB";Credentials = $myCreds})

$PSCONNECT.CreateRemoteSession(@{use = "Hostname"})


$HOST_LIST = @(
)

$instanceResults = @()
foreach($hostItem in $HOST_LIST){
  $hostedInstanceList = Invoke-PSCMD @{
        Session                 = @(Get-PSSession -name $hostItem)
        PowerShellScriptFolder  = ".\PSSTIG\Test"
        PowerShellScriptFile    = "Test"
        ArgumentList            = @("")
        AsJob                   = $false
    }


    foreach($hostResult in $hostedInstanceList.keys){
        foreach($entry in $hostedInstanceList.$hostResult){
            ("{0},{1}" -f $hostItem,$instanceParams.instance_name)
            $instanceParams = $entry
            $instanceResults+= Invoke-PSSQL @{
                Session             =   @(Get-PSSession -name $hostItem)
                SQLScriptFolder     =   ".\PSSTIG\Test\"
                SQLScriptFile       =   "GetSQLSessionProperties"
                ConnectionParams    = @{
                InstanceName    =   $instanceParams.instance_name
                DatabaseName    =   "Master"
                }
            }
        }
    }
}


$instanceResults.rows | ConvertTo-Csv -NoTypeInformation  | clip.exe
