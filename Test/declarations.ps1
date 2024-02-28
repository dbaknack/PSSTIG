$ErrorActionPreference = 'STOP'
Import-Module .\PSUTILITIES
Import-Module .\PSSTIG      ; $PSSTIG    = PSSTIG
Import-Module .\PSCONNECT


<#
    Remove-Module PSSTIG
    Remove-Module PSUTILITIES
    Remove-Module PSCONNECT
#>

# runs the set up when first using tool
$PSSTIG.Initalize(@{
    ParentFolderPath    = '.\PSSTIG\Data'
    DataSource          = 'SQLServerInstance'
})

# runs the set up when first using tool
$PSSTIGVIEWER = PSSTIGVIEWER
$PSSTIGVIEWER.Initalize(@{ExePath = "$STIGVIEWERPATH\STIG Viewer 3.exe"})
$PSSTIGVIEWER.StartStigViewer()
$PSSTIGVIEWER.StopStigViewer()
$PSSTIGVIEWER.RestartStigViewer()


#   You might have used an incorrect password when defining the credentail and
#------------------------------------------------------------------------------------
$PSCONNECT      = (PSCONNECT)
$myCreds        = Get-Credential
$myCredAlias    = "DEV-ADM" 

$PSCONNECT.StashCredentials(@{CredentialAlias = "DEV-ADM";Credentials     = $myCreds})
$PSCONNECT.RemoveStashCredentials(@{CredentialAlias = $myCredAlias})
$PSCONNECT.GetStashedCredentials(@{CredentialAlias = $myCredAlias})
$PSCONNECT.GetHostData(@{All = $false})
$PSCONNECT.CreateRemoteSession(@{Use = "Alias"})
Get-PSSession

# 4.0 -   define levels
# how these are filtered needs to be reworked, but its ok for the moment...
#------------------------------------------------------------------------------------
$InstanceLevelParams = $PSSTIG.MyHostDataSet(@{DataSource = "SQLServerInstance";Level = "Instance"})
$InstanceLevelParams.Count

# 5.0 -   perform checks
#----------------------------------------------------------------------------------------#1
# Tested - good
$findingID = 'V-213988'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams  = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        SourceDataFrom  = $PSSTIG.Configuration.Files.ServerAdminAccountsList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        CheckListType   = $InstanceLevelParam.CheckListType
        DisplayStatus   = $true
    }
    Invoke-Finding213988  @FunctionParams
}
#----------------------------------------------------------------------------------------#2
$findingID = 'V-213987'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        SourceDataFrom  = $PSSTIG.Configuration.Files.SQLRoleMembersList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding213987 @FunctionParams
}
#----------------------------------------------------------------------------------------#3
$findingID = 'V-214045'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214045 @FunctionParams
}
#----------------------------------------------------------------------------------------#4
$findingID = 'V-214042'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        $HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        SourceDataFrom  = $PSSTIG.Configuration.Files.SQLRoleMembersList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214042 @FunctionParams
}
#----------------------------------------------------------------------------------------#5
$findingID = 'V-214043'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        SourceDataFrom  = $PSSTIG.Configuration.Files.SQLRoleMembersList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214043 @FunctionParams
}
#----------------------------------------------------------------------------------------#6
$findingID = 'V-214044'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214044 @FunctionParams
}
#----------------------------------------------------------------------------------------#7
$findingID = 'V-214041'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214041 @FunctionParams
}
# ----------------------------------------------------------------------------------------#8
$findingID = 'V-214040'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214040 @FunctionParams
}
# ----------------------------------------------------------------------------------------#9
$findingID = 'V-214039'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214039 @FunctionParams
}
# ----------------------------------------------------------------------------------------#10
$findingID = 'V-214038'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214038 @FunctionParams
}
# ----------------------------------------------------------------------------------------#11
$findingID = 'V-214037'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214037 @FunctionParams
}
# ----------------------------------------------------------------------------------------#12
$findingID = 'V-214036'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214036 @FunctionParams
}
# ----------------------------------------------------------------------------------------#13
$findingID = 'V-214035'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214035 @FunctionParams
}
# ----------------------------------------------------------------------------------------#14
$findingID = 'V-214034'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214034 @FunctionParams
}
# ----------------------------------------------------------------------------------------#15
$findingID = 'V-214033'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214033 @FunctionParams
}
# ----------------------------------------------------------------------------------------#16
$findingID = 'V-214032'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214032 @FunctionParams
}
# ----------------------------------------------------------------------------------------#17
$findingID = 'V-214031'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214031 @FunctionParams
}
# ----------------------------------------------------------------------------------------#18
$findingID = 'V-214030'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214030 @FunctionParams
}
# ----------------------------------------------------------------------------------------#19
$findingID = 'V-214029'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214029 @FunctionParams
}
# ----------------------------------------------------------------------------------------#20
$findingID = 'V-214028'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214028 @FunctionParams
}
# ----------------------------------------------------------------------------------------#21
$findingID = 'V-214027'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214027 @FunctionParams
}
# ----------------------------------------------------------------------------------------#22
$findingID = 'V-214026'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214026 @FunctionParams
}
# ----------------------------------------------------------------------------------------#23
$findingID = 'V-214025'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        CheckListName               = $InstanceLevelParam.CheckListName
        DocumentationFolderPath     = ".\PSSTIG\Documentation"
        DisplayStatus               = $true
    }
    Invoke-Finding214025 @FunctionParams
}
# ----------------------------------------------------------------------------------------#24
$findingID = 'V-214024'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214024 @FunctionParams
}
# ----------------------------------------------------------------------------------------#25
$findingID = 'V-214023'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214023 @FunctionParams
}
# ----------------------------------------------------------------------------------------#26
$findingID = 'V-214021'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214021 @FunctionParams
}
# ----------------------------------------------------------------------------------------#27
$findingID = 'V-214018'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214018 @FunctionParams
}
# ----------------------------------------------------------------------------------------#28
$findingID = 'V-214017'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214017 @FunctionParams
}
# ----------------------------------------------------------------------------------------#29
$findingID = 'V-214016'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214016 @FunctionParams
}
# ----------------------------------------------------------------------------------------#30
$findingID = 'V-214015'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214015 @FunctionParams
}
# ----------------------------------------------------------------------------------------#31
$findingID = 'V-214014'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214014 @FunctionParams
}
# ----------------------------------------------------------------------------------------#32
$findingID = 'V-214012'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214014 @FunctionParams
}
# ----------------------------------------------------------------------------------------#33
$findingID = 'V-214010'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214010 @FunctionParams
}
# ----------------------------------------------------------------------------------------#34
$findingID = 'V-214008'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214008 @FunctionParams
}
# ----------------------------------------------------------------------------------------#35
$findingID = 'V-214006'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214006 @FunctionParams
}
# ----------------------------------------------------------------------------------------#36
$findingID = 'V-214004'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214004 @FunctionParams
}
# ----------------------------------------------------------------------------------------#37
$findingID = 'V-214002'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214002 @FunctionParams
}
# ----------------------------------------------------------------------------------------#38
$findingID = 'V-214000'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214000 @FunctionParams
}
# ----------------------------------------------------------------------------------------#39
$findingID = 'V-213998'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213998 @FunctionParams
}
# ----------------------------------------------------------------------------------------#40
$findingID = 'V-213994'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213994 @FunctionParams
}
# ----------------------------------------------------------------------------------------#41
$findingID = 'V-213929'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName

        # where ever this happes to be, it will be created.
        $FolderPath                  = "$env:HOMEPATH\Documents\Knowledge_Base\Sources_Library"
        $FileName                    = "\Niper - Concurrent Sessions Per User.csv"
        DisplayStatus               = $true
    }
    Invoke-Finding213929 @FunctionParams
}
# ----------------------------------------------------------------------------------------#42
$findingID = 'V-213969'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName

        DisplayStatus               = $true
    }
    Invoke-Finding213969 @FunctionParams
}
# ----------------------------------------------------------------------------------------#43
$findingID = 'V-213968'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName

        DisplayStatus               = $true
    }
    Invoke-Finding213968 @FunctionParams
}
# ----------------------------------------------------------------------------------------#44
$findingID = 'V-213967'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName

        DisplayStatus               = $true
    }
    Invoke-Finding213967 @FunctionParams
}
# ----------------------------------------------------------------------------------------#45
$findingID = 'V-213934'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213934 @FunctionParams
}
# ----------------------------------------------------------------------------------------#46
$findingID = 'V-214020'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214020 @FunctionParams
}
# ----------------------------------------------------------------------------------------#47
$findingID = 'V-213995'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213995 @FunctionParams
}
# ----------------------------------------------------------------------------------------#48
$findingID = 'V-213993'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        # where ever this happes to be, it will be created.
        FolderPath                  = "$env:HOMEPATH\Documents\Knowledge_Base\Sources_Library"
        FileName                    = "\Niper - SQLServer Installed Features.csv"
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213993 @FunctionParams
}
# ----------------------------------------------------------------------------------------#49
$findingID = 'V-213930'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        # where ever this happes to be, it will be created.
        FolderPath                  = "$env:HOMEPATH\Documents\Knowledge_Base\Sources_Library"
        FileName                    = "\Niper - Approved SQLLogins List.csv"
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213930 @FunctionParams
}

# ----------------------------------------------------------------------------------------#50
$findingID = 'V-213935'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213935 @FunctionParams
}
# ----------------------------------------------------------------------------------------#51
$findingID = 'V-213991'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        FolderPath                  = "$env:HOMEPATH\Documents\Knowledge_Base\Sources_Library"
        FileName                    = "\Niper - Intances with CLR Configured.csv"
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213991 @FunctionParams
}
# ----------------------------------------------------------------------------------------#52
# run this twice
$findingID = 'V-213992'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        FolderPath                  = "$env:HOMEPATH\Documents\Knowledge_Base\Sources_Library"
        FileName                    = "\Niper - SQL Services and Service Accounts.csv"
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213992 @FunctionParams
}
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        FolderPath                  = "$env:HOMEPATH\Documents\Knowledge_Base\Sources_Library"
        FileName                    = "\Niper - SQL Services and Service Accounts.csv"
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213992 @FunctionParams
}
# ----------------------------------------------------------------------------------------#53

$findingID = 'V-213990'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        FolderPath                  = "$env:HOMEPATH\Documents\Knowledge_Base\Sources_Library"
        FileName                    = "\Niper - SQL Server NetInfo.csv"
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213990 @FunctionParams
}
# ----------------------------------------------------------------------------------------#54

$findingID = 'V-213965'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        FolderPath                  = "$env:HOMEPATH\Documents\Knowledge_Base\Sources_Library"
        FileName                    = "\Niper - SQL Server NetInfo.csv"
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213965 @FunctionParams
}
# ----------------------------------------------------------------------------------------#55
$findingID = 'V-213956'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        FolderPath                  = "$env:HOMEPATH\Documents\Knowledge_Base\Sources_Library"
        FileName                    = "\Niper - Server Installed Software.csv"
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding213956 @FunctionParams
}
# ----------------------------------------------------------------------------------------#56
$findingID = 'V-213954'
$InstanceLevelParams = $InstanceLevelParams | Select-Object -Property * | Where-Object {$_.HostName -eq 'DEV-SQL01'}
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
        SkipNonFinding             = $false
    }
    Invoke-Finding213954 @FunctionParams
}




# <<- <<- <<- |- Query -| ->> ->> ->> ->> #

$STIGQUERY = [STIGQUERY]::new()
$STIGQUERY.Select(@{
    SourceFolder    = @("C:\Users\abrah\Documents\Knowledge_Base\Sources_Library\")
    SourceFile      = "Niper - SQL Server NetInfo"
    Table           = $true
})

$STIGQUERY.Update(@{
    Reload          = $true
    SourceFolder    = @("C:\Users\abrah\Documents\Knowledge_Base\Sources_Library\")
        SourceFile      = "Niper - SQL Server NetInfo"
        Filter          = @{
            HostName        = "DEV-SQL01"
            InstanceName    = "SANDBOX01"
        }
        Set             = @{
            isApproved      = "Dynamic"
            ApprovedPort    = "1433" 
        }
})



# here we pass in a list of sessions in to run a given command, with a set of parameters
Invoke-PSCMD @{
    Session                 = $Sessions[0]
    PowerShellScriptFolder  = ".\PSSTIG\Private\Functions"
    PowerShellScriptFile    = "V-213966"
    ArgumentList            = @("SANDBOX01")
    AsJob                   = $false
};$results


$results = Get-Job | Receive-Job -Wait  | Group-Object -Property "pscomputerName" -AsHashTable ; Get-Job | Remove-Job
$results.Values

# here we pass in one session with a set of parameters
Invoke-PSCMD @{
    Session                 = @($Sessions[1])
    PowerShellScriptFolder  = "./POWERSHELLPLAYGROUND/PowerShellScripts"
    PowerShellScriptFile    = "GetFolders"
    ArgumentList            = @("C:\")
    AsJob                   = $true
}
$results = Get-Job | Receive-Job -Wait  | Group-Object -Property "pscomputerName" -AsHashTable ; Get-Job | Remove-Job
$results.values

# here we pass is a session, but not as a job
$results = Invoke-PSCMD @{
    Session                 = @($Sessions[1])
    PowerShellScriptFolder  = "./POWERSHELLPLAYGROUND/PowerShellScripts"
    PowerShellScriptFile    = "GetFolders"
    ArgumentList            = @("C:\")
    AsJob                   = $false
};$results