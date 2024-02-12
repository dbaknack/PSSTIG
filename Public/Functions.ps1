#-------------------------------------------------> [ module utilities ]
Function Get-MyModulePath {
    $PSScriptRoot_String = $PSScriptRoot
    $PathStringLength = ($PSScriptRoot_String).Length
    # this removed the reference to the private folder
    $ModulePath  = $PSScriptRoot_String.Substring(0,($PathStringLength -7))
    $ModulePath
}
Function PSSTIG {
    $PSSTIG =  [PSSTIG]::new()
    $PSSTIG
}
Function Get-SqlInstances{

    Param($ServerName = [System.Net.Dns]::GetHostName())
   
 
    $LocalInstances = @()
 
    [array]$Captions = Get-WmiObject win32_service -ComputerName $ServerName |
      Where-Object {
        $_.Name -match "mssql*" -and
        $_.PathName -match "sqlservr.exe"
      } |
        ForEach-Object {$_.Caption}
 
    foreach ($Caption in $Captions) {
      if ($Caption -eq "MSSQLSERVER") {
        $LocalInstances += "MSSQLSERVER"
      } else {
        $Temp = $Caption |
          ForEach-Object {$_.split(" ")[-1]} |
          ForEach-Object {$_.trimStart("(")} |
            ForEach-Object {$_.trimEnd(")")}
 
        $LocalInstances += "$ServerName\$Temp"
      }
 
    }
 
     $instance_names_list = @()
     $instance_ruid = 1
    foreach($localinstance_name in $LocalInstances){
      # if the instance name is not a named instance, this condition will be true
      if($localinstance_name -match '(.*)\\(MSSQLSERVER)'){
         $instance_names_list += [pscustomobject]@{
          id = $instance_ruid
          host_name = $ServerName
          instance_type = 'unnamed'
          instance_name = $matches[1]
          }
      }else{
          $instance_names_list += [pscustomobject]@{
              id = $instance_ruid
              host_name = $ServerName
              instance_type = 'named'
              instance_name =  $localinstance_name
          }
      }
      $instance_ruid = $instance_ruid + 1
    }
    $instance_names_list | Group-Object -Property host_name -AsHashTable
}
Function PSSTIGVIEWER{
    $PSSTIGVIEWER = [PSSTIGVIEWER]::new()
    $PSSTIGVIEWER
}
Function PSSTIGMANUAL{
    $PSSTIGMANUAL = [PSSTIGMANUAL]::new()
    $PSSTIGMANUAL
}
Function Invoke-UDFSQLCommand{
    param(
        [hashtable]$Query_Params
    )

    $processname = 'Invoke-UDFSQLCommand'
    $myQuery = "{0}" -f $Query_Params.Query
    $sqlconnectionstring = "
        server                          = $($Query_Params.InstanceName);
        database                        = $($Query_Params.DatabaseName);
        trusted_connection              = true;
        application name                = $processname;"
    # sql connection, setup call
    $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
    $sqlconnection.connectionstring = $sqlconnectionstring
    $sqlconnection.open()
    $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
    $sqlcommand.connection          = $sqlconnection
    $sqlcommand.commandtext         = $myQuery
    # sql connection, handle returned results
    $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
    $sqladapter.selectcommand       = $sqlcommand
    $dataset                        = new-object system.data.dataset
    $sqladapter.fill($dataset) | out-null
    $resultsreturned                = $null
    $resultsreturned               += $dataset.tables
    $sqlconnection.close()      # the session opens, but it will not close as expected
    $sqlconnection.dispose()    # TO-DO: make sure the connection does close
    $resultsreturned
}
Function Get-TargetData{
    param(
        [string]$CheckListName,
        [psobject]$Session
    )
    $myCheckListFolderPath  = $PSSTIG.Configuration.Folders.CheckLists.Path
    $myCheckListFile        = Get-ChildItem -Path $myCheckListFolderPath -Filter "$CheckListName.cklb"

    $myCheckListData = $PSSTIG.GetCheckListData(@{
        CheckListName = $CheckListName
    })

    $technologyArea = switch(($PSSTIG.PlatformParameters.OS)){
        "onWindows" {"Windows OS"}
    }

    $myResults = Invoke-Command -Session $Session -ScriptBlock {
        $MACAddress     = (Get-NetAdapter)[0] | Select-Object MacAddress
        $IPv4           = (Get-NetIPConfiguration)[0] | Select-Object IPv4Address
        $FQDN           = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName
        $HostName       = HostName
        $myResults = @{
            MACAddress = $MACAddress
            IPV4        = $IPv4
            FQDN        = $FQDN
            HostName    = $HostName
        }
        $myResults
    }
    $myResults.Add("TechnologyArea",$technologyArea)

    $myTargetData                   = $myCheckListData.target_data
    $myTargetData.host_name         = $myResults.HostName
    $myTargetData.ip_address          = $myResults.IPV4.IPv4Address.IPAddress
    $myTargetData.mac_address       = $myResults.MACAddress.MacAddress
    $myTargetData.technology_area   = $technologyArea
    $myTargetData.fqdn              = $myResults.FQDN
    $myCheckListData.target_data    = $myTargetData

    $myCheckListDataConverted = $myCheckListData | ConvertTo-Json -Depth 5
    Set-Content -path  $myCheckListFile.FullName -Value $myCheckListDataConverted
}

Function Get-PSTIGModuleLocation{
    $myFunctionsPath = $PSCommandPath
    #TODO: on mac you wont be able to split on that separator
    $mySeparator = '\'
    $pathList = $myFunctionsPath.Split($mySeparator)
    $pathListCount = ($PathList.count -3)

    $modulePathList = @()
    foreach($pathItem in 0..$pathListCount){
        $modulePathList += $pathList[$pathItem]
    }
    $modulePathList -join $mySeparator
}

#-------------------------------------------------> [ audit functions ]
Function Invoke-Finding213988{
    param(
        [string]$Hostname,
        [string]$FindingID,
        [psobject]$Session,
        [string]$SourceDataFrom,
        [string]$CheckListName,
        [string]$CheckListType,
        [switch]$DisplayStatus
    )
   
    $FUNCTION_NAME  = "Invoke-Finding213988"
    # this host has issues with the cmdlet, not sure why
    if($Hostname -eq "PETERESNSWSQL01"){
        $results = net localgroup administrators
        $results = $results -split "`n" | Select-Object -Skip 6
        $newResults = @()
        foreach($result in $results){
            if(($result -ne 'The command completed successfully.')){
               $newResults += $result
            }
        }
        $finalResults = @()
        foreach($result in $newResults){
            if(($result -ne '')){
               $finalResults += $result
            }
        }
        $groupResults = @()
        foreach($finalResult in $finalResults){
            $groupResults += [pscustomobject]@{Name = $finalResult ; PrincipalSource = 'ActiveDirectory'}
        }
    }else{
        $groupResults  = Invoke-Command -Session $Session -ScriptBlock {Get-LocalGroupMember -Group "Administrators"}
    }
    if(-not(Test-Path -Path $SourceDataFrom)){
        New-Item -ItemType File -Path $SourceDataFrom | Out-Null
    }
    $myContent      = Get-Content -path $SourceDataFrom | ConvertFrom-Csv -Delimiter ","
    $headingString  = [string]
    $myHostName     = Invoke-Command -Session $Session -ScriptBlock {hostname}
    $headingsList   = @("RecordID","HostName","Name","PrincipalSource","Description")
    $headingString  ='"{0}"' -f ($headingString = $headingsList -join '","')


    if(0 -eq [int]$myContent.count){
        Add-Content -Path $SourceDataFrom -Value $headingString
    }

    if(0 -eq [int]$myContent.count){
        [int]$recordID = 1
    }else{
        [int]$recordID = [int]$myContent.RecordID[-1]+1
    }
   
    $myEntriesList  = @()
    foreach($accountName in $groupResults){
        $entryString    = [string]
        $myEntry        = @("$recordID","$myHostName","$($accountName.Name)","$($accountName.PrincipalSource)","NULL")
        $entryString    =  '"{0}"'-f ($entryString = $myEntry -join '","')
        $myEntriesList += $entryString
        $recordID       = ($recordID) + 1
    }
   
    $newEntriesList         = $myEntriesList | ConvertFrom-Csv -Header $headingsList
    $myCurrenEntriesTable   = $myContent | Group-Object -Property 'HostName' -AsHashTable

    $findingStatus          = "not_a_finding"
    $nullDescriptionList    = @()
    $noEntryExistsList      = @()
    $noAccountNameExistList = @()
    foreach($newEntry in $newEntriesList){
        $newEntryHostName = $newEntry.HostName
        $currentEntriesObject = $myCurrenEntriesTable.$newEntryHostName
       
       
        # are there entries for this hostname?
        $HostNameEntryExists = [bool]
        if($currentEntriesObject.HostName.count -eq 0){
            $HostNameEntryExists = $false
        }else{
            $HostNameEntryExists = $true
        }

        # if the entry doesnt already exist, then it gets added
        if(-not($HostNameEntryExists)){
            $myEntry = ('"{0}","{1}","{2}","{3}","{4}"' -f
                $newEntry.RecordID,
                $newEntry.HostName,
                $newEntry.Name,
                $newEntry.PrincipalSource,
                $newEntry.Description)
            Add-Content -Path $SourceDataFrom -Value $myEntry
            $findingStatus      = "open"
            $noEntryExistsList += [pscustomobject]@{HostName = $newEntry.HostName ; Name = $newEntry.Name}
        }
        # is the name of the account in the list?
        $accountNameExists = [bool]
        if(-not($currentEntriesObject.Name -contains $newEntry.Name)){
            $accountNameExists = $false
        }else{
            $accountNameExists = $true
        }

        if( $accountNameExists -eq $false){
            $findingStatus          = "open"
            $noAccountNameExistList += [pscustomobject]@{HostName = $newEntry.HostName ; Name = $newEntry.Name}
        }

        $currentEntryCheck = $currentEntriesObject |
            Select-Object -Property @('Name','Description') |
            Where-Object {$_.Name -eq ($newEntry.name)}

        $entryDescriptionIsNUll = $currentEntryCheck.Description -match 'NULL'
       
        if($entryDescriptionIsNUll){
            $findingStatus          = "open"
            $nullDescriptionList += [pscustomobject]@{HostName = $newEntry.HostName ; Name = $newEntry.Name}
        }
    }

    $checkedBy      = "{0} {1}" -f "Check performed by:",$env:USERNAME
    $dateChecked    = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $myCommentList = @()
    if($findingStatus -eq "open"){
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Remarks:'
        $myCommentList += "'$SourceDataFrom' is used to document all admin account for '$($myHostName)'."
        $myCommentList += "All account need to be documented with a description, the following account are missing a description:"
        $myCommentList += ' '
        foreach($nullValue in $nullDescriptionList){
            $myCommentList +=  "   Host - '$($nullValue.HostName)', admin account '$($nullValue.Name)' is not documentend."
        }
    }else{
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Remarks:'
        $myCommentList += "'$SourceDataFrom' is used to document all admin account for '$($myHostName)'."
        $myCommentList += "All account need to be documented with a description, the following account are missing a description:"
    }
   
   
    $PSSTIG.UpdateComment(@{
        CheckListName   = $CheckListName
        FindingID       = $FindingID
        Comment         = ($myCommentList -join "`n")
    })
   
    $PSSTIG.UpdateStatus(@{
        CheckListName   = $CheckListName
        FindingID       = $FindingID
        Status          = $findingStatus
    })

    $updatedTargetData = [bool]
    try{
        $updatedTargetData = $true
        Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
    }catch{
        $updatedTargetData = $false
    }

    if($updatedTargetData -eq $false){
        $PSSTIG.PSUTILITIES.DisplayMessage(@{
            Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
            Category = "feedback"
            Type = "warning"
        })
    }

    if($DisplayStatus){
        $PSSTIG.GetFindingInfo(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
    }
}
Function Invoke-Finding213987{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$SourceDataFrom,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )

    $FUNCTION_NAME = "Invoke-Finding213987"
    $myScripts = $PSSTIG.GetSQLQuery(@{
        FindingID = $FindingID
    })
    # this script is not working in terms of its definiton as a query param, string is used instead for now
    #$principalsScript   = $myScripts['script_01']
   


    $instanceNameList   = $CheckListName -split '_'
    $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

    # run first check
    $SQLCommandParams = @{
        DatabaseName    = "master"
        InstanceName    = $instanceName
        Query           = @'

        -- table for final results
        declare @finalAssesment table (
            CheckResult         int,            -- either 1 for a finding 0 for not a finding
            ResultValue         nvarchar(100),  -- what value was evaluated
            ResultDescripton    nvarchar(100)   -- check description
        )
                       
        declare
            @finding_condition_met  int
            ,@CheckResult           int
            ,@ResultValue           varchar(100)
            ,@ResultDescripton      varchar(100)
       
        -- finding condition is initalized to 0
        set @finding_condition_met = 0
       
        -- filter out internal system only principals
        ;with cte_Principals as
        (
            select *
            from (
                select *
                from (
                    SELECT p.name AS Principal,
                    p.type_desc AS Type,
                    sp.permission_name AS Permission,  
                    sp.state_desc AS State
                    FROM sys.server_principals p
                    INNER JOIN sys.server_permissions sp ON p.principal_id = sp.grantee_principal_id
                    WHERE sp.permission_name = 'CONTROL SERVER'
                    OR sp.state = 'W'
                ) MyPrincipals
                where Principal not like ('##MS_SchemaSigningCertificate%')
            ) FilteredLikePrincipal
            where Principal not in (
                '##MS_AgentSigningCertificate##'
               ,'##MS_PolicySigningCertificate##'
               ,'##MS_SmoExtendedSigningCertificate##'
               ,'##MS_SQLAuthenticatorCertificate##'
               ,'##MS_SQLReplicationSigningCertificate##'
               ,'##MS_SQLResourceSigningCertificate##'
            )
        )
        select @ResultValue = (count(*))
        from cte_Principals
       
        if(@ResultValue) != '0'
        begin
            set @finding_condition_met  = 1
            set @ResultDescripton       = 'Principal other than internal ones has control server permissions.'
        end
        else
        begin
            set @ResultDescripton       = 'No other principal other than internal ones, have control server permissions.'
        end
       
        insert into @finalAssesment
        Select
             [CheckResult]      = @finding_condition_met
            ,[ResultValue]      = @ResultValue
            ,[ResultDescripton] = @ResultDescripton
       
        select * from @finalAssesment
'@
    }

    # check 1
    $reachedInstance = [bool]
    $findingStatus   = "not_a_finding"
    $myCommentList   = @()
    $checkedBy      = "{0} {1}" -f "Check performed by:",$env:USERNAME
    $dateChecked    = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    try{
        $reachedInstance = $true
        $checkResults = Invoke-Command -Session $session -ScriptBlock ${Function:Invoke-UDFSQLCommand} -ArgumentList $SQLCommandParams -ErrorAction Stop
    }catch{
        $reachedInstance = $false
    }
   

    if($reachedInstance -eq $false){
        $findingStatus = "open"
         $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Remarks:'
            $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."

            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($myCommentList -join "`n")
            })
           
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
       
            if($DisplayStatus){
                $PSSTIG.GetFindingInfo(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                })
            }
    }else{
        $myCheckResults = @(
            [pscustomobject]@{Results = $checkResults.Rows.CheckResult ; ResultValue = $checkResults.Rows.ResultValue; ResultDescripton = $checkResults.Rows.ResultDescripton}
        )
   
        if($myCheckResults.Results -eq 1){
            $findingStatus = "open"
        }
   
        if($myCheckResults.Results -eq 0){
            $findingStatus = "not_a_finding"
        }
   
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Remarks:'
        $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescripton, "There is a total of '$($myCheckResults.ResultValue)' accounts that need to be addressed.")
        #$myCommentList += "'$SourceDataFrom' is used to document all sql logins that are memebers of 'sysadmin','securityadmin', or 'serveradmin' roles for instance '$($instanceName)'."

        $adminRoleScript    = $myScripts['script_02']
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = $adminRoleScript
        }
   
        $checkResults   = Invoke-Command -Session $session -ScriptBlock ${Function:Invoke-UDFSQLCommand} -ArgumentList $SQLCommandParams
        $myContent      = @(Get-Content -path $SourceDataFrom | ConvertFrom-Csv -Delimiter ",")
        $headingString  = [string]
        $headingsList   = @("RecordID","InstanceName","Memeber","Type","Role","Description")
        $headingString  ='"{0}"' -f ($headingString = $headingsList -join '","')
   
        if(0 -eq [int]$myContent.count){
            Add-Content -Path $SourceDataFrom -Value $headingString
        }
   
        if(0 -eq [int]$myContent.count){
            [int]$recordID = 1
        }else{
            [int]$recordID = [int]$myContent.RecordID[-1]+1
        }
       
        $myEntriesList  = @()
        foreach($accountName in $checkResults){
            $entryString    = [string]
            $myEntry        = @("$recordID","$($accountName.InstanceName)","$($accountName.Member)","$($accountName.Type)","$($accountName.Role)","$($accountName.Description)")
            $entryString    =  '"{0}"'-f ($entryString = $myEntry -join '","')
            $myEntriesList += $entryString
            $recordID       = ($recordID) + 1
        }
   
        $newEntriesList         = $myEntriesList | ConvertFrom-Csv -Header $headingsList
        $myCurrenEntriesTable   = $myContent | Group-Object -Property 'InstanceName' -AsHashTable
   
        $nullDescriptionList    = @()
        $noEntryExistsList      = @()
        $noAccountNameExistList = @()
        foreach($newEntry in $newEntriesList){
            $newEntryInstanceName = $newEntry.InstanceName
            $currentEntriesObject = $myCurrenEntriesTable.$newEntryInstanceName
           
            # are there entries for this hostname?
            $instanceNameEntryExists = [bool]
            if($currentEntriesObject.InstanceName.count -eq 0){
                $instanceNameEntryExists = $false
            }else{
                $instanceNameEntryExists = $true
            }
   
            # if the entry doesnt already exist, then it gets added
            if(-not($instanceNameEntryExists)){
                $myEntry = ('{0},"{1}","{2}","{3}","{4}","{5}"' -f
                    $newEntry.RecordID,
                    $newEntry.InstanceName,
                    $newEntry.Memeber,
                    $newEntry.Type,
                    $newEntry.Role,
                    $newEntry.Description)
                Add-Content -Path $SourceDataFrom -Value $myEntry
                $findingStatus      = "open"
                $noEntryExistsList += [pscustomobject]@{InstanceName = $newEntry.InstanceName ; Memeber = $newEntry.Memeber}
            }
            # is the name of the account in the list?
            $accountNameExists = [bool]
            if(-not($currentEntriesObject.Memeber -contains $newEntry.Memeber)){
                $accountNameExists = $false
            }else{
                $accountNameExists = $true
            }
   
            if( $accountNameExists -eq $false){
                $findingStatus          = "open"
                $noAccountNameExistList += [pscustomobject]@{InstanceName = $newEntry.InstanceName ; Memeber = $newEntry.Memeber}
            }
   
            $currentEntryCheck = $currentEntriesObject |
                Select-Object -Property @('Memeber','Description') |
                Where-Object {$_.Memeber -eq ($newEntry.Memeber)}
   
            $entryDescriptionIsNUll = $currentEntryCheck.Description -match 'NULL'
           
            if($entryDescriptionIsNUll){
                $findingStatus          = "open"
                $nullDescriptionList += [pscustomobject]@{InstanceName = $newEntry.InstanceName ; Memeber = $newEntry.Memeber}
            }
        }
   
        if($findingStatus -eq "open"){
            if($nullDescriptionList.count -gt 0){
                $myCommentList += "All members need to be documented with a description, the following members are missing a description:"
                $myNullMembersList = ($nullDescriptionList | Select-Object -Property Memeber).Memeber
                $myMembersString = @()
                foreach($member in $myNullMembersList){
                    if($member -eq 'sa'){
                        $myMembersString += ("   '{0}' is missing a description. Note: 'sa' accounts need to be renamed and disabled." -f $member)
                    }else{
                        $myMembersString += ("   '{0}' is missing a description." -f $member)
                    }
                }
                $myMembersString = $myMembersString -join "`n"
                $myCommentList += $myMembersString
            }
        }else{
            $myCommentList += "'$SourceDataFrom' is used to document all role memebers for instance'$($instanceName)'."
        }
   
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
   
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214045{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME   = "Invoke-FindingV214045"
    }
    process{
        # if a script is needed, get it
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = "V-214045"#$FindingID
        })

        # instance name is needed
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # sqlcommand params are defined
    # TODO: still cant reference my script from GetSQLQuery
        # manually adding it
        $SQLCommandParams = @{
        DatabaseName    = "master"
        InstanceName    = $instanceName
        Query           = @"
        DECLARE @temp_results TABLE (
        name            varchar(max),
        config_value    varchar(max)
        )

        INSERT INTO @temp_results
        EXEC master.sys.xp_loginconfig 'login mode';

        -- CheckResult  either 1 for a finding 0 for not a finding
        -- ResultValue what value was evaluated
        -- ResultDescripton check description
        select
            case
                when config_value = 'Windows NT Authentication'
                then 0
                else 1
            end as 'CheckResult',
            [ResultValue]       = config_value,
            [ResultDescripton]  = 'using windows only authentication'
        from
        @temp_results
"@
        }

        # sql command is ran
        $invokeParams = @{
            Session = $Session
            ScriptBlock = ${Function:Invoke-UDFSQLCommand}
            ArgumentList  = $SQLCommandParams
            ErrorAction  = 'Stop'
        }

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{Results = $checkResults.Rows.CheckResult ; ResultValue = $checkResults.Rows.ResultValue; ResultDescripton = $checkResults.Rows.ResultDescripton}
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Remarks:'
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescripton, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescripton, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214042{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-FindingV214045"
        $FINDING_DESCRIPTION    = 'The SQL Server Browser service must be disabled unless specifically required and approved'
    }
    process{
        $invokeParams = @{
            Session         = $Session
            ScriptBlock     = {Get-Service -Name 'SQLBrowser' -ErrorAction Stop}
            ErrorAction     = 'Stop'
        }

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $reachedInstance = [bool]
        try{
            $reachedInstance  = $true
            $checkResults = Invoke-Command @invokeParams
       
        }catch{
            $reachedInstance  = $false
            $checkResults = $Error[0]
        }
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += 'Remarks:'
            $myCommentList += "Was unable to perform check on Host '$HostName', validate that the host is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $checkResultAssessed = [pscustomobject]@{
                CheckResult         = [int]
                ResultValue         = [string]
                ResultDescripton    = [string]
            }

           
            $checkResultAssessed.CheckResult = switch(($checkResults.Status)){
                "Running"{ 1}
                "Stopped"{ 0 }
            }

            $checkResultAssessed.ResultValue        = "SQL Browser is currently '{0}'." -f $checkResults.Status
            $checkResultAssessed.ResultDescripton   = "SQL admins and authorized users to discover database instances over the network"

       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($checkResultAssessed.CheckResult -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $checkResultAssessed.ResultDescripton, "")
            }
       
            if($checkResultAssessed.CheckResult -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $checkResultAssessed.ResultDescripton, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214043{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding214043"
        $FINDING_DESCRIPTION    = "SQL Server Replication Xps feature must be disabled, unless specifically required and approved"

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214044{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding214044"
        $FINDING_DESCRIPTION    = "If the SQL Server Browser Service is specifically required and approved, SQL instances must be hidden."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214041{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding214041"
        $FINDING_DESCRIPTION    = "SQL Server External Scripts Enabled feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214040{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
       
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Remote Data Archive feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214039{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Allow Polybase Export feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214038{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Hadoop Connectivity feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214037{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Remote Access feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214036{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server User Options feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214035{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Ole Automation Procedures feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214034{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Filestream must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214033{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server execute permissions to access the registry must be revoked, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214032{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server Service Broker endpoint must utilize AES encryption."

        $reachedHost        = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $pwshScriptBlock = {
            # 0 -> TLS is is enabled and not a finding
            # 1 _> TLS is not enabled and a finding
            $enableManualOverride           = $false
            $value                          = 0
            $openResult_Description        = "TLS 1.2 is not enaled."
            $notafinding_ResultDescription  = "TLS 1.2 is enaled."
       
            $checkResults = [pscustomobject]@{
                CheckResults        = [int]
                ResultValue         = [int]
                ResultDescription   = [string]
            }
           
            if($enableManualOverride){
                switch($value){
                    1   {
                        $checkResults.CheckResults = 1
                        $checkResults.ResultValue  = 0
                        $checkResults.ResultDescription = $openResult_Description
                    }
                    0   {
                        $checkResults.CheckResults = 0
                        $checkResults.ResultValue  = 1
                        $checkResults.ResultDescription = $notafinding_ResultDescription
                    }
                }
            }
       
            if($enableManualOverride -eq $false){
                $checkCompleted = [bool]
                try{
                    $checkCompleted             = $true
                    (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -ErrorAction stop) | Out-Null
                    $checkResults.ResultValue = 0
                }catch{
                    $checkCompleted  = $false
                    $checkResults.ResultValue = 1
                }
           
                $checkResults.CheckResults = switch($checkCompleted){
                    $false  { 1 }
                    $true   { 0 }
                }
           
                if($checkResults.CheckResults -eq 1){
                    $checkResults.ResultDescription = $openResult_Description
                }
                if($checkResults.CheckResults -eq 0){
                    $checkResults.ResultDescription = $notafinding_ResultDescription
                }
            }
           $checkResults
        }
        $invokeParams = @{
            Session         = $Session
            ScriptBlock     = $pwshScriptBlock
            ErrorAction     = 'Stop'
        }
       
        try{
            $reachedHost = $true
            $checkResults = (Invoke-Command @invokeParams) | Select-Object -Property * -ExcludeProperty ("RunSpaceID","PSComputerName")
        }catch{
            $reachedHost = $false
        }
       
        # if you cant reach instance
        if($reachedHost -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on host '$HostName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.CheckResults
                    ResultValue         = $checkResults.ResultValue
                    ResultDescription   = $checkResults.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += ' '
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME

   
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ' '
                $myCommentList += $myCheckResults.ResultDescription
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += $myCheckResults.ResultDescription
                $myCommentList += ' '
                $myCommentList += "When TLS 1.2 is enabled, relying solely on SQL AES encryption becomes redundant because"
                $myCommentList += "TLS 1.2 already provides robust encryption and authentication for secure communication between SQL Server instances and applications ."
                $myCommentList += "Adding an additional layer of AES encryption would unnecessarily complicate the setup and management without significantly enhancing security."
               
            }
        }
    }
    end{
 
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214031{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server Mirroring endpoint must utilize AES encryption."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214030{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Execution of startup stored procedures must be restricted to necessary cases only."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214029{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server default account [sa] must have its name changed."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214028{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "The SQL Server default account [sa] must be disabled."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214027{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server must configure SQL Server Usage and Error Reporting Auditing."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214026{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Customer experience improvement program (CEIP) not used in enviornment."

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $productScriptBlock = {
            # 0 -> TLS is is enabled and not a finding
            # 1 -> TLS is not enabled and a finding
            $enableManualOverride           = $false
            $value                          = 0
            $openResult_Description        = "One or More instances are participating in the customer experience improvement program (CEIP)."
            $notafinding_ResultDescription  = "No instances are participating in the customer experience improvement program (CEIP)."
       
            $checkResults = [pscustomobject]@{
                CheckResults        = [int]
                ResultValue         = @()
                ResultDescription   = [string]
            }
            $instancesInstalledList = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server').InstalledInstances
            if($enableManualOverride){
                switch($value){
                    1   {
                        $checkResults.CheckResults = 1
                        $checkResults.ResultValue  += $instancesInstalledList
                        $checkResults.ResultDescription = $openResult_Description
                    }
                    0   {
                        $checkResults.CheckResults = 0
                        $checkResults.ResultValue  += $instancesInstalledList
                        $checkResults.ResultDescription = $notafinding_ResultDescription
                    }
                }
            }
            if($enableManualOverride -eq $false){
                $myHostName = HostName
                $instanceProductConfigurationList  = @()
                foreach($i in $instancesInstalledList) {
                    $product = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL').$i
                    $productParameters = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft SQL Server\$product\CPE\"
           
                    $instanceName = [string]
                    if(-not($myHostName -eq $i)){
                        $instanceName = ("{0}\{1}" -f $myHostName,$i)
                    }else{
                        $instanceName = $i
                    }
                    $instanceProductConfigurationList  += [pscustomobject]@{
                        HostName                = $myHostName
                        Instancename            = $instanceName
                        CustomerFeedback        = $productParameters.CustomerFeedback
                        EnableErrorReporting    = $productParameters.EnableErrorReporting    
                    }
                }
                foreach($instProduct in $instancesInstalledList){
                    if(($instProduct.CustomerFeedback -or $instProduct.EnableErrorReporting) -eq 0){
                        $checkResults.CheckResults = 1
                        $checkResults.ResultDescription = $openResult_Description
                    }else{
                        checkResults.CheckResults = 0
                        $checkResults.ResultDescription = $notafinding_ResultDescription
                    }
                }
                $checkResults.ResultValue = $instanceProductConfigurationList
            }
            $checkResults
        }
        $invokeParams = @{
            Session = $Session
            ScriptBlock = $productScriptBlock
            ArgumentList  = $SQLCommandParams
            ErrorAction  = 'Stop'
        }
       
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams | Select-Object -Property * -ExcludeProperty ("PSComputerName","RunspaceId")
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on host '$HostName', validate that the host is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.CheckResults
                    ResultValue         = $checkResults.ResultValue
                    ResultDescription    = $checkResults.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            $aggregatedComment = @()
            foreach($entry in $checkResults.ResultValue){
                $aggregatedComment += "On host '{0}, instance {1} has CustomerFeedback set to {2}, and Enabled ErrorReporting set to {3}'" -f
                    $entry.HostName,
                    $entry.Instancename,
                    $entry.CustomerFeedback,
                    $entry.EnableErrorReporting
            }

            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
                $myCommentList += $aggregatedComment
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
                $myCommentList += $aggregatedComment
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214025{
    param(
        [string]$HostName,
        [string]$FindingID,
        [string]$CheckListName,
        [switch]$DisplayStatus,
        [string]$DocumentationFolderPath
       
    )
    begin{
        $DocumentationFileName      = ("\{0}SQLArchivedLogging.json" -f $CheckListName)
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "The system SQL Server must off-load audit data to a separate log management facility."


        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $checkResults = [pscustomobject]@{
            CheckResults        = [int]
            ResultValue         = @()
            ResultDescription   = [string]
        }

        $DefaultSettings = @{
            IsNearRealTime = $true
            StorageLabel = "\HostName\SomeLocation"
            ArchiveInterval = "weekly"
            DirectlyWritesToArchive = $false
            HasContinousConnection = $true
        }
        $docExists = $PSSTIG.PSUTILITIES.GetUtilitySettingsTable(@{Label = $CheckListname })
        if($docExists -eq 0){
            $SQLLogsTable = @{}
            $SQLLogsTable.Add($CheckListname,@(@{
                IsNearRealTime          = $DefaultSettings.IsNearRealTime
                StorageLabel            = $DefaultSettings.StorageLabel
                DirectlyWritesToArchive = $DefaultSettings.DirectlyWritesToArchive
                ArchiveInterval         = $DefaultSettings.ArchiveInterval
                HasContinousConnection  = $DefaultSettings.HasContinousConnection
            }))
            $PSSTIG.PSUTILITIES.CacheConfiguration(@{
                Configuration = $SQLLogsTable
                Label       = $CheckListname
                FolderPath  = $DocumentationFolderPath
                FileName    = $DocumentationFileName
                Overwrite   = $false
            })
        }
        $myDocumentation = $PSSTIG.PSUTILITIES.ReadCache(@{
            Label = $CheckListname
        })
       
        $HashContinousConnection = $myDocumentation.$CheckListname.HasContinousConnection
        $DirectlyWritesToArchive = $myDocumentation.$CheckListname.DirectlyWritesToArchive
       
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Description:'
        $myCommentList += $FINDING_DESCRIPTION
        $myCommentList += " "
        $myCommentList += 'Remarks:'
        $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME

        if(($HashContinousConnection -eq $true )-and ($DirectlyWritesToArchive -eq $false)){
            $checkResults.CheckResults = 1
            $myCommentList += "There is a continouse connection, but the logs are not written directly to the archive location."
        }else{
            $checkResults.CheckResults = 0
            $myCommentList += "There is a continouse connection, and the logs are  written directly to the archive location."
        }
       
     
        $ArchiveInterval = $myDocumentation.$CheckListname.ArchiveInterval
        if(($HashContinousConnection -eq $false )-and ($ArchiveInterval -notmatch "weekly")){
            $checkResults.CheckResults = 1
            $myCommentList += "There is a intermittent connection, but the logs are not written weekly."
        }else{
            $checkResults.CheckResults = 0
            $myCommentList += "There is a intermittent connection, and the logs are written weekly."
        }


        if($checkResults.CheckResults -eq 1){
            $findingStatus = "open"
            $myCommentList += ("{0}`n{1} " -f $FINDING_DESCRIPTION, "")
            $myCommentList += $aggregatedComment
        }
   
        if($checkResults.CheckResults -eq 0){
            $findingStatus = "not_a_finding"
            $myCommentList += ("{0}`n{1} " -f $FINDING_DESCRIPTION, "")
            $myCommentList += $aggregatedComment
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            #Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214024{
    param(
        [string]$HostName,
        [string]$FindingID = "V-214024",
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool]
        }else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not implementing NIST FIPS 140-2 or 140-3 validated cryptographic modules"
            NotafindingResultDescription    = "SQL Server is implementing NIST FIPS 140-2 or 140-3 validated cryptographic modules"
            EnableManualOverride            = $false
            Value                           = 0
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "Customer experience improvement program (CEIP) not used in enviornment."
        }
        # checkedBy                       = "{0} {1}" -f "Check performed by:",$env:USERNAME
        # dateChecked                     = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')

        # this check itself with all its properties as defined in the argumentlist hashtable
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # when enabled, results are manually set on the checklist file
            if($argumentList.enableManualOverride){
                switch($value){
                    # in this block you can simulate the check is an open finding
                    1   {
                        $Check.Result      = 1
                        $Check.Value       = "[Manually set finding result to open]"
                        $Check.Description = $argumentList.OpenResultDescription
                    }

                    # in this block you can simuate the check is not a finding
                    0   {
                        $Check.Result      = 0
                        $Check.Value       = "[Manually set finding result to not_a_finding]"
                        $Check.Description = $argumentList.NotafindingResultDescription
                    }
                }
            }
            # when disabled, results are set from the check done
            if($argumentList.enableManualOverride -eq $false){
                $findingData = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
                $Check.Value = $findingData.Enabled
                # when returned true, its not a finding
                if($findingData.Enabled -eq 1){
                    $Check.Result      = 0
                    $Check.Description = $argumentList.NotafindingResultDescription
                }
                else{
                    $Check.Result      = 1
                    $Check.Description = $argumentList.OpenResultDescription
                }
            }

            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{
        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
       
        # if you cant reach instance
        if($establishedSession -eq $false){
            $findingStatus = "open"
            $myComments  += ' '
            $myComments  += 'Remarks:'
            $myComments  += "Was unable to perform check on host '$HostName', validate that the host is running and is accessible."
        }else{
            $myComments    += ' '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $ArgumentList.FUNCTION_NAME
       
            if($myResult.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $myResult.Description,"")
            }
       
            if($myResult.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $myResult.Description,"")
            }
        }
    }
    end{
        # here we update the checklist itself
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ("{0}" -f ($myComments -join "`n"))
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })

        # here we display as needed
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}





# $PSSTIG.U


# $invokeParams = @{
#     Session         = Get-PSSession -id '1'
#     ScriptBlock     = $productScriptBlock
#     ErrorAction     = 'Stop'
# }
# $checkResults = Invoke-Command @invokeParams | Select-Object -Property * -ExcludeProperty ("PSComputerName","RunspaceId")









# $FindingID = "V-214027"
# $myScripts      = $PSSTIG.GetSQLQuery(@{
#     FindingID = $FindingID
# })
# $SQLCommandParams = @{
#     DatabaseName    = "master"
#     InstanceName    = $instanceName
#     Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
#     }
#     # sql command is ran
# $invokeParams = @{
#     Session = $Session
#     ScriptBlock = ${Function:Invoke-UDFSQLCommand}
#     ArgumentList  = $SQLCommandParams
#     ErrorAction  = 'Stop'
# }