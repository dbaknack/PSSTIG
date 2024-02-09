$ErrorActionPreference = 'Stop'
Class PSSTIG{
    $Configuration = @{
        Folders = @{
            Parent = @{
                Description = "Used at the central repository of output from this tool."
                Path        = [string]
            }
            Sources = @{
                Description = "Used to output files used as a datasource for reports."
                Path        = [string]
            }
            Reports = @{
                Description = "Used to store reports generated from datasources."
                Path        = [string]
            }
            CheckLists = @{
                Description = "Used to store checklist used by STIG VIEWER."
                Path        = [string]
            }
            CheckListProperties = @{
                Description = "Used to store folders for each checklists created. One fore each checklist."
                Path        = [string]
            }
        }
        Files = @{
            SQLRoleMembersList = @{
                Description = "For SQL Server roles and role members."
                Name        = "SQLRoleMembersList.csv"
                Path        = [string]
            }

            ServerAdminAccountsList = @{
                Description = "For SQL Server roles and role members."
                Name        = "SQLRoleMembersList.csv"
                Path        = [string]
            }
        }
    }
    $FindingInfo = @{
       
    }

    $SessionsTable = @{}
    $PSUTILITIES        = (PSUTILITIES)
    $PlatformParameters = (PlatformParameters)
    $Separator          = $this.PlatformParameters.Separator
    $myMessage          = "[{0}]:: {1}"
    $CheckListTemplates = (Get-ChildItem -path "$((get-Location).path)$($this.Separator)Private$($this.Separator)CheckListTemplates$($this.Separator)")
    $HOSTDATA = @()

    [psobject]GetData([hashtable]$fromSender){
        $METHOD_NAME = "GetData"

        #$myDataSourcePath = ".\Private\HOSTDATA.csv"
        $myDataSourcePath = $fromSender.DataSourcePath
        $validSourcePath = (Test-Path -Path $myDataSourcePath)
        if(-not($validSourcePath)){
            $msgError = ("[{0}]:: {1}" -f $METHOD_NAME,"Invalid datasource '$myDataSourcePath'.")
            Write-Error -Message $msgError;$Error[0]
            return $Error[0]
        }

        $readContent = [bool]
        $myRawData = $()
        try{
            $readContent = $true
            $myRawData =  Get-Content -path $myDataSourcePath -ErrorAction "Stop"
        }catch{
            $readContent = $false
        }

        if(-not($readContent)){
            $msgError = ("[{0}]:: {1}" -f $METHOD_NAME,"Cannot read content.")
            Write-Error -Message $msgError;$Error[0]
            return $Error[0]
        }

        $convertedContent = [bool]
        $myConvertedData = @()
        try{
            $convertedContent = $true
            $myConvertedData = ConvertFrom-Csv $myRawData -ErrorAction "Stop"
        }catch{
            $convertedContent = $false
        }

        if(-not($convertedContent)){
            $msgError = ("[{0}]:: {1}" -f $METHOD_NAME,"Cannot convert content.")
            Write-Error -Message $msgError;$Error[0]
            return $Error[0]
        }
        return $myConvertedData
    }
    [void]AddData([hashtable]$fromSender){

        [string]$myDataSourcePath =($fromSender.DataSource)
        $myData = $this.GetData(@{
            DataSourcePath = $myDataSourcePath
        })

        $this.HOSTDATA += $myData
    }
    [void]GetFindingInfo([hashtable]$fromSender){
        $myCheckListName    = $fromSender.CheckListName
        $myFindingID        = $fromSender.FindingID
        $myCheckListData    = $this.GetCheckListData(@{
            CheckListName = $myCheckListName
        })
        $myFindindInfo = $myCheckListData.stigs.rules | Select-Object * |Where-Object {$_.group_id -eq $myFindingID}
        $divider = ('-')*105
        $returnMessage = "`n{0}`nStatus: {1}`nCheckListName: {2}`n{3}" -f $divider,$myFindindInfo.Status,$myCheckListName,$myFindindInfo.comments
        $messageColor = $null
        if(($myFindindInfo.Status) -eq 'open'){
            $messageColor = 'Red'
        }

        if($myFindindInfo.status -eq 'not_a_finding'){
            $messageColor = 'Cyan'
        }
        if($null -eq $messageColor){
            $messageColor = 'Magenta'
        }
        Write-Host $returnMessage -ForegroundColor $messageColor
    }
    [psobject]MyHostDataSet([hashtable]$fromSender){

        $myDataSource = $fromSender.DataSource
        $myHostData = $this.GetHostData(@{
            DataSource = $myDataSource
        })
        $myLevel = $fromSender.level
       
        $myDataTable = @()
        if($myLevel -eq "Server"){
            $groupedHostsList  = ($myHostData | Group-Object -Property HostName -AsHashTable)
            $myCheckListType = [string]
            foreach($groupedHost in $groupedHostsList.keys){
                if(((($groupedHostsList.($groupedHost)).CheckListType)).count -gt 1){
                    $myCheckListType =((($groupedHostsList.($groupedHost)).CheckListType)) | Select-Object -First 1
                   
                }else{
                    $myCheckListType = ((($groupedHostsList.($groupedHost)).CheckListType))
                }
                $myCheckListName = "{0}__{1}" -f $groupedHost, $myCheckListType
                $myDataTable += [pscustomobject]@{HostName = $groupedHost; CheckListName = $myCheckListName ; CheckListType = $myCheckListType}

            }
        }
        if($myLevel -eq "Instance"){
            foreach($myHost in $myHostData){
                $myCheckListName = "{0}_{1}_{2}" -f $myHost.HostName,$myHost.InstanceName,$myHost.CheckListType
                $myDataTable += [pscustomobject]@{HostName = $myHost.HostName; CheckListName = $myCheckListName ; CheckListType = $myHost.CheckListType}
            }
        }


        return $myDataTable
    }
    [void]CreateSessions([hashtable]$fromSender){
        $setAllHostSession  = $fromSender.All
        $myHostList         = $fromSender.HostList
        $filteredHosts = switch($setAllHostSession){
            $true   {
                $myHostData = $this.GetHostData(@{
                    DataSource = "SQLServerInstance"
                })
                $myHostData
            }
            $false  {
                $myHostData = $this.GetHostData(@{
                    DataSource = "SQLServerInstance"
                })
               
                foreach($myHost in $myHostData){
                    if($myHostList -contains $myHost.HostName){
                        $myHost
                    }
                }
            }
        }
        $frames = @(
            "`r[{0}]>--------[{1}]",
            "`r[{0}]->-------[{1}]",
            "`r[{0}]-->------[{1}]",
            "`r[{0}]--->-----[{1}]",
            "`r[{0}]---->----[{1}]",
            "`r[{0}]----->---[{1}]",
            "`r[{0}]------>--[{1}]",
            "`r[{0}]------->-[{1}]",
            "`r[{0}]-------->[{1}]",
            "`r[{0}]--------<[{1}]",
            "`r[{0}]-------<-[{1}]",
            "`r[{0}]------<--[{1}]",
            "`r[{0}]-----<---[{1}]",
            "`r[{0}]----<----[{1}]",
            "`r[{0}]---<-----[{1}]",
            "`r[{0}]--<------[{1}]",
            "`r[{0}]-<-------[{1}]",
            "`r[{0}]<--------[{1}]"
        )
        $localHost = hostname
        $groupedHostList    = ($filteredHosts | Group-Object -Property HostName).Name
        $myCreds            = $fromSender.Creds
        $groupedHostListCount = ($groupedHostList.count)-1
        foreach($remoteHost in 0..$groupedHostListCount){
            $sessionState =  $this.StoreASession(@{
                HostName    = ($groupedHostList[$remoteHost])
                Creds       = $myCreds
            })
           
            Do{
                foreach($frame in $frames){
                    $displaythis = $frame -f $localHost,($groupedHostList[$remoteHost])
                    Start-Sleep -Milliseconds 30
                    write-host $displaythis -NoNewline -ForegroundColor Cyan
                }
            }Until(($sessionState -eq 0) -or $($sessionState -eq 1))
       
        }
    }
    [psobject]GetSession([hashtable]$fromSender){
        $mySessionName = $fromSender.SessionName
        return $this.SessionsTable.$mySessionName
    }
    [psobject]StoreASession([hashtable]$fromSender){
        $myHostName = $fromSender.HostName
        $sessionEstablished = [bool]
       
        try{
            $sessionEstablished = $true
            $this.SessionsTable.Add($myHostName,(New-PSSession -ComputerName  $myHostName -Credential ($fromSender.Creds) -ErrorAction Stop))
        }catch{
            $sessionEstablished = $false
        }
        if($sessionEstablished -eq $false){
            return 0
        }
        return 1
    }
    [psobject]GetAllCheckListFindings([hashtable]$fromSender){
        $myCheckListName = $fromSender.CheckListName
        $myCheckListFolderPath = $this.Configuration.Folders.CheckLists.path
        $myCheckListParametersFolderPath = $this.Configuration.Folders.CheckListProperties.Path
        $myCheckListFilesList = Get-ChildItem -Path $myCheckListFolderPath
        $checkListFindingsExists = [bool]
        if(($myCheckListFilesList.BaseName) -contains $myCheckListName){
            $checkListFindingsExists = $true
           
        }else{
            $myFindingIDList = $false
        }

        if($checkListFindingsExists){
            $myFindingIDList = (Get-ChildItem  ("{0}{1}" -f $myCheckListParametersFolderPath,$myCheckListName)).BaseName
        }else{
            $myFindingIDList = $null
        }
        return $myFindingIDList
    }
    [void]UpdateStatus([hashtable]$fromSender){
        $METHOD_NAME = "UpdateComment"

        $myFindingID                    = $fromSender.FindingID
        $myCheckListName                = $fromSender.CheckListName
        $myCheckListsFolderPath         = $this.Configuration.Folders.CheckLists.Path
        $myCheckListPropertiesFolder    = $this.Configuration.Folders.CheckListProperties.Path

        $myMainData = $this.GetCheckListData(@{
            CheckListName = $myCheckListName
        })

        if($myMainData -eq 0){ return }

        $myCheckListPropertiesContainer = "{0}{1}{2}{3}.json" -f $myCheckListPropertiesFolder,$myCheckListName,$this.Separator,$myFindingID
        $propertiesFileExists           = [bool]
        $mypropertiesFile               = $null
        try{
            $propertiesFileExists   = $true
            $mypropertiesFile       = get-childitem  $myCheckListPropertiesContainer
        }catch{
            $propertiesFileExists = $false
        }
       
        if($propertiesFileExists -eq $false){
            $this.PSUTILITIES.DisplayMessage(@{
                Message     = ($this.myMessage -f $METHOD_NAME,"there is no properties file for checklist $myCheckListName.")
                type        = "warning"
                category    = "feedback"
            })
            return
        }

        $myStatus                       = $fromSender.Status
        $myPropertiesFileContent        = get-content $mypropertiesFile.FullName
        $myConvertedPropertiesContent   = $myPropertiesFileContent | ConvertFrom-Json
        $myConvertedPropertiesContent.status = $myStatus

        $myPropertiesFileString = $myConvertedPropertiesContent | ConvertTo-Json
        Set-Content -path $mypropertiesFile.FullName -Value $myPropertiesFileString

        $myRuleData = ($myMainData.stigs.rules) | Select-Object * | Where-Object {$_.group_id -eq $myFindingID}
        $myRuleData.status = $myConvertedPropertiesContent.status
        ($myMainData.stigs.rules) | ForEach-Object{
            if($_.group_id -eq $myFindingID){
                $_.status =  $myRuleData.status
            }
        }
        $myCheckListFilePath = "{0}{1}.cklb" -f $myCheckListsFolderPath,$myCheckListName
        Set-Content -Path $myCheckListFilePath -Value ($myMainData| ConvertTo-Json -Depth 5)

    }
    [void]UpdateComment([hashtable]$fromSender){
        $METHOD_NAME = "UpdateComment"

        $myFindingID = $fromSender.FindingID
        $myCheckListName = $fromSender.CheckListName
        $myCheckListsFolderPath = $this.Configuration.Folders.CheckLists.Path
        $myCheckListPropertiesFolder = $this.Configuration.Folders.CheckListProperties.Path

        $myMainData = $this.GetCheckListData(@{
            CheckListName = $myCheckListName
        })

        if($myMainData -eq 0){
            return
        }

        $myCheckListPropertiesContainer = "{0}{1}{2}{3}.json" -f $myCheckListPropertiesFolder,$myCheckListName,$this.Separator,$myFindingID
        $propertiesFileExists = [bool]
        $mypropertiesFile = $null
        try{
            $propertiesFileExists = $true
            $mypropertiesFile           = get-childitem  $myCheckListPropertiesContainer
        }catch{
            $propertiesFileExists = $false
        }
       
        if($propertiesFileExists -eq $false){
            $this.PSUTILITIES.DisplayMessage(@{
                Message = ($this.myMessage -f $METHOD_NAME,"there is no properties file for checklist $myCheckListName.")
                type = "warning"
                category = "feedback"
            })
            return
        }

        $myComment = $fromSender.Comment
        $myPropertiesFileContent    = get-content $mypropertiesFile.FullName
        $myConvertedPropertiesContent = $myPropertiesFileContent | ConvertFrom-Json
        $myConvertedPropertiesContent.comments = $myComment

        $myPropertiesFileString = $myConvertedPropertiesContent | ConvertTo-Json
        Set-Content -path $mypropertiesFile.FullName -Value $myPropertiesFileString

        $myRuleData = ($myMainData.stigs.rules) | Select-Object * | Where-Object {$_.group_id -eq $myFindingID}
        $myRuleData.comments = $myConvertedPropertiesContent.comments
        ($myMainData.stigs.rules) | ForEach-Object{
            if($_.group_id -eq $myFindingID){
                $_.comments =  $myRuleData.comments
            }
        }
        $myCheckListFilePath = "{0}{1}.cklb" -f $myCheckListsFolderPath,$myCheckListName
        Set-Content -Path $myCheckListFilePath -Value ($myMainData| ConvertTo-Json -Depth 5)

    }
    [psobject]GetHostData([hashtable]$fromSender){
        $METHOD_NAME = "GetHostData"

        $myHostData = $fromSender.DataSource
        $sourceHostData = $this.HOSTDATA
        [array]$hostDataList = $sourceHostData.Keys

        if($hostDataList -notcontains $myHostData){
            $msgError = ($this.myMessage -f $METHOD_NAME,"No Data for $myHostData exists.")
            Write-Error -Message $msgError
            return $Error[0]
        }
       
        $myData = $sourceHostData.$myHostData
        return $myData
    }
    [void]UpdateCheckListTitle([hashtable]$fromSender){
       # $METHOD_NAME = "UpdateCheckListTitle"

        $myCheckListFileName    = $fromSender.CheckListName
        $myFolders              = $this.Configuration.Folders
        $myCheckListsFolderPath = $myFolders.CheckLists.Path
        $myCheckListFilePath    = "$($myCheckListsFolderPath)$($myCheckListFileName).cklb"

        $myCheckListData = $this.GetCheckListData(@{
            CheckListName = $myCheckListFileName
        })


        $myCheckListData.title = $fromSender.Title
       
        $myUpdatedData = $myCheckListData | ConvertTo-Json -Depth 5
        Set-Content $myCheckListFilePath -Value $myUpdatedData
    }
    [psobject]GetCheckListData([hashtable]$fromSender){
        $myCheckListName = "$($fromSender.CheckListName).cklb"
        $myCheckListFolder = $this.Configuration.Folders.CheckLists
        $myCheckListFullPath = "{0}{1}" -f $myCheckListFolder.Path,$myCheckListName

        $checkListExists = (Test-Path -Path $myCheckListFullPath)
        if($checkListExists -eq $false){
            Write-Warning -Message "CheckList of name '$myCheckListName' does not exist."
            return 0
        }
       
        return (Get-Content -path $myCheckListFullPath) | ConvertFrom-Json
    }
    [void]DeleteChecklist([hashtable]$fromSender){
        $METHOD_NAME = "DeletChecklist"
        $this.myMessage = "{0}:: {1}"
        $myCheckListName = $fromSender.CheckListName
        $myCheckListFolder = ($this.Configuration.Folders.CheckLists).Path

        #check to make sure that it exists first
        $myCheckListExists = (Test-path -path $myCheckListFolder)
       
        if($myCheckListExists){
            #given the name of the checklist you wish to remove, and the location, delet it if it exist
            $this.PSUTILITIES.DisplayMessage(@{
                Message     = ($this.myMessage -f $METHOD_NAME,"The checklist provided '$myCheckListName' exists.")
                Type        = "debug"
                category    = "debug"
            })
        }else{
            #given the name of the checklist you wish to remove, and the location, delet it if it exist
            $this.PSUTILITIES.DisplayMessage(@{
                Message     = ($this.myMessage -f $METHOD_NAME,"The checklist provided '$myCheckListName' does not exists.")
                Type        = "debug"
                category    = "debug"
            })

        }

        $wasRemoved = [bool]
        $myCheckListFullPath = "{0}{1}.cklb" -f $myCheckListFolder,$myCheckListName
        if($myCheckListExists){
            try{
                $wasRemoved = $true
                Remove-Item -Path $myCheckListFullPath -ErrorAction Stop
            }catch{
                $wasRemoved = $false
            }
        }

        if(($wasRemoved)){
            #given the name of the checklist you wish to remove, and the location, delet it if it exist
            $this.PSUTILITIES.DisplayMessage(@{
                Message     = ($this.myMessage -f $METHOD_NAME,"The checklist provided '$myCheckListName' was removed successfully.")
                Type        = "success"
                category    = "feedback"
            })
        }else{
            $this.PSUTILITIES.DisplayMessage(@{
                Message     = ($this.myMessage -f $METHOD_NAME,"The checklist provided '$myCheckListName' failed to be removed.")
                Type        = "warning"
                category    = "feedback"
            })
        }

    }
    [void]CreateCommentFile([hashtable]$fromSender){
        $METHOD_NAME = "CreateCommentFile"
        $myCheckListFileName = $fromSender.CheckListName
        $myFolders = $this.Configuration.Folders
        $myCheckListsFolderPath = $myFolders.CheckLists.Path
        $myCommentsFolderPath   = $myFolders.Comments.Path
        $myCheckListFilePath    = "$($myCheckListsFolderPath)$($myCheckListFileName).cklb"

        $checkListExists = (Test-Path -Path $myCheckListFilePath)
        if(-not($checkListExists)){
            $msgError = ($this.myMessage -f $METHOD_NAME,"Cannot create comment container for non existing checklist file(s).")
            Write-Error -Message $msgError;$Error[0]
            return
        }

        $namingConvetion = $myCheckListFileName -split "_"
        $myCommentFileName = "{0}_{1}_{2}" -f $namingConvetion[0],$namingConvetion[1],$namingConvetion[2]

        $myCommentsFilePath = "$($myCommentsFolderPath)$($myCommentFileName).csv"
        $myCommentsFileExists = (Test-Path -Path $myCommentsFilePath)

        if($myCommentsFileExists){
            $this.PSUTILITIES.DisplayMessage(@{
                Message     = ($this.myMessage -f $METHOD_NAME, "Comment file '$myCommentFileName' already exists.")
                Type        = "informational"
                Category    = "feedback"
            })
            return
        }
        $this.PSUTILITIES.CreateItem(@{
            ItemType        = "File"
            Path            = $myCommentsFilePath
            WithFeedback    = $false
        })
    }
    [void]CreateCheckList([hashtable]$fromSender){
        $METHOD_NAME        = "CreateCheckList"
        $myCheckListFolder  = $this.Configuration.Folders.CheckLists

        $myCheckListType = ($fromSender.CheckListType)
        if(-not(($this.CheckListTemplates.basename) -contains $myCheckListType)){
            $msgError = "there is no checklist template for the type of checklist you want to create."
            Write-Error -Message $msgError; $Error[0]
            return
        }

        $myTemplateFile     = ($this.CheckListTemplates) | Select-Object FullName,basename | Where-Object {$_.basename -eq $myCheckListType }
        $myCheckListName    = $fromSender.CheckListName
        $myDestinationPath  = "{0}{1}" -f $myCheckListFolder.Path,"$($myCheckListName).cklb"
       

        $skipCreate = [bool]
        if(Test-Path -Path $myDestinationPath){
            $this.PSUTILITIES.DisplayMessage(@{
                Message = ("{0}:: {1}" -f $METHOD_NAME,"CheckList - '$myCheckListName.cklb' already exists.")
                Type = 'warning'
                category = 'feedback'
            })
            $skipCreate = $true
        }else{
            $skipCreate = $false
        }

        if($skipCreate -eq $false){
            $checkListCopied = [bool]
            try{
                $checkListCopied = $true
                Copy-Item  $myTemplateFile.FullName -Destination $myDestinationPath -ErrorAction Stop
            }catch{
                $checkListCopied = $false
                Write-Error -Message "Unabled to successfully copy '$($myCheckListName)'."; $Error[0]
                return
            }
            if($checkListCopied -eq $false){
                Write-Error -Message $Error[0]
                return
            }
            if($checkListCopied){
                $this.PSUTILITIES.DisplayMessage(@{
                    Message = ("{0}:: {1}" -f $METHOD_NAME,"CheckList - '$myCheckListName.cklb' successfully created")
                    Type = 'informational'
                    category = 'feedback'
                })
            }
        }


    }
    [void]SetFileSystemItems([hashtable]$fromSender){
        $METHOD_NAME    = "SetFileSystemItems"
        $myFolders  = $this.Configuration.Folders
        $myFiles    = $this.Configuration.Files
       
        # Parent Folder
        $parentExists = Test-Path -Path $myFolders.Parent.path
        $createItem = [bool]
        $itemCreated = [bool]
        if($parentExists -eq $false){
            $createItem = $true
        }else{
            $itemCreated = $true
            $createItem = $false
        }
        $msgState = ""
        if($createItem){
            try{
                $itemCreated = $true
                $this.PSUTILITIES.CreateItem(@{
                    ItemType        = "Directory"
                    Path            = $myFolders.Parent.Path
                    WithFeedback    = $false
                })
                $msgState = ($this.myMessage -f $METHOD_NAME,"Successfully created '$($myFolders.Parent.Path)'.")
            }catch{
                $itemCreated = $false
                $msgState = ($this.myMessage -f $METHOD_NAME,"Failed to create '$($myFolders.Parent.Path)'.")
            }
        }else{
            $msgState = ($this.myMessage -f $METHOD_NAME,"'$($myFolders.Parent.Path)' already exists.")
        }
        if($itemCreated -eq $false){
            $msgError = ($this.myMessage -f $METHOD_NAME,"Unable to create $($myFolders.Parent.Path) folder.")
            Write-Error -Message $msgError; $Error[0]
            return
        }

        $this.PSUTILITIES.DisplayMessage(@{
            Message = $msgState
            Type        = "success"
            Category    = "Feedback"
        })

        # Sources Folder

        $SourceFolderPath   = $myFolders.Sources.Path
        $sourcesExists      = Test-Path -Path $SourceFolderPath

        # check if folder exists
        if($sourcesExists -eq $false){
            $createItem = $true
        }else{
            $itemCreated    = $true
            $createItem     = $false
        }
        # does item need to be created
        if($createItem){
            try{
                $itemCreated = $true
                $this.PSUTILITIES.CreateItem(@{
                    ItemType        = "Directory"
                    Path            = $SourceFolderPath
                    WithFeedback    = $false
                })
                $msgState = ($this.myMessage -f $METHOD_NAME,"Successfully created '$($SourceFolderPath)'.")
            }catch{
                $itemCreated = $false
                $msgState = ($this.myMessage -f $METHOD_NAME,"Failed to create '$($SourceFolderPath)'.")
            }
        }else{
            $msgState = ($this.myMessage -f $METHOD_NAME,"'$($SourceFolderPath)' already exists.")
        }

        # was item created successfully?
        if($itemCreated -eq $false){
            Write-Error -Message $msgState; $Error[0]
            return
        }

        $this.PSUTILITIES.DisplayMessage(@{
            Message = $msgState
            Type        = "success"
            Category    = "Feedback"
        })

        # CheckList folder
        $checkListFoldePath     = $myFolders.CheckLists.Path
        $checkListFolderExists  = Test-Path -Path $checkListFoldePath

        if($checkListFolderExists -eq $false){
            $createItem = $true
        }else{
            $itemCreated = $true
            $createItem = $false
        }

        if($createItem){
            try{
                $itemCreated = $true
                $this.PSUTILITIES.CreateItem(@{
                    ItemType        = "Directory"
                    Path            = $checkListFoldePath
                    WithFeedback    = $false
                })
                $msgState = ($this.myMessage -f $METHOD_NAME,"Successfully created '$($checkListFoldePath )'.")
            }catch{
                $itemCreated = $false
                $msgState = ($this.myMessage -f $METHOD_NAME,"Failed to create '$($checkListFoldePath)'.")
            }
        }else{
            $msgState = ($this.myMessage -f $METHOD_NAME,"'$($checkListFoldePath)' already exists.")
        }

        if($itemCreated -eq $false){
            Write-Error -Message $msgState; $Error[0]
            return
        }

        $this.PSUTILITIES.DisplayMessage(@{
            Message = $msgState
            Type        = "success"
            Category    = "Feedback"
        })

        # Report folder
        $reportFolderPath = $myFolders.Reports.Path
        $reportExists = Test-Path -Path $reportFolderPath

        if($reportExists -eq $false){
            $createItem = $true
        }else{
            $itemCreated = $true
            $createItem = $false
        }

        if($createItem){
            try{
                $itemCreated = $true
                $this.PSUTILITIES.CreateItem(@{
                    ItemType        = "Directory"
                    Path            = $reportFolderPath
                    WithFeedback    = $false
                })
                $msgState = ($this.myMessage -f $METHOD_NAME,"Successfully created '$($reportFolderPath )'.")
            }catch{
                $itemCreated = $false
                $msgState = ($this.myMessage -f $METHOD_NAME,"Failed to create '$($reportFolderPath)'.")
            }
        }else{
            $msgState = ($this.myMessage -f $METHOD_NAME,"'$($reportFolderPath)' already exists.")
        }


        if($itemCreated -eq $false){
            Write-Error -Message $msgState; $Error[0]
            return
        }

        $this.PSUTILITIES.DisplayMessage(@{
            Message = $msgState
            Type        = "success"
            Category    = "Feedback"
        })

        # CheckListProperties folder
        $CheckListPropertiesFolderPath = $myFolders.CheckListProperties.Path
        $CheckListPropertiesExists = Test-Path -Path $CheckListPropertiesFolderPath

        if($CheckListPropertiesExists -eq $false){
            $createItem = $true
        }else{
            $itemCreated = $true
            $createItem = $false
        }

        if($createItem){
            try{
                $itemCreated = $true
                $this.PSUTILITIES.CreateItem(@{
                    ItemType        = "Directory"
                    Path            = $CheckListPropertiesFolderPath
                    WithFeedback    = $false
                })
                $msgState = ($this.myMessage -f $METHOD_NAME,"Successfully created '$($CheckListPropertiesFolderPath)'.")
            }catch{
                $itemCreated = $false
                $msgState = ($this.myMessage -f $METHOD_NAME,"Failed to create '$($CheckListPropertiesFolderPath)'.")
            }
        }else{
            $msgState = ($this.myMessage -f $METHOD_NAME,"'$($CheckListPropertiesFolderPath)' already exists.")
        }


        if($itemCreated -eq $false){
            Write-Error -Message $msgState; $Error[0]
            return
        }

        $this.PSUTILITIES.DisplayMessage(@{
            Message = $msgState
            Type        = "success"
            Category    = "Feedback"
        })
       

        $myDataSource = $fromSender.DataSource
        $myData = $this.GetHostData(@{
            DataSource = "$myDataSource"
        })

        $myCheckListPropertiesListItems = @()
        $myCheckListType = [string]
        foreach($entry in $myData){
            $myCheckListType = $entry.CheckListType
            $myCheckListPropertiesListItems += ("{0}_{1}_{2}" -f $entry.HostName,$entry.InstanceName,$myCheckListType)
        }
        $myCheckListPropertiesFolderList = Get-ChildItem -path $CheckListPropertiesFolderPath -Attributes 'Directory' -Filter "*$myDataSource"
        foreach($propertiesFolder in $myCheckListPropertiesListItems){
            $createPropertiesFolder = [bool]
           
            if(($myCheckListPropertiesFolderList.BaseName) -notcontains $propertiesFolder){
                $createPropertiesFolder = $true
            }else{
                $createPropertiesFolder = $false
            }
   
            $myPropertiesFolderPath = ("{0}{1}" -f $CheckListPropertiesFolderPath,$propertiesFolder)
            $this.PSUTILITIES.DisplayMessage(@{
                Message     = $myPropertiesFolderPath
                Type        = "debug"
                Category    = "debug"
            })

            if($createPropertiesFolder){
                New-Item -itemtype Directory -Name $myPropertiesFolderPath
            }
        }

        $myCheckListsFolderPath = $myFolders.CheckLists.Path
        foreach($checklist in $myCheckListPropertiesListItems){
            $this.CreateCheckList(@{
                CheckListType = $myCheckListType
                CheckListName = $checklist
            })
        }
        $myCheckListParametersString = @{
            status= ""
            comments=""
            UpdateAt=""
            severity=""
            finding_details=""
            mitigation_controls=""
            potential_impact=""
        } | ConvertTo-Json

       
        $myCheckListsFiles = Get-ChildItem $myCheckListsFolderPath
        foreach($checkListFile in $myCheckListsFiles){
            $myCheckListFileData = Get-Content $checkListFile.FullName
            $myCheckListConvertedData = $myCheckListFileData | ConvertFrom-Json
            [array]$myGroupIDList = $myCheckListConvertedData.stigs.rules.group_id
            $myCheckListParametersFolder = ("{0}{1}{2}" -f $CheckListPropertiesFolderPath,$checkListFile.BaseName,$this.Separator)
            foreach($groupID in $myGroupIDList){
                $myCheckListParametersFile = ("{0}{1}.json" -f $myCheckListParametersFolder,$groupID)
                $myParameterFileExists = [bool]
                try{
                    $myParameterFileExists = $true
                    $this.PSUTILITIES.CreateItem(@{
                        ItemType        = "File"
                        Path            = $myCheckListParametersFile
                        WithFeedback    = $false
                    })

                }catch{
                    $myParameterFileExists = $false
                }

                if($myParameterFileExists -eq $false){
                    $this.PSUTILITIES.DisplayMessage(@{
                        Message = ($this.myMessage -f $METHOD_NAME,"$myCheckListParametersFile already exists.")
                        Category    = 'feedback'
                        type        = 'informational'
                    })
                }
                if($myParameterFileExists -eq $true){
                    Set-Content -path $myCheckListParametersFile -Value $myCheckListParametersString
                }
               
            }
        }

        # File Creation
        foreach($file in $myFiles.keys){
            $myFilePath = $myFiles.$file.Path
            $myFileExists = Test-Path -Path $myFilePath

            $createItem = [bool]
            if(-not($myFileExists)){
                $createItem = $true
                $itemCreated = $false
            }else{
                $createItem = $false
                $itemCreated = $true
            }

            if($createItem){
                try{
                    $itemCreated = $true
                    $this.PSUTILITIES.CreateItem(@{
                        ItemType        = "File"
                        Path            = $myFilePath
                        WithFeedback    = $false
                    })
                }catch{
                    $itemCreated = $false
                }
            }
        }
    }
    [psobject]ReadFromSource([hashtable]$fromSender){
        $fromSender =  @{SourceFileName = "SQLRoleMembersList"}
        $mySource = $this.Configuration.Files.($fromSender.SourceFileName)
        $mySourceFileInfo = Get-ChildItem -Path $mySource.Path

        $SourceFileType = $mySourceFileInfo.extension
        $mySourceContent = switch($SourceFileType){
            ".csv"{
                Get-Content -Path $mySource.Path | ConvertFrom-Csv
            }
        }
        return $mySourceContent
    }
    [void]AddCheckListTemplate([hashtable]$fromSender){
        $METHOD_NAME = "AddCheckListTemplate"
        $msgState = $this.myMessage
        $folderprop = '.*{0}$' -f $this.Separator
        if($fromSender.CheckListFolder -notmatch $folderprop){
            $fromSender.CheckListFolder = "$($fromSender.CheckListFolder)$($this.Separator)"
        }

        $checkListTemplateName = "{0}.cklb" -f $($fromSender.CheckListName)
        $checkListFilePath = "$($fromSender.checkListFolder)$($checkListTemplateName)"
        $checkListExists = (test-path -path $checkListFilePath)

        if(-not($checkListExists)){
            $msgError = ($msgState -f $METHOD_NAME,"Unable to find a checklist named '$($checkListFilePath)'")
            Write-Error -Message $msgError; $Error[0]
            return
        }

        $myDestinationFolderPath    = $this.Configuration.Folders.Sources.Path

        Move-Item -Path $checkListFilePath -Destination $myDestinationFolderPath
        $this.PSUTILITIES.DisplayMessage(@{
            Message     = ($msgState -f $METHOD_NAME,"CheckList template sourced pulled in.")
            Type        = "success"
            Category    = "Feedback"
        })
    }
    [void]Initalize([hashtable]$fromSender){
        $Seperator = $this.PlatformParameters.Separator
        $myParent = ($fromSender.ParentFolderPath)

        if(-not($myParent[-1] -eq $Seperator)){
            $myParent =  "$($myParent)$($Seperator)"
        }

        $mySourcesFolderPath                = "$($myParent)Sources$($Seperator)"
        $myReportsFolderPath                = "$($myParent)Reports$($Seperator)"
        $mycheckListstsFolderPath           = "$($myParent)CheckLists$($Seperator)"
        $myCheckListPropertiesFolderPath    = "$($mySourcesFolderPath)CheckListProperties$($Seperator)"

        $this.Configuration.Folders.Parent.Path                 = $myParent
        $this.Configuration.Folders.Sources.Path                = $mySourcesFolderPath
        $this.Configuration.Folders.Reports.Path                = $myReportsFolderPath
        $this.Configuration.Folders.CheckLists.Path             = $mycheckListstsFolderPath
        $this.Configuration.Folders.CheckListProperties.Path    = $myCheckListPropertiesFolderPath

        $this.Configuration.Files.SQLRoleMembersList.Name = "SQLRoleMembersList.csv"
        $this.Configuration.Files.SQLRoleMembersList.Path = "$($mySourcesFolderPath)SQLRoleMembersList.csv"

        $this.Configuration.Files.ServerAdminAccountsList.Name = "ServerAdminAccountsList.csv"
        $this.Configuration.Files.ServerAdminAccountsList.Path = "$($mySourcesFolderPath)ServerAdminAccountsList.csv"

        $this.SetFileSystemItems(@{DataSource = ($fromSender.DataSource)})
    }
    [psobject]GetSQLQuery([hashtable]$fromSender){
        $myFindingID            = $fromSender.FindingID
        $modulePath             = Get-PSTIGModuleLocation
        $SQLScriptFolderPath    = "{0}{1}{2}{3}{4}{5}" -f
            $modulePath ,
            $this.PlatformParameters.Separator,
            "Private",
            $this.PlatformParameters.Separator,
            "SQLScripts",
            $this.PlatformParameters.Separator
           
        $scriptList = (Get-ChildItem -path $SQLScriptFolderPath  )

        if(($scriptList.BaseName) -notcontains $myFindingID){
            return 0
        }
       
       # $isDirectory = [bool]
        try{
            #$isDirectory = $true
            $scriptItemProperty = Get-ItemProperty -Path "$($SQLScriptFolderPath)$($myFindingID)" -ErrorAction Stop
        }catch{
            #$isDirectory = $false
            $scriptItemProperty = Get-ItemProperty -Path "$($SQLScriptFolderPath)$($myFindingID).sql" 

        }

        $scriptTable            = @{}
        $scriptFileProperties   = $null
        switch($ScriptItemProperty.Attributes){
            "Directory"{
                $scriptFileProperties = Get-ChildItem -path "$($SQLScriptFolderPath)$($myFindingID)"
                foreach($scriptProperty in $scriptFileProperties){
                    $script = Get-Content -Path $scriptProperty.FullName
                    $scriptTable.Add(($scriptProperty.BaseName),$script)
                }
            }
            "Archive"{
                $scriptFileProperties = Get-ChildItem -path "$($SQLScriptFolderPath)$($myFindingID).sql"
                $script = Get-Content -Path $scriptFileProperties.FullName
                $scriptTable.Add(($scriptFileProperties.BaseName),$script)
            }
        }
        return $scriptTable
    }
}
Class PSSTIGVIEWER{
    $StigViewerProcessName = "Stig Viewer 3"
    $PathToEXE = [string]
    $myMessage = "[{0}]:: {1}"

    [psobject]GetProcessesRunning(){
        $StigViewRunning = [bool]
        try{
            $StigViewRunning = $true
            Get-Process $this.StigViewerProcessName
        }catch{
            $StigViewRunning = $false
        }

       
        if($StigViewRunning){
            $myProcesses = Get-Process $this.StigViewerProcessName
        }else{
            $myProcesses = 0
        }

        return $myProcesses
    }
    [bool]GetProcessStatus(){
        $StigViewRunning = [bool]
        try{
            $StigViewRunning = $true
            Get-Process $this.StigViewerProcessName
        }catch{
            $StigViewRunning = $false
        }
        return $StigViewRunning
    }
    [void]Initalize([hashtable]$fromSender){
        $this.PathToEXE = ($fromSender.ExePath)
    }
    [void]StartStigViewer(){
        $METHOD_NAME = "StartStigViewer"
        $myExePath = $this.PathToEXE

        $validExePath = Test-Path -Path $myExePath

        if($validExePath -eq $false){
            $msgError = ($this.myMessage -f $METHOD_NAME, "Exe path '$($myExePath)' is invalid.")
            Write-Error -Message $msgError; $Error[0]
            return
        }

        $viewerRunning = $this.GetProcessStatus()
        if($viewerRunning -eq $true){
            $msgError = ($this.myMessage -f $METHOD_NAME,"StigViewer is already running...")
            Write-Error -Message $msgError; $Error[0]
            return
        }

        Start-Process -FilePath $myExePath
        $myStatus = [bool]
        do{
            Start-Sleep -Seconds 2
            $myStatus = ($this.GetProcessStatus()) 
        }while($myStatus-eq $false)
        Start-Sleep -Seconds 3
        Clear-host
    }
    [void]StopStigViewer(){
        $METHOD_NAME = "StopStigViewer"

        $viewerRunning = $this.GetProcessStatus()
        if($viewerRunning -eq $false){
            $msgError = ($this.myMessage -f $METHOD_NAME,"StigViewer is already stopped...")
            Write-Error -Message $msgError; $Error[0]
            return
        }

        $this.GetProcessesRunning() | Stop-Process 
    }
    [void]RestartStigViewer(){
        $METHOD_NAME = "RestartStigViewer"
        $myStigViewerStatus = $this.GetProcessStatus()

        if($myStigViewerStatus -eq $false){
            $msgError = ($this.myMessage -f $METHOD_NAME,"Stig Viewer 3 is currertly not running...")
            Write-Error -Message $msgError; $Error[0]
            return
        }

        $this.StopStigViewer()
        Start-Sleep -Seconds 2
        $this.StartStigViewer()
    }
}
Class PSSTIGMANUAL{

    $myMessage = "[{0}]:: {1}"
    $URLTable = @{
        MSSQL_Server_2016   = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_SQL_Server_2016_Y24M01_STIG.zip"
    }
    [string]SelectURL([hashtable]$fromSender){
        $METHOD_NAME = "SelectURL"
        $LinkKey = $fromSender.LinkLabel

       $myURL =  $this.URLTable.$LinkKey
        if($myURL.length -eq 0){
            $msgError = $this.myMessage -f $METHOD_NAME,"'$LinkKey' is not mapped to a URL."
            Write-Error -Message $msgError; 
            return $Error[0]
        }
        return $myURL
    }
    [void]DownloadManual([hashtable]$fromSender){
        $METHOD_NAME = "DownloadManual"
        $LinkKey = $fromSender.LinkLabel
        $myURL = $this.SelectURL(@{LinkLabel = $LinkKey})
        $myOutputPath       = $fromSender.SaveToFolderPath
        $myOutputPathExists = Test-Path -Path $myOutputPath

        if($myOutputPathExists -eq $false){
            $msgError = ($this.myMessage -f $METHOD_NAME, "'$myOutputPath' is invalid.")
            Write-Error -Message $msgError; $Error[0]
            return
        }
        $myFilePath  = "$($myOutputPath)\$($LinkKey).zip"
        Invoke-WebRequest -Uri $myURL -OutFile $myFilePath
    }
}
Class PSCONNECT{
    $SourcePath     = [string]
    $HostDataTable  = @()

    # Constructor
    PSCONNECT([hashtable]$fromSender){
        $myFilaPath = $fromSender.FilePath
        $myData     = Get-Content  -path $myFilaPath
        $this.HostDataTable = ( $myData | ConvertFrom-Csv)
        $this.SourcePath    = $myFilaPath
    }

    [void]ReloadHostData(){
        $myFilaPath = $this.SourcePath
        $myData     = Get-Content  -path $myFilaPath
        
        $this.HostDataTable = ($myData | ConvertFrom-Csv)
    }
    [void]AddHostData([pscustomobject]$fromSender){

        $FilePath       =  $this.SourcePath
        $myContent      = Get-Content -path  $FilePath| ConvertFrom-Csv -Delimiter ","
        $headingString  = [string]
        $headingsList   = @("RecID","Enclave","Alias","Port","IP","HostName","NamedInstance ","InstanceName","CheckType","CheckListType","CredentialRequired","CredentialAlias","Enable")
        $headingString  ='"{0}"' -f ($headingString = $headingsList -join '","')

      
        if(0 -eq  (($myContent) | Measure-Object).count){ Add-Content -Path $FilePath -Value $headingString }
        
        if(0 -eq  (($myContent) | Measure-Object).count){[int]$recordID = 1}
        else{
            [int]$myLastRecId = ($myContent.RecID)[-1]
            [int]$recordID = $myLastRecId +1}
        

        $myEntriesList  = @()
        foreach($entry in $fromSender){
            $valuesArray = @($recordID)
            $valuesArray += $entry | Get-Member -MemberType Properties | ForEach-Object {
                $entry.$($_.Name)
            }
            $entryString    =  '"{0}"'-f ($valuesArray -join '","')
            $myEntriesList += $entryString
            $recordID       = ($recordID) + 1
        }

        Add-Content -Path $FilePath -value $myEntriesList
        $this.ReloadHostData()
    }
}
