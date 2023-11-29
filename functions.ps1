# Function to check SQL Server configurations using .NET
function Check-SqlConfigurations {
    param (
        [string]$serverInstance
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Check Contained Databases
    $containedDatabasesSSMSQuery = "SELECT value FROM sys.configurations WHERE name = 'contained database authentication'"
    $containedDatabasesSSMSResult = Execute-SqlQuery -connectionString $connectionString -query $containedDatabasesSSMSQuery
    $containedDatabasesSSMS = $containedDatabasesSSMSResult.value -eq 1

    # Check Windows Authentication Mode
    $windowsAuthenticationSSMSQuery = "SELECT name, value FROM sys.dm_server_registry WHERE registry_key LIKE '%MSSQLServer\\Server\\LoginMode%'"
    $windowsAuthenticationSSMSResult = Execute-SqlQuery -connectionString $connectionString -query $windowsAuthenticationSSMSQuery
    $windowsAuthenticationSSMS = $windowsAuthenticationSSMSResult.value -eq 1

    # Return the check results
    [PSCustomObject]@{
        ContainedDatabasesSSMS = $containedDatabasesSSMS
        WindowsAuthenticationSSMS = $windowsAuthenticationSSMS
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $connection.Open()
    $result = $command.ExecuteScalar()
    $connection.Close()

    return $result
}

# Function to make changes based on check results using .NET
function Configure-SqlBasedOnCheckResults {
    param (
        [string]$serverInstance,
        [PSCustomObject]$checkResults
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Make changes for Contained Databases
    if (-not $checkResults.ContainedDatabasesSSMS) {
        Write-Host "Configuring Contained Databases..."
        $configureContainedDatabasesQuery = "EXEC sp_configure 'contained database authentication', 1; RECONFIGURE;"
        Execute-SqlQuery -connectionString $connectionString -query $configureContainedDatabasesQuery
    }

    # Make changes for Windows Authentication
    if (-not $checkResults.WindowsAuthenticationSSMS) {
        Write-Host "Configuring Windows Authentication..."
        $configureWindowsAuthenticationQuery = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'mixed authentication mode', 0; RECONFIGURE;"
        Execute-SqlQuery -connectionString $connectionString -query $configureWindowsAuthenticationQuery
    }
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$checkResults = Check-SqlConfigurations -serverInstance $serverInstance
Configure-SqlBasedOnCheckResults -serverInstance $serverInstance -checkResults $checkResults



# Function to check database permissions using .NET
function Check-DatabasePermissions {
    param (
        [string]$serverInstance,
        [string]$database,
        [string]$permissionsScriptPath
    )

    $connectionString = "Server=$serverInstance;Database=$database;Integrated Security=True;"

    # Check if the database is tempdb
    if ($database -eq 'tempdb') {
        Write-Host "Database is tempdb. This check is not applicable."
        return
    }

    # Read the supplemental SQL file
    try {
        $permissionsScript = Get-Content -Path $permissionsScriptPath -Raw
    } catch {
        Write-Host "Error reading permissions script: $_"
        return
    }

    # Execute the permissions script to get the documented permissions
    $documentedPermissions = Execute-SqlQuery -connectionString $connectionString -query $permissionsScript

    # Execute a query to get the actual permissions in the database
    $actualPermissionsQuery = "SELECT * FROM fn_my_permissions(NULL, 'DATABASE')"
    $actualPermissions = Execute-SqlQuery -connectionString $connectionString -query $actualPermissionsQuery

    # Compare actual and documented permissions
    $permissionsMatch = Compare-Object $documentedPermissions $actualPermissions -Property PermissionState, PermissionType, GranteePrincipal
    $permissionsMatchCount = $permissionsMatch.Count

    if ($permissionsMatchCount -eq 0) {
        Write-Host "Actual permissions match the documented requirements."
    } else {
        Write-Host "$permissionsMatchCount permission discrepancies found:"
        $permissionsMatch | ForEach-Object { Write-Host "$($_.SideIndicator) $($_.InputObject.PermissionState) $($_.InputObject.PermissionType) $($_.InputObject.GranteePrincipal)" }
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $connection.Open()
    $result = $command.ExecuteScalar()
    $connection.Close()

    return $result
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$database = "YourDatabaseName"
$permissionsScriptPath = "C:\Path\To\Database permission assignments to users and roles.sql"

Check-DatabasePermissions -serverInstance $serverInstance -database $database -permissionsScriptPath $permissionsScriptPath








# Function to check database users and determine if they are computer accounts
function Check-DatabaseUsers {
    param (
        [string]$serverInstance,
        [string]$database
    )

    $connectionString = "Server=$serverInstance;Database=$database;Integrated Security=True;"

    # Execute the query to get users from the database
    $usersQuery = "SELECT name FROM sys.database_principals WHERE type IN ('U','G') AND name LIKE '%$'"
    $users = Execute-SqlQuery -connectionString $connectionString -query $usersQuery

    # Check if users are returned
    if ($users.Count -eq 0) {
        Write-Host "No users returned. This is not a finding."
        return
    }

    # Check if each user is a computer account
    foreach ($user in $users) {
        $username = $user.name -replace '%$'
        $accountInfo = Get-ComputerAccountInfo -username $username

        if ($accountInfo -eq $null) {
            Write-Host "No account information found for user '$username'. This is not a finding."
        } else {
            Write-Host "Account information found for user '$username'. This is a finding."
        }
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Function to get computer account information using PowerShell ADSI
function Get-ComputerAccountInfo {
    param (
        [string]$username
    )

    $adsiSearcher = New-Object DirectoryServices.DirectorySearcher
    $adsiSearcher.Filter = "(&(ObjectCategory=Computer)(Name=$username))"
    $adsiSearcher.FindAll()
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$database = "YourDatabaseName"

Check-DatabaseUsers -serverInstance $serverInstance -database $database






# Function to check if collecting and keeping historical versions of a table is required
function Check-TemporalTableRequirements {
    param (
        [string]$serverInstance,
        [string]$database,
        [string]$documentationPath
    )

    $connectionString = "Server=$serverInstance;Database=$database;Integrated Security=True;"

    # Check if collecting and keeping historical versions of a table is required
    $historicalVersionsRequired = Get-HistoricalVersionsRequirement -documentationPath $documentationPath

    if (-not $historicalVersionsRequired) {
        Write-Host "Collecting and keeping historical versions of a table is not required. This is not a finding."
        return
    }

    # Find all temporal tables in the database
    $temporalTablesQuery = @"
    SELECT SCHEMA_NAME(T.schema_id) AS schema_name, T.name AS table_name, T.temporal_type_desc, SCHEMA_NAME(H.schema_id) + '.' + H.name AS history_table
    FROM sys.tables T
    JOIN sys.tables H ON T.history_table_id = H.object_id
    WHERE T.temporal_type != 0
    ORDER BY schema_name, table_name
"@
    $temporalTables = Execute-SqlQuery -connectionString $connectionString -query $temporalTablesQuery

    # Check if tables listed in the documentation are not in the list of temporal tables
    $tablesInDocumentation = Get-TablesInDocumentation -documentationPath $documentationPath

    foreach ($table in $tablesInDocumentation) {
        $tableExists = $temporalTables | Where-Object { $_.schema_name -eq $table.schema_name -and $_.table_name -eq $table.table_name }

        if ($tableExists -eq $null) {
            Write-Host "Table '$($table.schema_name).$($table.table_name)' listed in documentation is not a temporal table. This is a finding."
        }
    }

    # Ensure a field exists documenting the login and/or user who last modified the record
    $lastModifiedFieldExists = Check-LastModifiedField -connectionString $connectionString

    if (-not $lastModifiedFieldExists) {
        Write-Host "Field documenting the login and/or user who last modified the record does not exist. This is a finding."
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Function to get tables listed in documentation
function Get-TablesInDocumentation {
    param (
        [string]$documentationPath
    )

    # Logic to read tables from documentation file, assuming it is a text file with one table per line
    $tables = Get-Content -Path $documentationPath

    $tables | ForEach-Object {
        $parts = $_.Split('.')
        [PSCustomObject]@{
            schema_name = $parts[0]
            table_name  = $parts[1]
        }
    }
}

# Function to check if collecting and keeping historical versions of a table is required
function Get-HistoricalVersionsRequirement {
    param (
        [string]$documentationPath
    )

    # Logic to determine if historical versions are required based on documentation
    # Replace this logic with your specific requirements
    return $true
}

# Function to check if a field exists documenting the login and/or user who last modified the record
function Check-LastModifiedField {
    param (
        [string]$connectionString
    )

    # Logic to check if the field documenting the last modification exists
    # Replace this logic with your specific requirements
    return $true
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$database = "YourDatabaseName"
$documentationPath = "C:\Path\To\Documentation.txt"

Check-TemporalTableRequirements -serverInstance $serverInstance -database $database -documentationPath $documentationPath


# Function to check MSDB database configurations
function Check-MSDBConfigurations {
    param (
        [string]$serverInstance
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;Database=msdb;"

    # Execute the query to get MSDB configurations
    $msdbConfigQuery = @"
    SELECT SUSER_SNAME(d.owner_sid) AS DatabaseOwner,
        CASE
            WHEN d.is_trustworthy_on = 0 THEN 'No'
            WHEN d.is_trustworthy_on = 1 THEN 'Yes'
        END AS IsTrustworthy,
        CASE
            WHEN role.name IN ('sysadmin', 'securityadmin')
                OR permission.permission_name = 'CONTROL SERVER'
            THEN 'YES'
            ELSE 'No'
        END AS 'IsOwnerPrivileged'
    FROM sys.databases d
        LEFT JOIN sys.server_principals login ON d.owner_sid = login.sid
        LEFT JOIN sys.server_role_members rm ON login.principal_id = rm.member_principal_id
        LEFT JOIN sys.server_principals role ON rm.role_principal_id = role.principal_id
        LEFT JOIN sys.server_permissions permission ON login.principal_id = permission.grantee_principal_id
    WHERE d.name = 'msdb'
"@

    $msdbConfig = Execute-SqlQuery -connectionString $connectionString -query $msdbConfigQuery

    # Check if trustworthy is enabled
    $isTrustworthyEnabled = $msdbConfig.IsTrustworthy -eq 'Yes'

    # Check if the database owner is a privileged account
    $isOwnerPrivileged = $msdbConfig.IsOwnerPrivileged -eq 'YES'

    # Return the check results
    [PSCustomObject]@{
        TrustworthyEnabled = $isTrustworthyEnabled
        OwnerIsPrivileged = $isOwnerPrivileged
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Function to review MSDB configurations and determine if trustworthy is required and authorized
function Review-MSDBTrustworthy {
    param (
        [string]$serverInstance,
        [PSCustomObject]$msdbConfig
    )

    # If trustworthy is not enabled, not a finding
    if (-not $msdbConfig.TrustworthyEnabled) {
        Write-Host "Trustworthy is not enabled in MSDB. This is not a finding."
        return
    }

    # If trustworthy is enabled and the owner is not a privileged account, not a finding
    if ($msdbConfig.TrustworthyEnabled -and -not $msdbConfig.OwnerIsPrivileged) {
        Write-Host "Trustworthy is enabled in MSDB, and the owner is not a privileged account. This is not a finding."
        return
    }

    # If trustworthy is enabled and the owner is a privileged account, check documentation
    Write-Host "Trustworthy is enabled in MSDB, and the owner is a privileged account."

    # Review system documentation to determine if trustworthy is required and authorized
    # Replace this logic with your specific requirements
    $documentationAvailable = Get-SystemDocumentation -documentationPath "C:\Path\To\SystemDocumentation.txt"

    if (-not $documentationAvailable) {
        Write-Host "System documentation does not exist. This is a finding."
    } else {
        Write-Host "System documentation exists. Trustworthy property review based on documentation is required."
    }
}

# Function to check if system documentation is available
function Get-SystemDocumentation {
    param (
        [string]$documentationPath
    )

    # Replace this logic with your specific requirements
    return Test-Path $documentationPath
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$msdbConfig = Check-MSDBConfigurations -serverInstance $serverInstance
Review-MSDBTrustworthy -serverInstance $serverInstance -msdbConfig $msdbConfig



# Function to check database roles and memberships for audit maintainers
function Check-DatabaseRolesAndPermissions {
    param (
        [string]$serverInstance,
        [string]$database,
        [string]$documentationPath
    )

    $connectionString = "Server=$serverInstance;Database=$database;Integrated Security=True;"

    # Obtain the list of approved audit maintainers from system documentation
    $approvedAuditMaintainers = Get-ApprovedAuditMaintainers -documentationPath $documentationPath

    # Check role memberships for the ability to create and maintain audit specifications
    $roleMembershipsQuery = @"
    SELECT
        R.name AS role_name,
        RM.name AS role_member_name,
        RM.type_desc
    FROM sys.database_principals R
    JOIN sys.database_role_members DRM ON 
        R.principal_id = DRM.role_principal_id
    JOIN sys.database_principals RM ON 
        DRM.member_principal_id = RM.principal_id
    WHERE R.type = 'R'
        AND R.name = 'db_owner'
    ORDER BY 
        role_member_name
"@
    $roleMemberships = Execute-SqlQuery -connectionString $connectionString -query $roleMembershipsQuery

    # Check if role memberships are documented and authorized
    foreach ($membership in $roleMemberships) {
        $isMembershipAuthorized = $approvedAuditMaintainers -contains $membership.role_member_name

        if (-not $isMembershipAuthorized) {
            Write-Host "Role membership '$($membership.role_name)\$($membership.role_member_name)' is not documented and authorized. This is a finding."
        }
    }

    # Check roles and users with specified permissions for audit definitions
    $permissionsQuery = @"
    SELECT
        PERM.permission_name,
        DP.name AS principal_name,
        DP.type_desc AS principal_type,
        DBRM.role_member_name
    FROM sys.database_permissions PERM
    JOIN sys.database_principals DP ON PERM.grantee_principal_id = DP.principal_id
    LEFT OUTER JOIN (
        SELECT
            R.principal_id AS role_principal_id,
            R.name AS role_name,
            RM.name AS role_member_name
        FROM sys.database_principals R
        JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
        JOIN sys.database_principals RM ON DRM.member_principal_id = RM.principal_id
        WHERE R.type = 'R'
    ) DBRM ON DP.principal_id = DBRM.role_principal_id
    WHERE PERM.permission_name IN ('CONTROL','ALTER ANY DATABASE AUDIT')
    ORDER BY
        permission_name, 
        principal_name, 
        role_member_name
"@
    $permissions = Execute-SqlQuery -connectionString $connectionString -query $permissionsQuery

    # Check if roles or users returned have undocumented permissions
    foreach ($permission in $permissions) {
        $isPermissionDocumented = $approvedAuditMaintainers -contains $permission.role_member_name -or $approvedAuditMaintainers -contains $permission.principal_name

        if (-not $isPermissionDocumented) {
            Write-Host "Role or user '$($permission.principal_name)\$($permission.role_member_name)' has undocumented permissions. This is a finding."
        }
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Function to get approved audit maintainers from system documentation
function Get-ApprovedAuditMaintainers {
    param (
        [string]$documentationPath
    )

    # Logic to read approved audit maintainers from documentation file
    # Assuming one maintainer per line in the file
    return Get-Content -Path $documentationPath
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$database = "YourDatabaseName"
$documentationPath = "C:\Path\To\SystemDocumentation.txt"

Check-DatabaseRolesAndPermissions -serverInstance $serverInstance -database $database -documentationPath $documentationPath



# Function to check users and roles authorized to change stored procedures, functions, and triggers
function Check-PermissionsAndRoles {
    param (
        [string]$serverInstance,
        [string]$documentationPath
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Obtain the list of authorized users and roles from server documentation
    $authorizedUsersAndRoles = Get-AuthorizedUsersAndRoles -documentationPath $documentationPath

    # Loop through each user database
    $databasesQuery = "SELECT name FROM sys.databases WHERE database_id > 4"
    $databases = Execute-SqlQuery -connectionString $connectionString -query $databasesQuery

    foreach ($database in $databases) {
        $databaseName = $database.name
        $databaseConnectionString = "Server=$serverInstance;Database=$databaseName;Integrated Security=True;"

        # Execute the query to get users and roles with permissions to change objects
        $permissionsQuery = @"
        SELECT P.type_desc AS principal_type, P.name AS principal_name, O.type_desc,
          CASE class
           WHEN 0 THEN '$databaseName'
           WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
           WHEN 3 THEN SCHEMA_NAME(major_id)
            ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
           END AS securable_name, DP.state_desc, DP.permission_name
        FROM sys.database_permissions DP
        JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
        LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
        WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
"@

        $permissions = Execute-SqlQuery -connectionString $databaseConnectionString -query $permissionsQuery

        # Check if user or role permissions are authorized
        foreach ($permission in $permissions) {
            $isPermissionAuthorized = $authorizedUsersAndRoles -contains "$($permission.principal_type)\$($permission.principal_name)"

            if (-not $isPermissionAuthorized) {
                Write-Host "User or role '$($permission.principal_type)\$($permission.principal_name)' is not authorized to modify the specified object or type. This is a finding."
            }
        }

        # Execute the query to get role memberships
        $roleMembershipsQuery = @"
        SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
        FROM sys.database_principals R
        JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
        JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
        WHERE R.name IN ('db_ddladmin','db_owner')
           AND M.name != 'dbo'
"@

        $roleMemberships = Execute-SqlQuery -connectionString $databaseConnectionString -query $roleMembershipsQuery

        # Check if user or role memberships are authorized
        foreach ($membership in $roleMemberships) {
            $isMembershipAuthorized = $authorizedUsersAndRoles -contains "$($membership.principal_type)\$($membership.principal_name)"

            if (-not $isMembershipAuthorized) {
                Write-Host "User or role '$($membership.principal_type)\$($membership.principal_name)' membership is not authorized. This is a finding."
            }
        }
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Function to get authorized users and roles from server documentation
function Get-AuthorizedUsersAndRoles {
    param (
        [string]$documentationPath
    )

    # Logic to read authorized users and roles from documentation file
    # Assuming one user or role per line in the file
    return Get-Content -Path $documentationPath
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$documentationPath = "C:\Path\To\ServerDocumentation.txt"

Check-PermissionsAndRoles -serverInstance $serverInstance -documentationPath $documentationPath



# Function to check schema ownership
function Check-SchemaOwnership {
    param (
        [string]$serverInstance,
        [string]$documentationPath
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Obtain the list of authorized owning principals from server documentation
    $authorizedOwningPrincipals = Get-AuthorizedOwningPrincipals -documentationPath $documentationPath

    # Execute the query to obtain a current listing of schema ownership
    $schemaOwnershipQuery = @"
    SELECT S.name AS schema_name, P.name AS owning_principal
    FROM sys.schemas S
    JOIN sys.database_principals P ON S.principal_id = P.principal_id
    ORDER BY schema_name
"@

    $schemaOwnership = Execute-SqlQuery -connectionString $connectionString -query $schemaOwnershipQuery

    # Check if schema is owned by an unauthorized database principal
    foreach ($ownership in $schemaOwnership) {
        $isOwnershipAuthorized = $authorizedOwningPrincipals -contains $ownership.owning_principal

        if (-not $isOwnershipAuthorized) {
            Write-Host "Schema '$($ownership.schema_name)' is owned by an unauthorized database principal ('$($ownership.owning_principal)'). This is a finding."
        }
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Function to get authorized owning principals from server documentation
function Get-AuthorizedOwningPrincipals {
    param (
        [string]$documentationPath
    )

    # Logic to read authorized owning principals from documentation file
    # Assuming one principal per line in the file
    return Get-Content -Path $documentationPath
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$documentationPath = "C:\Path\To\ServerDocumentation.txt"

Check-SchemaOwnership -serverInstance $serverInstance -documentationPath $documentationPath


# Function to check SQL Server accounts authorized to own database objects
function Check-ObjectOwners {
    param (
        [string]$serverInstance,
        [string]$documentationPath
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Obtain the list of authorized object owners from server documentation
    $authorizedObjectOwners = Get-AuthorizedObjectOwners -documentationPath $documentationPath

    # Execute the query to identify SQL Server accounts owning database objects
    $objectOwnersQuery = @"
    ;with objects_cte as
    (SELECT o.name, o.type_desc,
       CASE
        WHEN o.principal_id is null then s.principal_id
         ELSE o.principal_id
        END as principal_id
     FROM sys.objects o
     INNER JOIN sys.schemas s
     ON o.schema_id = s.schema_id
     WHERE o.is_ms_shipped = 0
    )
    SELECT cte.name, cte.type_desc, dp.name as ObjectOwner 
    FROM objects_cte cte
    INNER JOIN sys.database_principals dp
    ON cte.principal_id = dp.principal_id
    ORDER BY dp.name, cte.name
"@

    $objectOwners = Execute-SqlQuery -connectionString $connectionString -query $objectOwnersQuery

    # Check if any listed owners are not authorized
    foreach ($owner in $objectOwners) {
        $isOwnerAuthorized = $authorizedObjectOwners -contains $owner.ObjectOwner

        if (-not $isOwnerAuthorized) {
            Write-Host "Object '$($owner.name)' of type '$($owner.type_desc)' is owned by an unauthorized SQL Server account ('$($owner.ObjectOwner)'). This is a finding."
        }
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Function to get authorized object owners from server documentation
function Get-AuthorizedObjectOwners {
    param (
        [string]$documentationPath
    )

    # Logic to read authorized object owners from documentation file
    # Assuming one owner per line in the file
    return Get-Content -Path $documentationPath
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$documentationPath = "C:\Path\To\ServerDocumentation.txt"

Check-ObjectOwners -serverInstance $serverInstance -documentationPath $documentationPath


# Function to check users and roles authorized to modify database structure and logic modules
function Check-DatabasePermissions {
    param (
        [string]$serverInstance,
        [string]$documentationPath
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Obtain the list of authorized users and roles from server documentation
    $authorizedUsersAndRoles = Get-AuthorizedUsersAndRoles -documentationPath $documentationPath

    # Execute the query to get users and roles with permissions to modify objects
    $permissionsQuery = @"
    SELECT P.type_desc AS principal_type, P.name AS principal_name, O.type_desc,
       CASE class
        WHEN 0 THEN DB_NAME()
        WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
        WHEN 3 THEN SCHEMA_NAME(major_id)
          ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
       END AS securable_name, DP.state_desc, DP.permission_name
    FROM sys.database_permissions DP
    JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
    LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
    WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
"@

    $permissions = Execute-SqlQuery -connectionString $connectionString -query $permissionsQuery

    # Check if users or role permissions are authorized
    foreach ($permission in $permissions) {
        $isPermissionAuthorized = $authorizedUsersAndRoles -contains "$($permission.principal_type)\$($permission.principal_name)"

        if (-not $isPermissionAuthorized) {
            Write-Host "User or role '$($permission.principal_type)\$($permission.principal_name)' is not authorized to modify the specified object or type ('$($permission.securable_name)'). This is a finding."
        }
    }

    # Execute the query to get role memberships
    $roleMembershipsQuery = @"
    SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
    FROM sys.database_principals R
    JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
    JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
    WHERE R.name IN ('db_ddladmin','db_owner')
    AND M.name != 'dbo'
"@

    $roleMemberships = Execute-SqlQuery -connectionString $connectionString -query $roleMembershipsQuery

    # Check if users or role memberships are authorized
    foreach ($membership in $roleMemberships) {
        $isMembershipAuthorized = $authorizedUsersAndRoles -contains "$($membership.principal_type)\$($membership.principal_name)"

        if (-not $isMembershipAuthorized) {
            Write-Host "User or role '$($membership.principal_type)\$($membership.principal_name)' membership is not authorized. This is a finding."
        }
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Function to get authorized users and roles from server documentation
function Get-AuthorizedUsersAndRoles {
    param (
        [string]$documentationPath
    )

    # Logic to read authorized users and roles from documentation file
    # Assuming one user or role per line in the file
    return Get-Content -Path $documentationPath
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$documentationPath = "C:\Path\To\ServerDocumentation.txt"

Check-DatabasePermissions -serverInstance $serverInstance -documentationPath $documentationPath


# Function to check database properties, recovery model, backup schedule, and restoration testing
function Check-DatabaseSecurityPlan {
    param (
        [string]$serverInstance,
        [string]$sspDocumentPath
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Read the content of the System Security Plan (SSP) document
    $sspContent = Get-Content -Path $sspDocumentPath

    # Check if the database is static
    $isDatabaseStatic = -not ($sspContent -match "database is static")

    # Execute the query to determine the recovery model
    $recoveryModelQuery = @"
    USE [master]
    SELECT name, recovery_model_desc
    FROM sys.databases
    ORDER BY name
"@

    $recoveryModels = Execute-SqlQuery -connectionString $connectionString -query $recoveryModelQuery

    # Check if the recovery model description matches the documented recovery model
    foreach ($recoveryModel in $recoveryModels) {
        $documentedRecoveryModel = ($sspContent -match "$($recoveryModel.name).+?recovery model is (.+?)\.")
        if ($documentedRecoveryModel -and $documentedRecoveryModel[1] -ne $recoveryModel.recovery_model_desc) {
            Write-Host "Recovery model for database '$($recoveryModel.name)' does not match the documented recovery model ('$($recoveryModel.recovery_model_desc)'). This is a finding."
        }
    }

    # Check if backup jobs are set up
    $backupJobQuery = "SELECT name FROM msdb.dbo.sysjobs WHERE name LIKE 'Backup%'"
    $backupJobs = Execute-SqlQuery -connectionString $connectionString -query $backupJobQuery

    if ($backupJobs.Rows.Count -eq 0) {
        Write-Host "No backup jobs found. This is a finding."
    }

    # Check the history of backups
    $backupHistoryQuery = @"
    USE [msdb]
    SELECT database_name, 
       CASE type
        WHEN 'D' THEN 'Full'
        WHEN 'I' THEN 'Differential'
        WHEN 'L' THEN 'Log'
       ELSE type
       END AS backup_type,
     is_copy_only,
     backup_start_date, backup_finish_date
    FROM dbo.backupset
    WHERE backup_start_date >= dateadd(day, -30, getdate()) 
    ORDER BY database_name, backup_start_date DESC
"@

    $backupHistory = Execute-SqlQuery -connectionString $connectionString -query $backupHistoryQuery

    # Check for missing or gaps in backups
    $backupGaps = $backupHistory | Group-Object database_name | Where-Object { $_.Group.Count -lt 30 }

    if ($backupGaps.Count -gt 0) {
        Write-Host "Backup history indicates missing or gaps in backups for the following databases: $($backupGaps.Name -join ', '). This is a finding."
    }

    # Check evidence of annual or more frequent database recovery testing
    $recoveryTestingEvidence = $sspContent -match "database recovery is tested (\w+)"
    if ($recoveryTestingEvidence -and $recoveryTestingEvidence[1] -ne "annually" -and $recoveryTestingEvidence[1] -ne "more often") {
        Write-Host "Database recovery is not tested annually or more often. This is a finding."
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$sspDocumentPath = "C:\Path\To\SystemSecurityPlan.txt"

Check-DatabaseSecurityPlan -serverInstance $serverInstance -sspDocumentPath $sspDocumentPath



# Function to check Database Master Key encryption
function Check-DatabaseMasterKeyEncryption {
    param (
        [string]$serverInstance
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Get a list of databases in 'Online' state
    $onlineDatabasesQuery = "SELECT name FROM [master].sys.databases WHERE state = 0"
    $onlineDatabases = Execute-SqlQuery -connectionString $connectionString -query $onlineDatabasesQuery

    # Check Database Master Key encryption for each database
    foreach ($database in $onlineDatabases) {
        $databaseName = $database.name

        # Execute the query to check Database Master Key encryption
        $checkMasterKeyQuery = @"
        USE [$databaseName]
        SELECT COUNT(name)
        FROM sys.symmetric_keys s, sys.key_encryptions k
        WHERE s.name = '##MS_DatabaseMasterKey##'
        AND s.symmetric_key_id = k.key_id
        AND k.crypt_type IN ('ESKP', 'ESP2', 'ESP3')
"@

        $encryptedMasterKeysCount = Execute-SqlQuery -connectionString $connectionString -query $checkMasterKeyQuery

        # Check the result and report findings
        if ($encryptedMasterKeysCount -gt 0) {
            Write-Host "Database '$databaseName' has a Database Master Key that is encrypted with a password."

            # Additional check for password requirements
            # Note: Adjust the password requirements based on your specific needs
            $passwordRequirementsMet = $databaseName -match '^(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$%^&*(),.?":{}|<>0-9]).{15,}$'
            if (-not $passwordRequirementsMet) {
                Write-Host "Password requirements for Database Master Key encryption are not met for database '$databaseName'. This is a finding."
            }
        } else {
            Write-Host "Database '$databaseName': No Database Master Key encrypted with a password found. This is not applicable."
        }
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable.Rows[0][0]
}

# Example usage
$serverInstance = "YourSqlServerInstance"

Check-DatabaseMasterKeyEncryption -serverInstance $serverInstance



# Function to check if databases require encryption of the Database Master Key
function Check-DatabaseMasterKeyEncryptionStatus {
    param (
        [string]$serverInstance
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Get a list of databases where the master key is encrypted by the service master key
    $encryptedMasterKeyDatabasesQuery = @"
    SELECT name
    FROM [master].sys.databases
    WHERE is_master_key_encrypted_by_server = 1
    AND owner_sid <> 1
    AND state = 0
"@

    $encryptedDatabases = Execute-SqlQuery -connectionString $connectionString -query $encryptedMasterKeyDatabasesQuery

    # Check if any databases are returned by the query
    if ($encryptedDatabases.Rows.Count -eq 0) {
        Write-Host "No databases require encryption of the Database Master Key. This is not a finding."
        return
    }

    # Loop through each returned database
    foreach ($database in $encryptedDatabases) {
        $databaseName = $database.name

        Write-Host "Database '$databaseName' requires encryption of the Database Master Key."

        # Check if encryption is approved in the System Security Plan
        $sspContent = Get-Content -Path "C:\Path\To\SystemSecurityPlan.txt"  # Replace with the actual path to your SSP
        $encryptionApproval = $sspContent -match "encryption of the Database Master Key using the Service Master Key is acceptable and approved by the Information Owner"

        if (-not $encryptionApproval) {
            Write-Host "Encryption of the Database Master Key is not approved in the System Security Plan for database '$databaseName'. This is a finding."
            continue
        }

        # Additional requirements check (replace this with your specific requirements)
        # Check if additional protections are in place, e.g., auditing
        $additionalRequirements = $sspContent -match "additional protections are required"
        if ($additionalRequirements) {
            # Check if the specific additional requirements are in place (replace this with your specific checks)
            $additionalRequirementsInPlace = $sspContent -match "additional requirements are in place"
            
            if (-not $additionalRequirementsInPlace) {
                Write-Host "Additional requirements for database '$databaseName' are not in place. This is a finding."
            }
        }
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Example usage
$serverInstance = "YourSqlServerInstance"

Check-DatabaseMasterKeyEncryptionStatus -serverInstance $serverInstance


# Function to check encryption requirements and backup procedures
function Check-EncryptionAndBackupProcedures {
    param (
        [string]$serverInstance
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Check if encryption of data at rest is required
    $encryptionRequirementQuery = @"
    SELECT value
    FROM [master].sys.configurations
    WHERE name = 'backup encryption default'
"@

    $encryptionRequirement = Execute-SqlQuery -connectionString $connectionString -query $encryptionRequirementQuery

    if ($encryptionRequirement -eq 0) {
        Write-Host "Encryption of data at rest is not required. This is not a finding."
        return
    }

    # Check procedures and evidence of backup of the Certificate used for encryption
    $backupProceduresQuery = @"
    SELECT *
    FROM sys.certificates
    WHERE name = 'YourCertificateName' -- Replace with the actual certificate name
"@

    $certificateBackupInfo = Execute-SqlQuery -connectionString $connectionString -query $backupProceduresQuery

    if ($certificateBackupInfo.Rows.Count -eq 0) {
        Write-Host "Certificate backup procedures or evidence do not exist. This is a finding."
        return
    }

    # Check if procedures indicate offline and off-site storage of the Certificate used for encryption
    $offlineStorageCheck = $certificateBackupInfo.Rows[0]["pvt_key_encryption_type_desc"] -eq "ENCRYPTED_BY_MASTER_KEY"

    if (-not $offlineStorageCheck) {
        Write-Host "Certificate backup procedures do not indicate offline and off-site storage. This is a finding."
    }

    # Check if procedures indicate access restrictions to the Certificate backup
    $accessRestrictionsCheck = $certificateBackupInfo.Rows[0]["pvt_key_last_backup_date"] -ne $null

    if (-not $accessRestrictionsCheck) {
        Write-Host "Certificate backup procedures do not indicate access restrictions. This is a finding."
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable
}

# Example usage
$serverInstance = "YourSqlServerInstance"

Check-EncryptionAndBackupProcedures -serverInstance $serverInstance



# Function to check if security-related functionality is stored separately
function Check-SeparateSecurityDomain {
    param (
        [string]$serverInstance
    )

    $connectionString = "Server=$serverInstance;Integrated Security=True;"

    # Get a list of user-defined databases
    $userDefinedDatabasesQuery = @"
    SELECT Name
    FROM sys.databases
    WHERE database_id > 4
    ORDER BY 1
"@

    $userDefinedDatabases = Execute-SqlQuery -connectionString $connectionString -query $userDefinedDatabasesQuery

    # Check each user-defined database for security-related functionality
    foreach ($database in $userDefinedDatabases) {
        $databaseName = $database.name

        Write-Host "Checking database '$databaseName' for security-related functionality..."

        # Run queries to identify security-related functionality (replace these queries with your specific checks)
        $securityFunctionalityQuery = @"
        SELECT COUNT(*)
        FROM $databaseName.sys.objects
        WHERE type_desc IN ('DATABASE_ROLE', 'SQL_STORED_PROCEDURE', 'SQL_TRIGGER')
"@

        $securityFunctionalityCount = Execute-SqlQuery -connectionString $connectionString -query $securityFunctionalityQuery

        # Check if security-related functionality is stored separately
        if ($securityFunctionalityCount -gt 0) {
            Write-Host "Security-related functionality found in database '$databaseName'. Checking if stored separately..."

            # Run additional queries to check if security-related functionality is stored separately
            $separateSecurityDomainQuery = @"
            SELECT COUNT(*)
            FROM $databaseName.sys.schemas
            WHERE name = 'SecuritySchema'  -- Replace with your specific security schema name
"@

            $separateSecurityDomainCount = Execute-SqlQuery -connectionString $connectionString -query $separateSecurityDomainQuery

            if ($separateSecurityDomainCount -eq 0) {
                Write-Host "Security-related functionality in database '$databaseName' is not stored in a separate security domain. This is a finding."
            } else {
                Write-Host "Security-related functionality in database '$databaseName' is stored in a separate security domain."
            }
        } else {
            Write-Host "No security-related functionality found in database '$databaseName'."
        }
    }
}

# Function to execute SQL query using .NET
function Execute-SqlQuery {
    param (
        [string]$connectionString,
        [string]$query
    )

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    $command = $connection.CreateCommand()
    $command.CommandText = $query

    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataTable = New-Object System.Data.DataTable
    [void]$adapter.Fill($dataTable)

    $connection.Close()

    return $dataTable.Rows[0][0]
}

# Example usage
$serverInstance = "YourSqlServerInstance"

Check-SeparateSecurityDomain -serverInstance $serverInstance


param (
    [string]$serverInstance,
    [string]$databaseName,
    [string]$backupFilePath,
    [string]$restoreFilePath
)

# Function to backup a SQL Server database
function Backup-Database {
    param (
        [string]$serverInstance,
        [string]$databaseName,
        [string]$backupFilePath
    )

    try {
        # Build the backup query
        $backupQuery = @"
USE master;
BACKUP DATABASE [$databaseName] TO DISK = '$backupFilePath' WITH FORMAT;
"@

        # Execute the backup query using SQLCMD
        sqlcmd -S $serverInstance -Q $backupQuery
        Write-Host "Backup of database '$databaseName' completed successfully."
    }
    catch {
        Write-Host "Error: $_"
    }
}

# Function to restore a SQL Server database
function Restore-Database {
    param (
        [string]$serverInstance,
        [string]$databaseName,
        [string]$restoreFilePath
    )

    try {
        # Build the restore query
        $restoreQuery = @"
USE master;
RESTORE DATABASE [$databaseName] FROM DISK = '$restoreFilePath' WITH REPLACE;
"@

        # Execute the restore query using SQLCMD
        sqlcmd -S $serverInstance -Q $restoreQuery
        Write-Host "Restore of database '$databaseName' completed successfully."
    }
    catch {
        Write-Host "Error: $_"
    }
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$databaseName = "YourDatabaseName"
$backupFilePath = "C:\Path\To\BackupFile.bak"
$restoreFilePath = "C:\Path\To\BackupFile.bak"

# Backup the database
Backup-Database -serverInstance $serverInstance -databaseName $databaseName -backupFilePath $backupFilePath

# Restore the database
Restore-Database -serverInstance $serverInstance -databaseName $databaseName -restoreFilePath $restoreFilePath


param (
    [string]$serverInstance,
    [string]$databaseName
)

# Function to check column constraints and data types
function Check-ColumnConstraints {
    param (
        [string]$serverInstance,
        [string]$databaseName
    )

    try {
        # Build the query to retrieve column information
        $columnQuery = @"
USE [$databaseName];

SELECT 
    t.name AS TableName,
    c.name AS ColumnName,
    tp.name AS DataType,
    c.max_length AS MaxLength,
    c.is_nullable AS IsNullable,
    cc.definition AS DefaultConstraint,
    CASE 
        WHEN ic.column_id IS NOT NULL THEN 'Yes'
        ELSE 'No'
    END AS IsIdentity,
    CASE 
        WHEN tc.constraint_name IS NOT NULL THEN 'Yes'
        ELSE 'No'
    END AS HasConstraint
FROM 
    sys.tables t
    INNER JOIN sys.columns c ON t.object_id = c.object_id
    INNER JOIN sys.types tp ON c.system_type_id = tp.system_type_id
    LEFT JOIN sys.identity_columns ic ON c.object_id = ic.object_id AND c.column_id = ic.column_id
    LEFT JOIN sys.default_constraints cc ON c.default_object_id = cc.object_id
    LEFT JOIN information_schema.columns isc ON t.name = isc.table_name AND c.name = isc.column_name
    LEFT JOIN information_schema.table_constraints tc ON t.name = tc.table_name AND tc.constraint_type = 'PRIMARY KEY' AND c.column_id = tc.column_id
"@

        # Execute the query using SQLCMD
        $result = Invoke-Sqlcmd -ServerInstance $serverInstance -Database $databaseName -Query $columnQuery

        # Check for constraints and data types
        foreach ($row in $result) {
            $tableName = $row.TableName
            $columnName = $row.ColumnName
            $dataType = $row.DataType
            $maxLength = $row.MaxLength
            $isNullable = $row.IsNullable
            $defaultConstraint = $row.DefaultConstraint
            $isIdentity = $row.IsIdentity
            $hasConstraint = $row.HasConstraint

            Write-Host "Checking column '$columnName' in table '$tableName'..."

            # Add your custom logic here to check for constraints and data types
            # For example, you can check if the column has a specific constraint or if it meets certain criteria

            # Example: Check if the column has a constraint
            if ($hasConstraint -eq 'No') {
                Write-Host "Error: Column '$columnName' in table '$tableName' does not have a primary key constraint."
            }

            # Example: Check if the data type is as expected
            if ($dataType -ne 'int') {
                Write-Host "Error: Column '$columnName' in table '$tableName' has an unexpected data type '$dataType'."
            }
        }

        Write-Host "Column constraints and data types check completed."
    }
    catch {
        Write-Host "Error: $_"
    }
}

# Example usage
$serverInstance = "YourSqlServerInstance"
$databaseName = "YourDatabaseName"

Check-ColumnConstraints -serverInstance $serverInstance -databaseName $databaseName

<#
Reviewing application behavior and custom database code for sensitive information in error messages is crucial for maintaining a secure environment. While I can't directly review your code, I can provide guidance on how to approach this issue. Below are some steps and considerations to help you review and secure error messages:

Audit Code:

Examine the application code, stored procedures, and triggers to identify points where errors are raised and handled.
Look for instances where error messages are constructed or logged.
Use Generic Messages:

Avoid including detailed technical information in error messages that could expose sensitive information.
Provide generic messages to users and log more detailed errors internally for troubleshooting.
Logging and Monitoring:

Implement centralized logging to capture error messages, but ensure that sensitive details are not logged where they can be accessed by unauthorized personnel.
Set up monitoring systems to alert administrators of critical errors without exposing sensitive details in notifications.
Custom Error Handling:

Implement custom error handling mechanisms to control the information exposed in error messages.
Capture errors at different levels (e.g., application, database) and handle them appropriately.
Avoid Exposing Database Structure:

Avoid exposing database schema or structure details in error messages, as this information can be exploited by attackers.
Data Masking:

If necessary, implement data masking techniques to replace sensitive information with masked or obfuscated values in error messages.
Regular Code Reviews:

Conduct regular code reviews with a focus on error handling and message construction to ensure adherence to security best practices.
Security Testing:

Perform security testing, including penetration testing and code analysis tools, to identify any potential vulnerabilities related to error messages.
Educate Developers:

Educate developers on secure coding practices, including the importance of not exposing sensitive information in error messages.
Compliance Requirements:

Consider compliance requirements (e.g., GDPR, HIPAA) related to data protection and ensure that error messages comply with these regulations.
Here's an example of how you might handle errors in a stored procedure:

sql
Copy code
BEGIN TRY
    -- Your SQL statements here
END TRY
BEGIN CATCH
    -- Log the error without exposing sensitive details
    EXEC LogErrorProcedure;

    -- Return a generic error message to the application
    THROW 50001, 'An unexpected error occurred. Please contact support.', 1;
END CATCH;
#>


# If security labeling is required, you would typically implement a solution to enforce and maintain security labels on information in storage. Here are some considerations and steps you might take:

# Understand Security Labeling Requirements:

# Clearly define the security labeling requirements based on your organization's policies, regulatory compliance, or other security standards.
# Choose a Security Labeling Solution:

# Evaluate whether a third-party security labeling solution or a built-in SQL Server feature, such as Row-Level Security (RLS), aligns with your requirements.
# Implement Third-Party Solution:

# If a third-party solution is chosen, follow the vendor's documentation and guidelines to implement the security labeling solution.
# Implement SQL Server Row-Level Security (RLS):

# If you choose to implement SQL Server RLS, define and apply security policies to control access to rows in database tables based on the values in each row.
# Use functions to determine which users have access to specific rows based on their security labels or other criteria.
# Here's a simplified example of how you might use SQL Server RLS to enforce security labeling:

# sql
# Copy code
# -- Create a function to determine access based on security labels
# CREATE FUNCTION dbo.fn_security_predicate(@security_label NVARCHAR(255))
# RETURNS TABLE
# WITH SCHEMABINDING
# AS
# RETURN SELECT 1 AS fn_security_result
# WHERE @security_label = 'Sensitive';

# -- Create a security policy on a table
# CREATE SECURITY POLICY SecurityLabelPolicy
# ADD FILTER PREDICATE dbo.fn_security_predicate(SecurityLabelColumn) ON dbo.YourTable,
# ADD BLOCK PREDICATE dbo.fn_security_predicate(SecurityLabelColumn) ON dbo.YourTable;

# -- Enable the security policy
# ALTER TABLE dbo.YourTable ENABLE SECURITY POLICY SecurityLabelPolicy;


function Check-ObjectOwnershipAndAuthorization {
    # Connect to the SQL Server instance (replace with your connection details)
    $serverInstance = "YourServerInstance"
    $database = "YourDatabase"
    $connectionString = "Server=$serverInstance;Database=$database;Integrated Security=True;"
    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    try {
        # Open the SQL connection
        $connection.Open()

        # Query to discover schemas not owned by the schema or dbo
        $schemaQuery = "SELECT name AS schema_name, USER_NAME(principal_id) AS schema_owner FROM sys.schemas WHERE schema_id != principal_id AND principal_id != 1"

        $schemaCommand = $connection.CreateCommand()
        $schemaCommand.CommandText = $schemaQuery
        $schemaReader = $schemaCommand.ExecuteReader()

        # Check and output the result
        if ($schemaReader.HasRows) {
            Write-Output "Schemas not owned by the schema or dbo:"
            while ($schemaReader.Read()) {
                Write-Output ("Schema: {0}, Owner: {1}" -f $schemaReader["schema_name"], $schemaReader["schema_owner"])
            }
        } else {
            Write-Output "No issues found with schema ownership."
        }

        # Query to discover objects owned by an individual principal
        $objectQuery = "SELECT object_id, name AS securable, USER_NAME(principal_id) AS object_owner, type_desc FROM sys.objects WHERE is_ms_shipped = 0 AND principal_id IS NOT NULL ORDER BY type_desc, securable, object_owner"

        $objectCommand = $connection.CreateCommand()
        $objectCommand.CommandText = $objectQuery
        $objectReader = $objectCommand.ExecuteReader()

        # Check and output the result
        if ($objectReader.HasRows) {
            Write-Output "`nObjects owned by an individual principal:"
            while ($objectReader.Read()) {
                Write-Output ("Object: {0}, Owner: {1}, Type: {2}" -f $objectReader["securable"], $objectReader["object_owner"], $objectReader["type_desc"])
            }
        } else {
            Write-Output "No issues found with object ownership."
        }

        # Query to discover database users who have been delegated the right to assign additional permissions
        $delegationQuery = "SELECT U.type_desc, U.name AS grantee, DP.class_desc AS securable_type, CASE DP.class WHEN 0 THEN DB_NAME() WHEN 1 THEN OBJECT_NAME(DP.major_id) WHEN 3 THEN SCHEMA_NAME(DP.major_id) ELSE CAST(DP.major_id AS nvarchar) END AS securable, permission_name, state_desc FROM sys.database_permissions DP JOIN sys.database_principals U ON DP.grantee_principal_id = U.principal_id WHERE DP.state = 'W' ORDER BY grantee, securable_type, securable"

        $delegationCommand = $connection.CreateCommand()
        $delegationCommand.CommandText = $delegationQuery
        $delegationReader = $delegationCommand.ExecuteReader()

        # Check and output the result
        if ($delegationReader.HasRows) {
            Write-Output "`nDatabase users delegated the right to assign additional permissions:"
            while ($delegationReader.Read()) {
                Write-Output ("Grantee: {0}, Securable Type: {1}, Securable: {2}, Permission: {3}, State: {4}" -f $delegationReader["grantee"], $delegationReader["securable_type"], $delegationReader["securable"], $delegationReader["permission_name"], $delegationReader["state_desc"])
            }
        } else {
            Write-Output "No issues found with authorization delegation."
        }
    }
    catch {
        Write-Error "Error: $_"
    }
    finally {
        # Close the SQL connection
        $connection.Close()
    }
}

# Run the function
Check-ObjectOwnershipAndAuthorization



function Grant-PermissionToUser {
    param(
        [string]$userName,
        [string]$permission
    )

    # Connect to the SQL Server instance (replace with your connection details)
    $serverInstance = "YourServerInstance"
    $database = "YourDatabase"
    $connectionString = "Server=$serverInstance;Database=$database;Integrated Security=True;"
    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    try {
        # Open the SQL connection
        $connection.Open()

        # Grant permission to the specified user (replace with your specific permission)
        $grantPermissionQuery = "GRANT $permission TO [$userName]"

        $grantPermissionCommand = $connection.CreateCommand()
        $grantPermissionCommand.CommandText = $grantPermissionQuery
        $grantPermissionCommand.ExecuteNonQuery()

        Write-Output ("Permission '$permission' granted to user '$userName'.")
    }
    catch {
        Write-Error "Error: $_"
    }
    finally {
        # Close the SQL connection
        $connection.Close()
    }
}

# Example: Grant SELECT permission to a user
Grant-PermissionToUser -userName "YourUserName" -permission "SELECT"



-- Discover schemas not owned by the schema or dbo
-- This query identifies schemas in the database that are not owned by their corresponding schema or dbo.
-- It checks for inconsistencies in schema ownership.
SELECT name AS schema_name, USER_NAME(principal_id) AS schema_owner
FROM sys.schemas
WHERE schema_id != principal_id AND principal_id != 1;

-- Discover objects owned by an individual principal
-- This query identifies user-defined objects in the database (e.g., tables, views) that are not owned by the schema or dbo.
-- It helps find objects that may have individual ownership rather than being owned by a schema.
SELECT object_id, name AS securable, USER_NAME(principal_id) AS object_owner, type_desc
FROM sys.objects
WHERE is_ms_shipped = 0 AND principal_id IS NOT NULL
ORDER BY type_desc, securable, object_owner;

-- Discover database users delegated the right to assign additional permissions
-- This query identifies users in the database who have been granted the right to assign additional permissions (state = 'W').
-- It helps identify users with delegation rights, which might impact security.
SELECT U.type_desc, U.name AS grantee, DP.class_desc AS securable_type,
    CASE DP.class
        WHEN 0 THEN DB_NAME()
        WHEN 1 THEN OBJECT_NAME(DP.major_id) 
        WHEN 3 THEN SCHEMA_NAME(DP.major_id)
    ELSE CAST(DP.major_id AS nvarchar)
    END AS securable,
    permission_name, state_desc
FROM sys.database_permissions DP
JOIN sys.database_principals U ON DP.grantee_principal_id = U.principal_id
WHERE DP.state = 'W'
ORDER BY grantee, securable_type, securable;



# PowerShell script to check stored procedures and functions using impersonation

# Configuration
$SqlServerInstance = "YourSqlServerInstance"
$DatabaseName = "YourDatabaseName"
$OutputFilePath = "C:\Path\To\Output\ImpersonationDocumentation.md"

# Load SQL Server Management Objects (SMO) assembly
Add-Type -AssemblyName "Microsoft.SqlServer.Smo, Version=15.0.0.0, Culture=neutral, PublicKeyToken=89845dcd8080cc91"

# Create SQL Server connection
$serverConnection = New-Object Microsoft.SqlServer.Management.Common.ServerConnection -argumentlist $SqlServerInstance
$server = New-Object Microsoft.SqlServer.Management.Smo.Server -argumentlist $serverConnection

# Execute T-SQL query
$query = @"
SELECT S.name AS schema_name, O.name AS module_name,
    USER_NAME(
        CASE M.execute_as_principal_id
            WHEN -2 THEN COALESCE(O.principal_id, S.principal_id)
            ELSE M.execute_as_principal_id
        END
    ) AS execute_as
FROM sys.sql_modules M
JOIN sys.objects O ON M.object_id = O.object_id
JOIN sys.schemas S ON O.schema_id = S.schema_id
WHERE execute_as_principal_id IS NOT NULL
    AND o.name NOT IN (
        'fn_sysdac_get_username',
        -- List of excluded system procedures/functions...
    )
ORDER BY schema_name, module_name;
"@

$results = $server.Databases[$DatabaseName].ExecuteWithResults($query)

# Generate Markdown documentation
$markdownContent = @"
# Impersonation Documentation

The following stored procedures and functions utilize impersonation:

| Schema Name | Module Name | Execute As |
|-------------|-------------|------------|
"@

foreach ($row in $results.Tables[0].Rows) {
    $schemaName = $row["schema_name"]
    $moduleName = $row["module_name"]
    $executeAs = $row["execute_as"]

    $markdownContent += "| $schemaName | $moduleName | $executeAs |\n"
}

# Save documentation to a Markdown file
$markdownContent | Out-File -FilePath $OutputFilePath

Write-Host "Impersonation Documentation has been saved to: $OutputFilePath"



-- Obtain a listing of users and roles authorized to modify logic modules

-- Users with permissions
SELECT
    P.type_desc AS principal_type,
    P.name AS principal_name,
    O.type_desc,
    CASE
        WHEN class = 0 THEN DB_NAME()
        WHEN class = 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
        WHEN class = 3 THEN SCHEMA_NAME(major_id)
        ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
    END AS securable_name,
    DP.state_desc,
    DP.permission_name
FROM sys.database_permissions DP
JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR', 'TA', 'P', 'X', 'RF', 'PC', 'IF', 'FN', 'TF', 'U')
WHERE DP.type IN ('AL', 'ALTG') AND DP.class IN (0, 1, 53)

-- Roles with permissions
UNION ALL

SELECT
    R.name AS role_name,
    M.type_desc AS principal_type,
    M.name AS principal_name,
    NULL AS type_desc,
    NULL AS securable_name,
    NULL AS state_desc,
    NULL AS permission_name
FROM sys.database_principals R
JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
WHERE R.name IN ('db_ddladmin', 'db_owner') AND M.name != 'dbo'
ORDER BY principal_type, principal_name, type_desc, securable_name;



-- Obtain a listing of user databases whose owner is a member of a fixed server role

SELECT 
    D.name AS database_name,
    SUSER_SNAME(D.owner_sid) AS owner_name,
    FRM.is_fixed_role_member
FROM sys.databases D
OUTER APPLY (
    SELECT MAX(fixed_role_member) AS is_fixed_role_member
    FROM (
        SELECT IS_SRVROLEMEMBER(R.name, SUSER_SNAME(D.owner_sid)) AS fixed_role_member
        FROM sys.server_principals R
        WHERE is_fixed_role = 1
    ) A
) FRM
WHERE D.database_id > 4
    AND (FRM.is_fixed_role_member = 1 OR FRM.is_fixed_role_member IS NULL)
ORDER BY database_name;


function Check-SqlEncryption {
    param (
        [string]$SqlServerInstance,
        [string]$Database = "master"
    )

    # Load the required .NET assembly
    Add-Type -AssemblyName "System.Data.SqlClient"

    # Connection string for SQL Server
    $connectionString = "Server=$SqlServerInstance;Database=$Database;Integrated Security=True;"

    # Create a SQL connection
    $sqlConnection = New-Object System.Data.SqlClient.SqlConnection
    $sqlConnection.ConnectionString = $connectionString

    # Open the SQL connection
    $sqlConnection.Open()

    try {
        # Check BitLocker status for full-disk encryption
        $bitLockerStatus = (Get-BitLockerVolume).VolumeStatus
        if ($bitLockerStatus -ne "FullyEncrypted") {
            Write-Host "BitLocker is not configured for full-disk encryption. This is a finding."
        }

        # Check encryption state for each user database using TDE
        $tdeStatusQuery = @"
        SELECT DB_NAME(database_id) AS [Database Name], 
            CASE encryption_state 
                WHEN 0 THEN 'No database encryption key present, no encryption'
                WHEN 1 THEN 'Unencrypted'
                WHEN 2 THEN 'Encryption in progress'
                WHEN 3 THEN 'Encrypted'
                WHEN 4 THEN 'Key change in progress'
                WHEN 5 THEN 'Decryption in progress'
                WHEN 6 THEN 'Protection change in progress'
            END AS [Encryption State]
        FROM sys.dm_database_encryption_keys
"@

        $command = $sqlConnection.CreateCommand()
        $command.CommandText = $tdeStatusQuery

        # Execute the TDE status query
        $reader = $command.ExecuteReader()

        # Iterate through the result set
        while ($reader.Read()) {
            $databaseName = $reader["Database Name"]
            $encryptionState = $reader["Encryption State"]

            if ($encryptionState -eq "Unencrypted") {
                Write-Host "The database $databaseName is marked as Unencrypted. This is a finding."
            }
        }
    }
    finally {
        # Close the SQL connection
        $sqlConnection.Close()
    }

    # Display a message to configure Always Encrypted settings manually
    Write-Host "Please review the definitions and contents of relevant tables/columns for Always Encryption settings manually."
}

# Example usage:
# Check-SqlEncryption -SqlServerInstance "YourSqlServerInstance" -Database "master"



# Replace "YourSqlServerInstance" with the actual SQL Server instance name.
$serverInstance = "YourSqlServerInstance"
CheckSqlCryptography $serverInstance

function CheckSqlCryptography($sqlServerInstance) {
    # Connection string for the SQL Server instance
    $connectionString = "Server=$sqlServerInstance;Integrated Security=True;"

    # Load the System.Data.SqlClient assembly
    Add-Type -AssemblyName "System.Data.SqlClient"

    # Create a SqlConnection object
    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString

    try {
        $connection.Open()

        # Check FIPS compliance status
        $isFipsEnabled = CheckFipsCompliance $connection
        if (-not $isFipsEnabled) {
            Write-Host "FIPS compliance is not enabled. This is a finding."
        }

        # Check NIST FIPS certification of symmetric keys
        $uncertifiedAlgorithms = CheckNistFipsCertification $connection
        if ($uncertifiedAlgorithms.Count -gt 0) {
            Write-Host "The following symmetric keys use uncertified NIST FIPS 140-2 algorithms:"
            $uncertifiedAlgorithms | ForEach-Object { Write-Host "$($_.Name): $($_.AlgorithmDescription)" }
            Write-Host "This is a finding."
        }
    }
    finally {
        # Close the connection
        $connection.Close()
    }
}

function CheckFipsCompliance($connection) {
    # Execute a query to check FIPS compliance
    $fipsCommandText = "EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', N'System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy', N'Enabled'"
    $fipsCommand = $connection.CreateCommand()
    $fipsCommand.CommandText = $fipsCommandText
    $fipsEnabled = $fipsCommand.ExecuteScalar()

    return [bool]$fipsEnabled
}

function CheckNistFipsCertification($connection) {
    # Execute a query to check NIST FIPS certification of symmetric keys
    $certificationCommandText = "SELECT DISTINCT name, algorithm_desc FROM sys.symmetric_keys WHERE key_algorithm NOT IN ('D3','A3') ORDER BY name"
    $certificationCommand = $connection.CreateCommand()
    $certificationCommand.CommandText = $certificationCommandText
    $reader = $certificationCommand.ExecuteReader()

    $uncertifiedAlgorithms = @()
    while ($reader.Read()) {
        $algorithm = New-Object PSObject -Property @{
            Name = $reader["name"]
            AlgorithmDescription = $reader["algorithm_desc"]
        }
        $uncertifiedAlgorithms += $algorithm
    }

    return $uncertifiedAlgorithms
}
