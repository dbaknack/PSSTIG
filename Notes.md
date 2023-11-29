
# Automating STIG Compliance with PowerShell and T-SQL

In the realm of cybersecurity and system administration, adhering to Security Technical Implementation Guides (STIGs) is crucial for maintaining a secure and compliant infrastructure. PowerShell and T-SQL (Transact-SQL) provide powerful automation capabilities to streamline the STIG compliance process.

## Introduction

STIGs, developed by the Defense Information Systems Agency (DISA), are configuration standards for secure system implementation. They outline best practices and guidelines to strengthen the security posture of information systems.

This Markdown-formatted introduction aims to provide an overview of how PowerShell and T-SQL can be leveraged to automate and enforce STIG compliance. Through a combination of scripting and querying capabilities, these tools empower administrators to efficiently manage and monitor system configurations.

## Key Objectives

1. **Automation:** PowerShell enables the automation of routine tasks, allowing administrators to script the implementation of STIG requirements across multiple systems.

2. **Querying with T-SQL:** T-SQL provides a robust platform for querying and managing SQL Server databases. This is particularly useful for assessing and ensuring compliance with database-related STIG controls.

3. **Centralized Reporting:** By utilizing PowerShell and T-SQL together, administrators can create centralized reports that highlight the compliance status of various systems and databases.

4. **Continuous Monitoring:** Implementing continuous monitoring scripts ensures that systems remain in compliance over time. PowerShell's scripting capabilities make it easier to schedule and execute these checks.

## How This Guide Can Help

This guide will delve into practical examples and scripts, demonstrating how to use PowerShell and T-SQL to automate STIG compliance checks. It will cover scenarios such as checking user permissions, validating encryption settings, and ensuring configuration consistency.

By following the provided examples, administrators can gain insights into creating their own tailored automation solutions for STIG compliance. This approach not only saves time but also reduces the risk of human error associated with manual checks.

Whether you are responsible for securing Windows environments, SQL Server databases, or both, the combination of PowerShell and T-SQL offers a comprehensive toolkit for maintaining a robust security posture in alignment with STIG requirements.

Let's embark on a journey to harness the automation capabilities of PowerShell and T-SQL for enhanced STIG compliance in your IT infrastructure.
# Importing PowerShell Modules: Step-by-Step Guide

PowerShell modules extend the functionality of PowerShell by providing reusable scripts, functions, and cmdlets. Follow this step-by-step guide to import PowerShell modules.

## Step 1: Identify Module Location

- **Online Gallery:** If the module is available in an online repository like PowerShell Gallery, you can install it directly using the `Install-Module` cmdlet. For example:
  ```powershell
  Install-Module -Name ModuleName
  ```

- **Local Filesystem:** If the module is a local script or folder, ensure it's located in a directory listed in the `$env:PSModulePath` environment variable.

## Step 2: Check Module Installation

To verify if a module is already installed, use the `Get-Module` cmdlet:
```powershell
Get-Module -ListAvailable -Name ModuleName
```

## Step 3: Import the Module

- **Implicit Import:** If the module is in a directory listed in `$env:PSModulePath`, PowerShell automatically imports it when you use a cmdlet from the module.
  
- **Explicit Import:** To manually import a module, use the `Import-Module` cmdlet:
  ```powershell
  Import-Module -Name ModuleName
  ```

## Step 4: Check Imported Modules

To list currently imported modules, use:
```powershell
Get-Module
```

## Step 5: Importing Specific Functions or Cmdlets

If you only need specific functions or cmdlets from a module, use the `Import-Module` cmdlet with the `-Function` or `-Cmdlet` parameter:
```powershell
Import-Module -Name ModuleName -Function FunctionName1, FunctionName2
Import-Module -Name ModuleName -Cmdlet CmdletName1, CmdletName2
```

## Step 6: Automatic Module Loading

To automatically load a module when starting a new PowerShell session, add the `Import-Module` command to your PowerShell profile script (`$Profile`).

```powershell
# Example in $Profile script
Import-Module -Name ModuleName
```

## Step 7: Updating Modules

To update installed modules, use the `Update-Module` cmdlet:

```powershell
Update-Module -Name ModuleName
```

Keep in mind that some modules may require administrative privileges to install or update. Always check module documentation for specific installation instructions.

By following these steps, you can efficiently import and manage PowerShell modules to enhance your scripting and automation capabilities.

---

# PowerShell Functions Documentation

## Check-SqlConfigurations

### Purpose
This function checks specific SQL Server configurations related to contained databases and Windows authentication mode.

### Usage
```powershell
$serverInstance = "YourSqlServerInstance"
$checkResults = Check-SqlConfigurations -serverInstance $serverInstance
```

### Intended Outcome
The function returns a PowerShell custom object with properties `ContainedDatabasesSSMS` and `WindowsAuthenticationSSMS` indicating the status of the respective configurations.

## Execute-SqlQuery

### Purpose
This function executes a SQL query using .NET.

### Usage
```powershell
$connectionString = "YourConnectionString"
$query = "YourSqlQuery"
$result = Execute-SqlQuery -connectionString $connectionString -query $query
```

### Intended Outcome
The function returns the result of the SQL query.

## Configure-SqlBasedOnCheckResults

### Purpose
This function makes changes to SQL Server configurations based on the results of the `Check-SqlConfigurations` function.

### Usage
```powershell
$serverInstance = "YourSqlServerInstance"
Configure-SqlBasedOnCheckResults -serverInstance $serverInstance -checkResults $checkResults
```

### Intended Outcome
The function configures SQL Server settings as needed.

## Check-DatabasePermissions

### Purpose
This function checks database permissions against documented requirements.

### Usage
```powershell
$serverInstance = "YourSqlServerInstance"
$database = "YourDatabaseName"
$permissionsScriptPath = "C:\Path\To\Database permission assignments to users and roles.sql"
Check-DatabasePermissions -serverInstance $serverInstance -database $database -permissionsScriptPath $permissionsScriptPath
```

### Intended Outcome
The function compares actual and documented permissions, reporting any discrepancies.

## Check-DatabaseUsers

### Purpose
This function checks if database users are computer accounts.

### Usage
```powershell
$serverInstance = "YourSqlServerInstance"
$database = "YourDatabaseName"
Check-DatabaseUsers -serverInstance $serverInstance -database $database
```

### Intended Outcome
The function reports whether database users are computer accounts.

## Check-TemporalTableRequirements

### Purpose
This function checks if collecting and keeping historical versions of a table is required.

### Usage
```powershell
$serverInstance = "YourSqlServerInstance"
$database = "YourDatabaseName"
$documentationPath = "C:\Path\To\Documentation.txt"
Check-TemporalTableRequirements -serverInstance $serverInstance -database $database -documentationPath $documentationPath
```

### Intended Outcome
The function checks for temporal tables and ensures the existence of a field documenting the last modification.

---

Certainly! Here's the continuation of the documentation for the provided PowerShell functions:

---

## Get-TablesInDocumentation

### Purpose
This function reads table names from a documentation file and returns them as a PowerShell custom object.

### Usage
```powershell
$documentationPath = "C:\Path\To\Documentation.txt"
$tables = Get-TablesInDocumentation -documentationPath $documentationPath
```

### Intended Outcome
The function returns a PowerShell custom object with properties `schema_name` and `table_name` based on the tables listed in the documentation file.

## Get-HistoricalVersionsRequirement

### Purpose
This function determines if collecting and keeping historical versions of a table is required based on documentation.

### Usage
```powershell
$documentationPath = "C:\Path\To\Documentation.txt"
$historicalVersionsRequired = Get-HistoricalVersionsRequirement -documentationPath $documentationPath
```

### Intended Outcome
The function returns a Boolean indicating whether collecting historical versions is required.

## Check-LastModifiedField

### Purpose
This function checks if a field exists documenting the login and/or user who last modified the record.

### Usage
```powershell
$connectionString = "YourConnectionString"
$lastModifiedFieldExists = Check-LastModifiedField -connectionString $connectionString
```

### Intended Outcome
The function returns a Boolean indicating whether the last modified field exists.

## Check-MSDBConfigurations

### Purpose
This function checks MSDB database configurations related to trustworthiness and owner privileges.

### Usage
```powershell
$serverInstance = "YourSqlServerInstance"
$msdbConfig = Check-MSDBConfigurations -serverInstance $serverInstance
```

### Intended Outcome
The function returns a PowerShell custom object with properties `TrustworthyEnabled` and `OwnerIsPrivileged`.

## Review-MSDBTrustworthy

### Purpose
This function reviews MSDB configurations and determines if trustworthiness is required and authorized.

### Usage
```powershell
$serverInstance = "YourSqlServerInstance"
Review-MSDBTrustworthy -serverInstance $serverInstance -msdbConfig $msdbConfig
```

### Intended Outcome
The function provides insights based on trustworthiness and owner privileges, checks system documentation availability, and suggests further actions.

## Get-SystemDocumentation

### Purpose
This function checks if system documentation is available.

### Usage
```powershell
$documentationPath = "C:\Path\To\SystemDocumentation.txt"
$documentationAvailable = Get-SystemDocumentation -documentationPath $documentationPath
```

### Intended Outcome
The function returns a Boolean indicating whether system documentation is available.

---

Here's the markdown-formatted documentation for the `Check-DatabaseRolesAndPermissions` PowerShell function:

---

# Check-DatabaseRolesAndPermissions

## Purpose

This function checks database roles and memberships for audit maintainers, ensuring that they have the necessary permissions to create and maintain audit specifications.

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.
- `$database`: Specifies the database to check roles and permissions for.
- `$documentationPath`: Specifies the path to the system documentation file containing approved audit maintainer information.

## Usage

```powershell
$serverInstance = "YourSqlServerInstance"
$database = "YourDatabaseName"
$documentationPath = "C:\Path\To\SystemDocumentation.txt"

Check-DatabaseRolesAndPermissions -serverInstance $serverInstance -database $database -documentationPath $documentationPath
```

## Intended Outcome

The function reviews database roles and permissions related to audit maintainership, identifying any discrepancies between documented and authorized roles and permissions.

## Example Output

- If a role membership is not documented and authorized, a finding is reported.
- If a role or user has undocumented permissions, a finding is reported.

## Notes

- Ensure that the system documentation file at `$documentationPath` contains one approved audit maintainer per line.

---

Here's the markdown-formatted documentation for the three PowerShell functions you provided:

---

# Check-PermissionsAndRoles

## Purpose

This function checks users and roles authorized to change stored procedures, functions, and triggers in SQL Server databases.

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.
- `$documentationPath`: Specifies the path to the server documentation file containing authorized users and roles.

## Usage

```powershell
$serverInstance = "YourSqlServerInstance"
$documentationPath = "C:\Path\To\ServerDocumentation.txt"

Check-PermissionsAndRoles -serverInstance $serverInstance -documentationPath $documentationPath
```

## Intended Outcome

The function identifies and reports users and roles that are not authorized to modify specified database objects or types based on the provided documentation.

## Example Output

- If a user or role is not authorized to modify an object, a finding is reported.
- If a user or role's membership is not authorized, a finding is reported.

---

# Check-SchemaOwnership

## Purpose

This function checks the ownership of database schemas against authorized owning principals.

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.
- `$documentationPath`: Specifies the path to the server documentation file containing authorized owning principals.

## Usage

```powershell
$serverInstance = "YourSqlServerInstance"
$documentationPath = "C:\Path\To\ServerDocumentation.txt"

Check-SchemaOwnership -serverInstance $serverInstance -documentationPath $documentationPath
```

## Intended Outcome

The function identifies and reports schemas owned by unauthorized database principals based on the provided documentation.

## Example Output

- If a schema is owned by an unauthorized database principal, a finding is reported.

---

# Check-ObjectOwners

## Purpose

This function checks SQL Server accounts authorized to own database objects.

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.
- `$documentationPath`: Specifies the path to the server documentation file containing authorized object owners.

## Usage

```powershell
$serverInstance = "YourSqlServerInstance"
$documentationPath = "C:\Path\To\ServerDocumentation.txt"

Check-ObjectOwners -serverInstance $serverInstance -documentationPath $documentationPath
```

## Intended Outcome

The function identifies and reports objects owned by unauthorized SQL Server accounts based on the provided documentation.

## Example Output

- If an object is owned by an unauthorized SQL Server account, a finding is reported.

---

Here's the markdown-formatted documentation for the three PowerShell functions you provided:

---

# Check-DatabasePermissions

## Purpose

This function checks users and roles authorized to modify the database structure and logic modules in SQL Server databases.

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.
- `$documentationPath`: Specifies the path to the server documentation file containing authorized users and roles.

## Usage

```powershell
$serverInstance = "YourSqlServerInstance"
$documentationPath = "C:\Path\To\ServerDocumentation.txt"

Check-DatabasePermissions -serverInstance $serverInstance -documentationPath $documentationPath
```

## Intended Outcome

The function identifies and reports users and roles that are not authorized to modify specified database objects or types based on the provided documentation.

## Example Output

- If a user or role is not authorized to modify an object, a finding is reported.
- If a user or role's membership is not authorized, a finding is reported.

---

# Check-DatabaseSecurityPlan

## Purpose

This function checks database properties, recovery model, backup schedule, and restoration testing against a System Security Plan (SSP) document.

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.
- `$sspDocumentPath`: Specifies the path to the System Security Plan (SSP) document.

## Usage

```powershell
$serverInstance = "YourSqlServerInstance"
$sspDocumentPath = "C:\Path\To\SystemSecurityPlan.txt"

Check-DatabaseSecurityPlan -serverInstance $serverInstance -sspDocumentPath $sspDocumentPath
```

## Intended Outcome

The function ensures that database properties, recovery models, backup schedules, and restoration testing align with the requirements specified in the SSP document.

## Example Output

- If the recovery model does not match the documented recovery model, a finding is reported.
- If no backup jobs are found, a finding is reported.
- If there are missing or gaps in backup history, a finding is reported.
- If database recovery testing is not conducted annually or more often, a finding is reported.

---

# Check-DatabaseMasterKeyEncryption

## Purpose

This function checks the encryption status of the Database Master Key for each online database on a SQL Server instance.

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.

## Usage

```powershell
$serverInstance = "YourSqlServerInstance"

Check-DatabaseMasterKeyEncryption -serverInstance $serverInstance
```

## Intended Outcome

The function identifies databases where the Database Master Key is encrypted with a password and checks if the password meets specified requirements.

## Example Output

- If a Database Master Key is encrypted with a password, the function reports the finding and checks if the password meets specified requirements.

---

# Check-DatabaseMasterKeyEncryptionStatus

## Purpose

This function checks if databases require encryption of the Database Master Key and verifies compliance based on a System Security Plan (SSP).

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.

## Usage

```powershell
$serverInstance = "YourSqlServerInstance"

Check-DatabaseMasterKeyEncryptionStatus -serverInstance $serverInstance
```

## Intended Outcome

The function identifies databases that require encryption of the Database Master Key and checks compliance with the encryption approval and additional requirements specified in the SSP.

## Example Output

- If a database requires encryption of the Database Master Key and is not approved in the SSP, a finding is reported.
- If additional requirements are specified in the SSP, the function checks if they are in place.

---

Here is the markdown-formatted documentation for the additional PowerShell functions you provided:

---

# Execute-SqlQuery

## Purpose

This function executes a SQL query using .NET and returns the result as a DataTable.

## Parameters

- `$connectionString`: Specifies the connection string for the SQL Server instance.
- `$query`: Specifies the SQL query to be executed.

## Usage

```powershell
# Example usage
$serverInstance = "YourSqlServerInstance"
$databaseName = "YourDatabaseName"
$backupFilePath = "C:\Path\To\BackupFile.bak"
$restoreFilePath = "C:\Path\To\BackupFile.bak"

# Backup the database
Backup-Database -serverInstance $serverInstance -databaseName $databaseName -backupFilePath $backupFilePath

# Restore the database
Restore-Database -serverInstance $serverInstance -databaseName $databaseName -restoreFilePath $restoreFilePath
```

## Intended Outcome

The function is intended to be a reusable utility for executing SQL queries against a SQL Server database.

---

# Check-EncryptionAndBackupProcedures

## Purpose

This function checks encryption requirements and backup procedures for a SQL Server database.

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.

## Usage

```powershell
# Example usage
$serverInstance = "YourSqlServerInstance"

Check-EncryptionAndBackupProcedures -serverInstance $serverInstance
```

## Intended Outcome

The function checks whether data-at-rest encryption is required and verifies backup procedures for a specified certificate.

## Example Output

- If encryption of data at rest is not required, the function reports that it's not a finding.
- If certificate backup procedures or evidence do not exist, a finding is reported.
- If procedures do not indicate offline and off-site storage, a finding is reported.
- If procedures do not indicate access restrictions, a finding is reported.

---

# Check-SeparateSecurityDomain

## Purpose

This function checks if security-related functionality in user-defined databases is stored separately in a dedicated security schema.

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.

## Usage

```powershell
# Example usage
$serverInstance = "YourSqlServerInstance"

Check-SeparateSecurityDomain -serverInstance $serverInstance
```

## Intended Outcome

The function examines user-defined databases for security-related functionality and checks if such functionality is stored in a separate security domain.

## Example Output

- If security-related functionality is found and not stored in a separate security domain, a finding is reported.

---

# Check-ColumnConstraints

## Purpose

This function checks column constraints and data types for user-defined databases in a SQL Server instance.

## Parameters

- `$serverInstance`: Specifies the SQL Server instance to connect to.
- `$databaseName`: Specifies the name of the database to check.

## Usage

```powershell
# Example usage
$serverInstance = "YourSqlServerInstance"
$databaseName = "YourDatabaseName"

Check-ColumnConstraints -serverInstance $serverInstance -databaseName $databaseName
```

## Intended Outcome

The function retrieves column information and checks for specific constraints and data types, reporting findings accordingly.

## Example Output

- If a column lacks a primary key constraint, an error is reported.
- If a column has an unexpected data type, an error is reported.

---

# Reviewing and Securing Error Messages

## Audit Code

- Examine the application code, stored procedures, and triggers to identify points where errors are raised and handled.
- Look for instances where error messages are constructed or logged.

## Use Generic Messages

- Avoid including detailed technical information in error messages that could expose sensitive information.
- Provide generic messages to users and log more detailed errors internally for troubleshooting.

## Logging and Monitoring

- Implement centralized logging to capture error messages, ensuring that sensitive details are not logged where unauthorized personnel can access them.
- Set up monitoring systems to alert administrators of critical errors without exposing sensitive details in notifications.

## Custom Error Handling

- Implement custom error handling mechanisms to control the information exposed in error messages.
- Capture errors at different levels (e.g., application, database) and handle them appropriately.

## Avoid Exposing Database Structure

- Refrain from exposing database schema or structure details in error messages, as this information can be exploited by attackers.

## Data Masking

- Implement data masking techniques to replace sensitive information with masked or obfuscated values in error messages if necessary.

## Regular Code Reviews

- Conduct regular code reviews with a focus on error handling and message construction to ensure adherence to security best practices.

## Security Testing

- Perform security testing, including penetration testing and code analysis tools, to identify any potential vulnerabilities related to error messages.

## Educate Developers

- Educate developers on secure coding practices, including the importance of not exposing sensitive information in error messages.

## Compliance Requirements

- Consider compliance requirements (e.g., GDPR, HIPAA) related to data protection and ensure that error messages comply with these regulations.

---

# Security Labeling

## Understand Security Labeling Requirements

- Clearly define security labeling requirements based on organizational policies, regulatory compliance, or security standards.

## Choose a Security Labeling Solution

- Evaluate whether a third-party solution or a built-in SQL Server feature (e.g., Row-Level Security) aligns with requirements.

## Implement Third-Party Solution

- If a third-party solution is chosen, follow the vendor's documentation to implement the security labeling solution.

## Implement SQL Server Row-Level Security (RLS)

- If RLS is chosen, define and apply security policies to control access to rows based on values in each row.
- Use functions to determine user access to specific rows based on security labels or other criteria.

## Example - SQL Server RLS

```sql
-- Create a function to determine access based on security labels
CREATE FUNCTION dbo.fn_security_predicate(@security_label NVARCHAR(255))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_security_result
WHERE @security_label = 'Sensitive';

-- Create a security policy on a table
CREATE SECURITY POLICY SecurityLabelPolicy
ADD FILTER PREDICATE dbo.fn_security_predicate(SecurityLabelColumn) ON dbo.YourTable,
ADD BLOCK PREDICATE dbo.fn_security_predicate(SecurityLabelColumn) ON dbo.YourTable;

-- Enable the security policy
ALTER TABLE dbo.YourTable ENABLE SECURITY POLICY SecurityLabelPolicy;



## Usage

### Check-ObjectOwnershipAndAuthorization Function

#### Purpose
This PowerShell function checks SQL Server database for issues related to schema and object ownership, as well as authorization delegation.

#### Outcome
The function provides information on:
- Schemas not owned by the schema or dbo.
- User-defined objects owned by an individual principal.
- Database users delegated the right to assign additional permissions.

#### Additional Details
- Replace "YourServerInstance" and "YourDatabase" with the actual SQL Server instance and database details.
- The function connects to the specified SQL Server, executes queries to identify ownership and delegation issues, and outputs the results.

```powershell
# Run the function
Check-ObjectOwnershipAndAuthorization
```

### Grant-PermissionToUser Function

#### Purpose
This PowerShell function grants a specified permission to a user in a SQL Server database.

#### Outcome
The function executes a GRANT statement to provide the specified permission to the user.

#### Additional Details
- Replace "YourServerInstance" and "YourDatabase" with the actual SQL Server instance and database details.
- Example: Grant SELECT permission to a user.

```powershell
Grant-PermissionToUser -userName "YourUserName" -permission "SELECT"
```

### SQL Queries

#### Purpose
These SQL queries provide insights into the SQL Server database, highlighting ownership, authorization, and encryption-related issues.

#### Outcome
The queries return information on:
- Schemas not owned by the schema or dbo.
- User-defined objects owned by an individual principal.
- Database users delegated the right to assign additional permissions.
- Stored procedures and functions using impersonation.
- Users and roles authorized to modify logic modules.
- User databases whose owner is a member of a fixed server role.
- Encryption state for each user database using Transparent Data Encryption (TDE).

#### Additional Details
- Replace "YourSqlServerInstance" with the actual SQL Server instance name.

### Check-SqlEncryption Function

#### Purpose
This PowerShell function checks SQL Server database encryption settings, including BitLocker and Transparent Data Encryption (TDE).

#### Outcome
The function outputs findings related to BitLocker status and TDE encryption state for each user database.

#### Additional Details
- Replace "YourSqlServerInstance" with the actual SQL Server instance name.
- Example usage:

```powershell
# Example usage:
Check-SqlEncryption -SqlServerInstance "YourSqlServerInstance" -Database "master"
```

### CheckSqlCryptography Function

#### Purpose
This PowerShell function checks cryptographic settings on a SQL Server, including FIPS compliance and NIST FIPS certification of symmetric keys.

#### Outcome
The function outputs findings related to FIPS compliance and identifies symmetric keys using uncertified NIST FIPS 140-2 algorithms.

#### Additional Details
- Replace "YourSqlServerInstance" with the actual SQL Server instance name.
- Example usage:

```powershell
# Example usage:
$serverInstance = "YourSqlServerInstance"
CheckSqlCryptography $serverInstance
```