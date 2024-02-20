DECLARE @SimulateContainedDatabases BIT = 0; -- Set to 1 to simulate contained databases as used
DECLARE @SimulateContainedUsers BIT     = 0; -- Set to 1 to simulate contained users using SQL Authentication

-- Check for Contained Databases
DECLARE @ContainedDatabasesResult TABLE (DatabaseName NVARCHAR(255));
-- Actual check for contained databases


-- Sample entry for simulated contained databases
IF @SimulateContainedDatabases = 1
BEGIN
    INSERT INTO @ContainedDatabasesResult (DatabaseName)
    VALUES ('SampleDB1'), ('SampleDB2'), ('SampleDB3');
END

IF @SimulateContainedDatabases = 0
BEGIN
    INSERT INTO @ContainedDatabasesResult (DatabaseName)
    SELECT name
    FROM sys.databases
    WHERE containment = 1;
END

SELECT
    'ContainedDatabases' AS CheckType,
    CASE
        WHEN @SimulateContainedDatabases = 1 OR EXISTS (SELECT * FROM @ContainedDatabasesResult)
        THEN
            '{"result": {"value": 1, "databases": [' +
            ISNULL(
                STUFF(
                    (
                        SELECT ',"' + DatabaseName + '"'
                        FROM @ContainedDatabasesResult
                        FOR XML PATH(''), TYPE
                    ).value('.', 'NVARCHAR(MAX)'), 1, 1, ''
                ), '0'
            ) +
            '], "comments": ["Finding: Contained databases are used.", "Server documentation should be checked for authorized contained database users.", "Possible reasons for using contained databases include: data portability, simplified database management, and easier migration across environments."], "fixDescription": "Ensure authorized contained database users are not using SQL Authentication."}}'
        ELSE
            '{"result": {"value": 0, "databases": 0, "comments": ["No finding: Contained databases are not used."], "fixDescription": "No action required."}}'
    END AS Result;

-- Check for Contained Database Users using SQL Authentication
DECLARE @ContainedUsersResult TABLE (
    DatabaseName NVARCHAR(255),
    UserName NVARCHAR(255),
    AuthenticationType INT
);

-- Sample entry for simulated contained users
IF @SimulateContainedUsers = 1
BEGIN
    INSERT INTO @ContainedUsersResult (DatabaseName, UserName, AuthenticationType)
    VALUES
        ('SampleDB1', 'User1', 2),
        ('SampleDB2', 'User2', 2),
        ('SampleDB3', 'User3', 2);
END

-- Actual check for contained users
IF @SimulateContainedUsers = 0
BEGIN
    INSERT INTO @ContainedUsersResult (DatabaseName, UserName, AuthenticationType)
    EXEC sp_MSforeachdb '
    USE [?];
    SELECT DB_NAME() AS DatabaseName, name AS UserName, authentication_type
    FROM sys.database_principals
    WHERE authentication_type = 2';
END
SELECT
    'ContainedUsers' AS CheckType,
    CASE
        WHEN @SimulateContainedUsers = 1 OR EXISTS (SELECT * FROM @ContainedUsersResult)
        THEN
            '{"result": {"value": 1, "users": [{' +
            ISNULL(
                STUFF(
                    (
                        SELECT '{"DatabaseName":"' + DatabaseName + '","UserName":"' + UserName + '","AuthenticationType":' + CAST(AuthenticationType AS NVARCHAR(10)) + '},'
                        FROM @ContainedUsersResult
                        FOR XML PATH(''), TYPE
                    ).value('.', 'NVARCHAR(MAX)'), 1, 1, ''
                ), '0'
            ) +
            '], "comments": ["Finding: Contained database users are using SQL Authentication.", "Check the list of contained database users.", "Possible reasons for using SQL Authentication for contained users include: application compatibility, security requirements, and legacy system integration."], "fixDescription": "Review and update authentication type for contained database users."}}'
        ELSE
            '{"result": {"value": 0, "users": [], "comments": ["No finding: Contained database users are not using SQL Authentication."], "fixDescription": "No action required."}}'
    END AS Result;
