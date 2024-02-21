SELECT 
        [Result] = '{' +
        '"ProductVersion":"' + CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(MAX)) + '",' +
        '"ProductLevel":"' + CAST(SERVERPROPERTY('ProductLevel') AS NVARCHAR(MAX)) + '",' +
        '"ProductMajorVersion":"' + CAST(SERVERPROPERTY('ProductMajorVersion') AS NVARCHAR(MAX)) + '",' +
        '"ResourceLastUpdateDateTime":"' + CONVERT(VARCHAR(8), SERVERPROPERTY('ResourceLastUpdateDateTime'), 112) + '"' +
        '}';