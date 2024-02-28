DECLARE @IsProduction BIT = 1; -- Set to 1 if the system is identified as production

DECLARE @JsonResult NVARCHAR(MAX);

IF @IsProduction = 1
BEGIN
    IF EXISTS (
        SELECT 1
        FROM sys.databases
        WHERE name IN ('pubs', 'Northwind', 'AdventureWorks', 'WorldwideImporters')
    )
    BEGIN
        SET @JsonResult = 
            '{"CheckType": "DatabaseCheck", "result": {"value": 1, "comments": ["Finding: Production system contains one or more demonstration databases."], "fixDescription": "Review and update database configurations."}}';
    END
    ELSE
    BEGIN
        SET @JsonResult = 
            '{"CheckType": "DatabaseCheck", "result": {"value": 0, "comments": ["No finding: No demonstration databases found on the production system."], "fixDescription": "No action required."}}';
    END;
END
ELSE
BEGIN
    SET @JsonResult = 
        '{"CheckType": "DatabaseCheck", "result": {"value": 0, "comments": ["No finding: This system is not identified as a production system."], "fixDescription": "No action required."}}';
END;

-- Display or use @JsonResult as needed
SELECT [Results] = @JsonResult;
