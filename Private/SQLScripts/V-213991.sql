-- SQL Server must maintain a separate execution domain for each executing process.
-- If "[result]" is a "1" and CLR is not required, this is a finding.

SELECT
[result] = value_in_use 
FROM sys.configurations 
WHERE name = 'clr enabled'

