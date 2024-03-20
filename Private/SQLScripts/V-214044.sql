-- this control allows you to flip the finding if needed manually
-- set to 0 to not use manual override, set to 1 to enable.
-- when enabled, set @value to 0 for 'not_a_finding' or 1 for 'open'
declare @enableManualOverride			bit = 0
declare	@value							bit = 0

declare @openResult_Description			varchar(max)
declare @notafinding_ResultDescription	varchar(max)
set @openResult_Description = 'SQL Server instance is dicoverable.'
set @notafinding_ResultDescription = 'SQL Server instance is not dicoverable.'


-- table for condition results
declare @Results table (
    [Hidden] char(3)
)

DECLARE @HiddenInstance INT 
EXEC master.dbo.Xp_instance_regread 
 N'HKEY_LOCAL_MACHINE', 
 N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib', 
 N'HideInstance', 
 @HiddenInstance output 

 --declare @HiddenInstance int
INSERT INTO  @Results
SELECT CASE
    WHEN @HiddenInstance = 0
    AND Serverproperty('IsClustered') = 0 THEN 'No'
    ELSE 'Yes'
    END AS [Hidden]


if(@enableManualOverride) = 1
begin
select
	case when @value = 0
		then 0
		else 1
		end as [CheckResults],
	case when @value = 0
		then 'Yes' -- not a finding
		else 'No'	-- finding
		end as [CheckValue],
	case when @value = 1
		then @openResult_Description
		else @notafinding_ResultDescription
	end as [ResultDescription]
 from @Results
end

if(@enableManualOverride) = 0
begin
select
	case when [Hidden] = 'no'
		then 1 -- not a finding
		else 0	-- finding
		end as [CheckResults],
	[CheckValue] = [Hidden],
	case when [Hidden] = 'no'
		then @openResult_Description
		else @notafinding_ResultDescription
	end as [ResultDescription]
 from @Results
end
