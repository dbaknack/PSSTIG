-- this control allows you to flip the finding if needed manually
-- set to 0 to not use manual override, set to 1 to enable.
-- when enabled, set @value to 0 for 'not_a_finding' or 1 for 'open'
declare @enableManualOverride			bit = 0
declare	@value							bit = 0

declare @openResult_Description			varchar(max)
declare @notafinding_ResultDescription	varchar(max)
set @openResult_Description         = 'System documentation needs to be reviewed to determine the use of External scripts feature is required AND authorized.'
set @notafinding_ResultDescription  = 'External scripts feature is currently disabled.'

-- table for final results
declare @final_assesment table (
    check_result nvarchar(100),
    check_value  nvarchar(100),
    result_type  nvarchar(100)
)

-- table for condition results
declare @Results table (
    name varchar(100),
    minumum			int,
    maximum			int,
	config_value	int,
	run_value		int
)


EXEC SP_CONFIGURE 'show advanced options', '1';
RECONFIGURE WITH OVERRIDE;

INSERT INTO  @Results
EXEC SP_CONFIGURE 'external scripts enabled'


if(@enableManualOverride) = 1
begin
select
	[CheckResults]	= @value,
	[CheckValue]	= @value,
	case when @value = 1
		then @openResult_Description
		else @notafinding_ResultDescription
	end as [ResultDescription]
 from @Results
end

if(@enableManualOverride) = 0
begin
select
	[CheckResults]	= config_value,
	[CheckValue]	= config_value,
	case when config_value = 1
		then @openResult_Description
		else @notafinding_ResultDescription
	end as [ResultDescription]
 from @Results
end
