-- this control allows you to flip the finding if needed manually
-- set to 0 to not use manual override, set to 1 to enable.
-- when enabled, set @value to 0 for 'not_a_finding' or 1 for 'open'
declare @enableManualOverride			bit = 0
declare	@value							bit = 0

declare @openResult_Description			varchar(max)
declare @notafinding_ResultDescription	varchar(max)
set @openResult_Description         = 'Execution of startup stored procedures must be restricted to necessary cases only.'
set @notafinding_ResultDescription  = 'No stored procedures with a ExecIsStartup of 1 is set.'

if(@enableManualOverride) = 0
begin
    if(
        select count(*)
        from(
            Select [name] as StoredProc
            From sys.procedures
            Where OBJECTPROPERTY(OBJECT_ID, 'ExecIsStartup') = 1
        ) checkStoredProc
    ) = 0
    begin
        select
            [CheckResults]	= @value,
            [CheckValue]	= @value,
            case when @value = 1
                then @openResult_Description
                else @notafinding_ResultDescription
            end as [ResultDescription]
    end
end
if(@enableManualOverride) = 1
begin
select
	[CheckResults]	= @value,
	[CheckValue]	= @value,
	case when @value = 1
		then @openResult_Description
		else @notafinding_ResultDescription
	end as [ResultDescription]
end
