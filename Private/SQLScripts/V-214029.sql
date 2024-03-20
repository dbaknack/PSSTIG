declare @enableManualOverride			bit = 0
declare	@value							bit = 0

declare @openResult_Description			varchar(max)
declare @notafinding_ResultDescription	varchar(max)
set @openResult_Description         = 'SQL Server default account [sa] must have its name changed.'
set @notafinding_ResultDescription  = 'SQL Server default account [sa] does not need to be changed.'


declare @SAName varchar(25)

set  @SAName = (
    SELECT name
    FROM sys.sql_logins
    WHERE [name] = 'sa' OR [principal_id] = 1
)

if(@enableManualOverride) = 0
begin
    USE master;
    if(@SAName) != 'sa'
    begin
        select
        [CheckResults]	    = 0,
        [CheckValue]	    = (@SAName),
        [ResultDescription] = @notafinding_ResultDescription
    end

    if(@SAName) = 'sa'
    begin
    select
        [CheckResults]	    = 1,
        [CheckValue]	    = (@SAName),
        [ResultDescription] = @openResult_Description
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
