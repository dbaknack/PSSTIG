declare @enableManualOverride			bit = 0
declare	@value							bit = 0

declare @openResult_Description			varchar(max)
declare @notafinding_ResultDescription	varchar(max)
set @openResult_Description         = 'SQL Server Mirroring endpoint must utilize AES encryption.'
set @notafinding_ResultDescription  = 'SQL Server Mirroring endpoint is using AES encryption.'

if(@enableManualOverride) = 0
    begin
    if(
        select count(*)
        from (
        SELECT name, type_desc, encryption_algorithm_desc
        FROM sys.database_mirroring_endpoints
        WHERE encryption_algorithm != 2
        ) checkEnpoints
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
