-- this control allows you to flip the finding if needed manually
-- set to 0 to not use manual override, set to 1 to enable.
-- when enabled, set @value to 0 for 'not_a_finding' or 1 for 'open'
declare @enableManualOverride			bit     = 0
declare	@value							int     = 0

declare @openResult_Description			varchar(max)
declare @notafinding_ResultDescription	varchar(max)
set @openResult_Description         = 'Total number of principals with execute permissision with access to the registry.'
set @notafinding_ResultDescription  = 'SQL Server execute permissions to access the registry must be revoked, unless specifically required and approved.'


if(@enableManualOverride) = 0
begin
    ;WITH cte_temp AS (
        SELECT
        OBJECT_NAME(major_id) AS [Stored Procedure]
        ,dpr.NAME AS [Principal]
        FROM sys.database_permissions AS dp
        INNER JOIN sys.database_principals AS dpr ON dp.grantee_principal_id = dpr.principal_id
        WHERE major_id IN (
        OBJECT_ID('xp_regaddmultistring')
        ,OBJECT_ID('xp_regdeletekey')
        ,OBJECT_ID('xp_regdeletevalue')
        ,OBJECT_ID('xp_regenumvalues')
        ,OBJECT_ID('xp_regenumkeys')
        ,OBJECT_ID('xp_regremovemultistring')
        ,OBJECT_ID('xp_regwrite')
        ,OBJECT_ID('xp_instance_regaddmultistring')
        ,OBJECT_ID('xp_instance_regdeletekey')
        ,OBJECT_ID('xp_instance_regdeletevalue')
        ,OBJECT_ID('xp_instance_regenumkeys')
        ,OBJECT_ID('xp_instance_regenumvalues')
        ,OBJECT_ID('xp_instance_regremovemultistring')
        ,OBJECT_ID('xp_instance_regwrite')
        )
        AND dp.[type] = 'EX'
    )
    SELECT
        case when count(*) > 0
        then 1 else 0
        end as [CheckResults],
        [CheckValue] = count(*),
        case when count (*) > 0
        then @openResult_Description
        else @notafinding_ResultDescription
        end as [ResultDescription]
    FROM cte_temp;
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
