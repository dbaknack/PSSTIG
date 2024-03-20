declare @enableManualOverride			bit = 0
declare	@value							bit = 0

declare @openResult_Description			varchar(max)
declare @notafinding_ResultDescription	varchar(max)
set @openResult_Description         = 'SQL Server default account [sa] must have its name changed.'
set @notafinding_ResultDescription  = 'SQL Server default account [sa] does not need to be changed.'




SELECT [name], is_expiration_checked, is_policy_checked
FROM sys.sql_logins
