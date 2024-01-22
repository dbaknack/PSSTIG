
-- table for final results
declare @finalAssesment table (
    CheckResult			int,			-- either 1 for a finding 0 for not a finding
    ResultValue			nvarchar(100),	-- what value was evaluated
    ResultDescripton	nvarchar(100)	-- check description
)
               
declare
    @finding_condition_met	int
    ,@CheckResult			int
    ,@ResultValue			varchar(100)
    ,@ResultDescripton		varchar(100)

-- finding condition is initalized to 0
set @finding_condition_met = 0

-- filter out internal system only principals
;with cte_Principals as
(
	select *
	from (
		select *
		from (
			SELECT p.name AS Principal, 
			p.type_desc AS Type, 
			sp.permission_name AS Permission,  
			sp.state_desc AS State 
			FROM sys.server_principals p 
			INNER JOIN sys.server_permissions sp ON p.principal_id = sp.grantee_principal_id 
			WHERE sp.permission_name = 'CONTROL SERVER' 
			OR sp.state = 'W' 
		) MyPrincipals
		where Principal not like ('##MS_SchemaSigningCertificate%')
	) FilteredLikePrincipal
	where Principal not in (
		'##MS_AgentSigningCertificate##'
	   ,'##MS_PolicySigningCertificate##'
	   ,'##MS_SmoExtendedSigningCertificate##'
	   ,'##MS_SQLAuthenticatorCertificate##'
	   ,'##MS_SQLReplicationSigningCertificate##'
	   ,'##MS_SQLResourceSigningCertificate##'
	)
)
select @ResultValue = (count(*))
from cte_Principals

if(@ResultValue) != '0'
begin
	set @finding_condition_met	= 1
	set @ResultDescripton		= 'Principal other than internal ones has control server permissions.'
end
else
begin
	set @ResultDescripton		= 'No other principal other than internal ones, have control server permissions.'
end

insert into @finalAssesment
Select
	 [CheckResult]		= @finding_condition_met
	,[ResultValue]		= @ResultValue
	,[ResultDescripton] = @ResultDescripton

select * from @finalAssesment