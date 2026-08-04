// =============================================================================
//  Abstract Security - Microsoft Entra ID log streams -> Event Hub
//  Version : 1.0
//  Author  : Abstract Security - Solutions Engineering
//  Scope   : TENANT
//
//  Why this is a SEPARATE template from the policy pack
//  ----------------------------------------------------
//  Entra ID activity logs (sign-ins, audit, provisioning, identity-protection
//  risk, Graph activity) are NOT Azure Monitor resource logs. They are a single
//  TENANT-level diagnostic setting on the microsoft.aadiam provider. That means:
//    * Azure Policy cannot manage them - there is nothing per-subscription to
//      evaluate, so no DeployIfNotExists can reach them.
//    * They are configured ONCE per tenant, not once per subscription. Adding a
//      new subscription changes nothing here.
//    * The deployment must target TENANT scope, so it runs from the CLI or
//      PowerShell - the portal "Deploy to Azure" button cannot do tenant scope.
//  This is a feature, not a gap: one command onboards identity telemetry for the
//  entire organisation, permanently.
//
//  Requires
//  --------
//    * Security Administrator on the Entra tenant (Attribute Log Administrator
//      as well if you enable CustomSecurityAttributeAuditLogs).
//    * The Event Hub must already exist. Azure never creates it for you here.
//    * Entra ID P1/P2 for several categories - see entraLogCategories below.
//
//  Deploy
//  ------
//    az deployment tenant create \
//      --location eastus \
//      --template-file templates/tenant/entra-diagnostics.bicep \
//      --parameters eventHubAuthorizationRuleId=<namespace-auth-rule-id> \
//                   eventHubName=abs-prod-entra
//
//  Expect up to THREE DAYS before the first Entra records land in the hub -
//  Microsoft documents this latency for Entra diagnostic settings. Do not treat
//  an empty hub in the first hour as a failure.
// =============================================================================

targetScope = 'tenant'

@description('Name of the Entra ID diagnostic setting. Multiple settings are allowed, so this can sit alongside a setting you already send to another SIEM.')
@minLength(1)
@maxLength(260)
param settingName string = 'abstract-entra-logstream'

@description('Resource ID of an Event Hubs namespace authorization rule with Send rights. Use the abstractDiagnosticsAuthRuleId output of main.bicep.')
param eventHubAuthorizationRuleId string

@description('Event Hub that receives the Entra ID stream. Give identity its own hub so it can be partitioned and scaled independently of resource logs.')
param eventHubName string = 'abs-prod-entra'

@description('''
Entra ID log categories to stream. Defaults to the security-relevant set that
every Abstract Entra detection is built on.

Licensing / availability notes:
  SignInLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs,
  ManagedIdentitySignInLogs   - Entra ID P1 or P2
  RiskyUsers, UserRiskEvents,
  RiskyServicePrincipals, ServicePrincipalRiskEvents,
  RiskyAgents, AgentRiskEvents - Entra ID Protection (P2)
  ProvisioningLogs             - only populated when you provision via Entra
  ADFSSignInLogs               - only when AD FS is in use
  NetworkAccessTrafficLogs,
  EnrichedOffice365AuditLogs,
  RemoteNetworkHealthLogs      - only with Global Secure Access / Entra
                                 Internet Access + Private Access
  MicrosoftGraphActivityLogs   - high volume; the single best source for
                                 "what did this token actually do"
  MicrosoftServicePrincipalSignInLogs - preview, VERY high volume, first-party
                                 service-to-service. Microsoft advises against
                                 acting on it. Off by default here.
  CustomSecurityAttributeAuditLogs - needs Attribute Log Administrator, and
                                 Microsoft recommends keeping it separate from
                                 the directory audit stream.
  B2CRequestLogs               - Azure AD B2C tenants only.

Selecting a category your tenant does not license or use is harmless - it simply
produces no records.
''')
param entraLogCategories array = [
  'AuditLogs'
  'SignInLogs'
  'NonInteractiveUserSignInLogs'
  'ServicePrincipalSignInLogs'
  'ManagedIdentitySignInLogs'
  'ProvisioningLogs'
  'ADFSSignInLogs'
  'RiskyUsers'
  'UserRiskEvents'
  'RiskyServicePrincipals'
  'ServicePrincipalRiskEvents'
  'MicrosoftGraphActivityLogs'
]

// ---------------------------------------------------------------------------
// The tenant-level Entra diagnostic setting.
// Provider name is lower-case `microsoft.aadiam` by convention; API version
// 2017-04-01 is the current one - there has never been a newer stable version.
// ---------------------------------------------------------------------------
resource entraDiagnostics 'microsoft.aadiam/diagnosticSettings@2017-04-01' = {
  name: settingName
  properties: {
    eventHubAuthorizationRuleId: eventHubAuthorizationRuleId
    eventHubName: eventHubName
    logs: [for category in entraLogCategories: {
      category: category
      enabled: true
    }]
  }
}

output diagnosticSettingName string = entraDiagnostics.name
output eventHubName string = eventHubName
output streamedCategories array = entraLogCategories

output abstractOnboarding object = {
  scope: 'Microsoft Entra ID tenant - one setting covers the whole organisation'
  policyManaged: 'No. Entra diagnostic settings are tenant-level; Azure Policy has no per-subscription object to evaluate. This template IS the automation.'
  firstDataLatency: 'Up to 3 days for the first records, per Microsoft documentation.'
  notIncluded: 'Microsoft 365 unified audit (Exchange/SharePoint/Teams) and Defender XDR advanced hunting are separate streams - see docs/azure-log-streams.md'
}
