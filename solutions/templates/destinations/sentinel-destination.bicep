// =============================================================================
//  Abstract Security - Azure Sentinel DESTINATION onboarding (Bicep)
//  Version : 3.0
//  Author  : Abstract Security - Solutions Engineering
//
//  Provisions the Azure side of the Abstract "Azure Sentinel Destination"
//  integration - i.e. everything needed for Abstract to deliver events into
//  Microsoft Sentinel through the Azure Monitor Logs Ingestion API
//  (docs.abstractsecurity.app -> Integrations -> Destination -> Azure Sentinel
//  Destination).
//
//  Full stack (resource-group scope):
//    1. Log Analytics workspace     (create new, or reference an existing one
//                                     in this resource group)
//    2. Microsoft Sentinel          (onboarding state enabled on the workspace)
//    3. Data Collection Endpoint    (DCE - the ingestion endpoint)
//    4. Custom log table (*_CL)     (DCR-based, with a parameterizable schema)
//    5. Data Collection Rule (DCR)  (stream declaration -> workspace table)
//    6. RBAC on the DCR             (Monitoring Metrics Publisher + Monitoring
//                                     Contributor) for the supplied service
//                                     principal, per the Abstract docs.
//
//  NOTE: an Entra app registration + client secret CANNOT be created in ARM.
//  Create the app first (or have Abstract Solutions create it), pass its
//  service principal OBJECT id as principalId, and enter the Client ID /
//  Client Secret / Tenant ID directly in the Abstract destination modal.
//
//  The deployment OUTPUTS map field-for-field to the Abstract modal:
//    Data Collection Rule ID   -> dataCollectionRuleImmutableId
//    Data Collection Endpoint  -> dataCollectionEndpointUrl
//    Log Stream Name           -> logStreamName  (Custom-<table>)
//
//  Compile to ARM:  az bicep build --file sentinel-destination.bicep \
//                       --outfile sentinel-destination.azuredeploy.json
// =============================================================================

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------
@description('Azure region for the workspace, DCE and DCR. Keep these consistent (the DCE/DCR must be in the same region as the workspace).')
param location string = resourceGroup().location

@description('Tags applied to every created resource that supports tags.')
param tags object = {}

@description('Resource-specific tags, keyed by fully qualified Azure resource type.')
param tagsByResource object = {}

// ---------------------------------------------------------------------------
// Log Analytics workspace + Sentinel
// ---------------------------------------------------------------------------
@description('Create a new Log Analytics workspace. Set false to target an EXISTING workspace in THIS resource group (provide its name in workspaceName).')
param createWorkspace bool = true

@description('Workspace name. When creating: leave empty to auto-generate (abstract-sentinel-<hash>). When using an existing workspace: the exact name of that workspace (must live in this resource group).')
param workspaceName string = ''

@description('Workspace pricing tier. PerGB2018 is the standard pay-as-you-go tier.')
@allowed(['PerGB2018', 'CapacityReservation', 'Free', 'Standalone', 'PerNode'])
param workspaceSku string = 'PerGB2018'

@description('Workspace data retention in days (only applied when creating a new workspace).')
@minValue(7)
@maxValue(730)
param workspaceRetentionDays int = 90

@description('Enable Microsoft Sentinel on the workspace (only applied when creating a new workspace; assumed already enabled for existing workspaces).')
param enableSentinel bool = true

@description('Region of the EXISTING workspace (Existing mode only). The DCE and DCR MUST be created in the same region as the target workspace, so if your existing workspace is in a different region than this deployment, set it here (e.g. eastus2). Leave empty to use the deployment location.')
param existingWorkspaceLocation string = ''

// ---------------------------------------------------------------------------
// Data Collection Endpoint + Rule + custom table
// ---------------------------------------------------------------------------
@description('Name of the Data Collection Endpoint (DCE) that receives data from Abstract.')
param dataCollectionEndpointName string = 'abstract-dce'

@description('Name of the Data Collection Rule (DCR) that routes data into the workspace table.')
param dataCollectionRuleName string = 'abstract-dcr'

@description('Custom log table name. MUST end in _CL. Enter this (as the stream Custom-<table>) in the "Log Stream Name" field of the Abstract destination modal.')
param customTableName string = 'AbstractEventLogs_CL'

@description('Custom table columns. Leave empty (recommended) to use the generated ACS schema: one column per top-level key of the event Abstract sends, with a DCR transformation that sets TimeGenerated. Supply columns only for a custom payload shape; the DCR stream then uses the same columns and transformKql.')
param tableColumns array = []

@description('DCR transformation used only when tableColumns is supplied. The generated schema carries its own transformation.')
param transformKql string = 'source'

@description('Send the Data Collection Rule\'s ingestion errors (rejected requests, malformed payloads, limit and transformation errors) to the DCRLogErrors table in the workspace. Without it, data Azure refuses or drops is invisible to the customer and to Abstract.')
param enableDcrErrorLogs bool = true

@description('Sources whose raw record (event.original) Sentinel should parse with the vendor\'s own published connector logic, by name from parameters/sentinel-source-routes.json (for example [\'okta\']). Each adds a DCR route into the vendor\'s table and creates that table if it is a custom table. Every event still also lands in the Abstract table.')
param sourceRoutes array = []

@description('Table plan for the Abstract table. Analytics (default) runs analytics rules and our content pack on it. Auxiliary is the Sentinel data lake tier: cheap long retention and KQL jobs, but no analytics rules or alerts. Basic sits between them. Set at creation; changing an existing Analytics table to Auxiliary is not supported by Azure.')
@allowed(['Analytics', 'Basic', 'Auxiliary'])
param customTablePlan string = 'Analytics'

// ---------------------------------------------------------------------------
// RBAC for the Abstract service principal (granted on the DCR)
// ---------------------------------------------------------------------------
@description('Object ID of the service principal Abstract authenticates as (the Enterprise Application object ID, NOT the Application/client ID). Leave empty to skip role assignments and grant them yourself later.')
param principalId string = ''

@description('Type of the principal being granted RBAC (avoids PrincipalNotFound on freshly created SPNs).')
@allowed(['ServicePrincipal', 'User', 'Group'])
param principalType string = 'ServicePrincipal'

// ---------------------------------------------------------------------------
// Derived values
// ---------------------------------------------------------------------------
var autoWorkspaceName = 'abstract-sentinel-${uniqueString(resourceGroup().id)}'
var effectiveWorkspaceName = createWorkspace ? (empty(workspaceName) ? autoWorkspaceName : workspaceName) : workspaceName
var workspaceResourceId = resourceId('Microsoft.OperationalInsights/workspaces', effectiveWorkspaceName)

// The DCE and DCR must be co-located with the destination workspace. When
// creating a new workspace they share the deployment location; for an existing
// workspace in another region, callers set existingWorkspaceLocation.
var effectiveLocation = createWorkspace ? location : (empty(existingWorkspaceLocation) ? location : existingWorkspaceLocation)
// Generated by gen-sentinel-schema.py from the ACS field catalog. The
// stream mirrors the payload (it still carries the reserved id and type keys);
// the transformation sets TimeGenerated and renames those two.
var generatedSchema = loadJsonContent('../../parameters/sentinel-destination.schema.json')
var useGeneratedSchema = empty(tableColumns)
var effectiveTableColumns = useGeneratedSchema ? generatedSchema.tableColumns : tableColumns
var effectiveStreamColumns = useGeneratedSchema ? generatedSchema.streamColumns : tableColumns
var effectiveTransformKql = useGeneratedSchema ? generatedSchema.transformKql : transformKql

// Routes that reuse Microsoft's published connector parsing, generated by
// gen-sentinel-source-routes.py from github.com/Azure/Azure-Sentinel at a pinned ref.
var sourceRouteCatalog = loadJsonContent('../../parameters/sentinel-source-routes.generated.json').routes
var enabledSourceRoutes = filter(sourceRouteCatalog, route => contains(sourceRoutes, route.name))
var sourceRouteTables = filter(enabledSourceRoutes, route => contains(route, 'table'))
var sourceRouteFlows = [for route in enabledSourceRoutes: {
  streams: [
    streamName
  ]
  destinations: [
    logAnalyticsDestinationName
  ]
  transformKql: route.transformKql
  outputStream: route.outputStream
}]

// Stream name for a DCR-based custom table is always Custom-<table>.
var streamName = 'Custom-${customTableName}'
var logAnalyticsDestinationName = 'abstractSentinelWorkspace'

// Built-in role definition IDs (per Abstract docs).
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'
var monitoringContributorRoleId = '749f88d5-cbae-40b8-bcfc-e573ddc772fa'

// ---------------------------------------------------------------------------
// Log Analytics workspace
// ---------------------------------------------------------------------------
resource workspace 'Microsoft.OperationalInsights/workspaces@2026-03-01' = if (createWorkspace) {
  name: effectiveWorkspaceName
  location: location
  tags: union(tags, contains(tagsByResource, 'Microsoft.OperationalInsights/workspaces') ? tagsByResource['Microsoft.OperationalInsights/workspaces'] : {})
  properties: {
    sku: {
      name: workspaceSku
    }
    retentionInDays: workspaceRetentionDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// Microsoft Sentinel onboarding (extension resource on the workspace).
resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = if (createWorkspace && enableSentinel) {
  scope: workspace
  name: 'default'
  properties: {}
}

// ---------------------------------------------------------------------------
// Custom log table (DCR-based, *_CL). Created on the (new or existing) workspace.
// ---------------------------------------------------------------------------
resource customTable 'Microsoft.OperationalInsights/workspaces/tables@2026-03-01' = {
  name: '${effectiveWorkspaceName}/${customTableName}'
  properties: {
    schema: {
      name: customTableName
      // Log Analytics table columns want 'dateTime' (capital T); everything else is lower-case.
      columns: [for col in effectiveTableColumns: {
        name: col.name
        type: toLower(string(col.type)) == 'datetime' ? 'dateTime' : toLower(string(col.type))
      }]
    }
    totalRetentionInDays: workspaceRetentionDays
    plan: customTablePlan
  }
  dependsOn: createWorkspace ? [
    workspace
  ] : []
}

// ---------------------------------------------------------------------------
// Data Collection Endpoint
// ---------------------------------------------------------------------------
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2024-03-11' = {
  name: dataCollectionEndpointName
  location: effectiveLocation
  tags: union(tags, contains(tagsByResource, 'Microsoft.Insights/dataCollectionEndpoints') ? tagsByResource['Microsoft.Insights/dataCollectionEndpoints'] : {})
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}


// Vendor tables the enabled source routes write to (custom _CL tables only; built-in
// tables such as CommonSecurityLog already exist). Same schema as the vendor's solution.
resource sourceRouteTable 'Microsoft.OperationalInsights/workspaces/tables@2026-03-01' = [for route in sourceRouteTables: {
  name: '${effectiveWorkspaceName}/${route.table.name}'
  properties: {
    schema: {
      name: route.table.name
      columns: route.table.columns
    }
  }
  dependsOn: createWorkspace ? [
    workspace
  ] : []
}]

// ---------------------------------------------------------------------------
// Data Collection Rule: Custom-<table> stream -> workspace custom table
// ---------------------------------------------------------------------------
resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: dataCollectionRuleName
  location: effectiveLocation
  tags: union(tags, contains(tagsByResource, 'Microsoft.Insights/dataCollectionRules') ? tagsByResource['Microsoft.Insights/dataCollectionRules'] : {})
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      // DCR stream column types are all lower-case (datetime, string, int, ...).
      '${streamName}': {
        columns: [for col in effectiveStreamColumns: {
          name: col.name
          type: toLower(string(col.type))
        }]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaceResourceId
          name: logAnalyticsDestinationName
        }
      ]
    }
    dataFlows: concat([
      {
        streams: [
          streamName
        ]
        destinations: [
          logAnalyticsDestinationName
        ]
        transformKql: effectiveTransformKql
        outputStream: streamName
      }
    ], sourceRouteFlows)
  }
  dependsOn: [
    customTable
    sourceRouteTable
  ]
}


// ---------------------------------------------------------------------------
// DCR error logs -> DCRLogErrors in the workspace. The DCR metrics only count
// failures; this is the only place that records WHY a request was refused or
// a row dropped. Azure samples these per hour, so it is evidence, not a tally.
// ---------------------------------------------------------------------------
resource dcrErrorLogs 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableDcrErrorLogs) {
  name: 'abstract-dcr-errors'
  scope: dcr
  properties: {
    workspaceId: workspaceResourceId
    logs: [
      {
        category: 'LogErrors'
        enabled: true
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// RBAC on the DCR for the Abstract service principal (both roles per docs)
// ---------------------------------------------------------------------------
resource metricsPublisherAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(principalId)) {
  name: guid(dcr.id, principalId, monitoringMetricsPublisherRoleId)
  scope: dcr
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalType: principalType
  }
}

resource monitoringContributorAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(principalId)) {
  name: guid(dcr.id, principalId, monitoringContributorRoleId)
  scope: dcr
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringContributorRoleId)
    principalType: principalType
  }
}

// ---------------------------------------------------------------------------
// Outputs - field-for-field for the Abstract "Azure Sentinel Destination" modal
// ---------------------------------------------------------------------------
output workspaceName string = effectiveWorkspaceName
output workspaceResourceId string = workspaceResourceId
output customTableName string = customTableName
output dataCollectionRuleImmutableId string = dcr.properties.immutableId
output dataCollectionEndpointUrl string = dce.properties.logsIngestion.endpoint
output logStreamName string = streamName
output rbacAssigned bool = !empty(principalId)

output abstractSentinelOnboarding object = {
  azureMonitorDetails: {
    dataCollectionRuleId: dcr.properties.immutableId
    dataCollectionEndpoint: dce.properties.logsIngestion.endpoint
    logStreamName: streamName
  }
  authentication: {
    clientId: '(Entra ID > App registrations > your app > Application (client) ID)'
    clientSecretValue: '(Entra ID > App registrations > your app > Certificates & secrets)'
    applicationTenantId: subscription().tenantId
  }
  rbac: !empty(principalId) ? 'Monitoring Metrics Publisher + Monitoring Contributor granted on the DCR to principal ${principalId}' : '(no principalId supplied - assign both roles on the DCR yourself)'
  docs: 'https://docs.abstractsecurity.app/docs/integrations/destination-integrations/azure-sentinel-destination/'
}
