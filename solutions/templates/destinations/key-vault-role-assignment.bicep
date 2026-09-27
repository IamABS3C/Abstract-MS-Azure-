targetScope = 'resourceGroup'

param keyVaultName string
param principalId string
param roleDefinitionId string

resource keyVault 'Microsoft.KeyVault/vaults@2026-02-01' existing = {
  name: keyVaultName
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, principalId, roleDefinitionId)
  scope: keyVault
  properties: {
    principalId: principalId
    roleDefinitionId: roleDefinitionId
  }
}
