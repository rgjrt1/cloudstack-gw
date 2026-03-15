# CloudStack Built-In Role Permission Matrix

> **Sources:** `create-default-role-api-mappings.sql` (roles 1–4) · `Upgrade41400to41500.java` (roles 5–8 base) · schema migrations up to 4.21.0.x · `KubernetesClusterManagerImpl.java` (role 9)  
> ✅ = Allowed &nbsp;&nbsp; 🚫 = Denied / Not in role_permissions

| Cat | API Rule | Root Admin | Resource Admin | Domain Admin | User | Read-Only Admin | Read-Only User | Support Admin | Support User | Proj. K8s Svc |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Read** | `extractIso` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `extractTemplate` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `extractVolume` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `getApiLimit` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `getCloudIdentifier` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `getSolidFireAccountId` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `getSolidFireVolumeAccessGroupId` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `getSolidFireVolumeIscsiName` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `getSolidFireVolumeSize` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `getUploadParamsForTemplate` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | ✅ | 🚫 |
|  | `getUploadParamsForVolume` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | ✅ | 🚫 |
|  | `getVirtualMachineUserData` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `getVMPassword` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listAccounts` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listAffinityGroups` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listAffinityGroupTypes` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listAlerts` | ✅ | ✅ | 🚫 | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listApis` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listAsyncJobs` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listAutoScalePolicies` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listAutoScaleVmGroups` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listAutoScaleVmProfiles` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listCapabilities` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listCapacity` | ✅ | ✅ | 🚫 | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listClusters` | ✅ | ✅ | 🚫 | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listConditions` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listConfigurations` | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listCounters` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listDiskOfferings` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listDomainChildren` | ✅ | ✅ | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listDomains` | ✅ | ✅ | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listEgressFirewallRules` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listEvents` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listEventTypes` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listFirewallRules` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|  | `listGlobalLoadBalancerRules` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listHosts` | ✅ | ✅ | 🚫 | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listHostTags` | ✅ | ✅ | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listHypervisors` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listInstanceGroups` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listInternalLoadBalancerElements` | ✅ | ✅ | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listIpForwardingRules` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listIsoPermissions` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listIsos` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listKubernetesClusters` | ✅ | 🚫 | 🚫 | 🚫 | ✅ | 🚫 | ✅ | 🚫 | ✅ |
|  | `listLBHealthCheckPolicies` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listLBStickinessPolicies` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listLdapConfigurations` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listLdapUsers` | ✅ | ✅ | 🚫 | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listLoadBalancerRuleInstances` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|  | `listLoadBalancerRules` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|  | `listLoadBalancers` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listLunsOnFiler` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listNetworkACLLists` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listNetworkACLs` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|  | `listNetworkOfferings` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listNetworks` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|  | `listNics` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listOsCategories` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listOsTypes` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listOvsElements` | ✅ | ✅ | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listPods` | ✅ | ✅ | 🚫 | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listPools` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listPortForwardingRules` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listPrivateGateways` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listProjectAccounts` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listProjectInvitations` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listProjects` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listPublicIpAddresses` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|  | `listRegions` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listRemoteAccessVpns` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listResourceDetails` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listResourceLimits` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listRouters` | ✅ | ✅ | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listSamlAuthorization` | ✅ | ✅ | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listSecurityGroups` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listServiceOfferings` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listSnapshotPolicies` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listSnapshots` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|  | `listSSHKeyPairs` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listSslCerts` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listStaticRoutes` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listStoragePools` | ✅ | ✅ | 🚫 | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listStorageProviders` | ✅ | ✅ | 🚫 | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listStorageTags` | ✅ | ✅ | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listSystemVms` | ✅ | ✅ | 🚫 | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listTags` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listTemplatePermissions` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listTemplates` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listUsageRecords` | ✅ | ✅ | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listUsers` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listUserTwoFactorAuthenticatorProviders` | ✅ | 🚫 | 🚫 | 🚫 | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listVirtualMachines` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|  | `listVirtualRouterElements` | ✅ | ✅ | ✅ | 🚫 | ✅ | 🚫 | ✅ | 🚫 | 🚫 |
|  | `listVMSnapshot` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listVolumes` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|  | `listVolumesOnFiler` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listVPCOfferings` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listVPCs` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listVpnConnections` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listVpnCustomerGateways` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listVpnGateways` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listVpnUsers` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `listZones` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `queryAsyncJobResult` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|  | `quotaBalance` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `quotaCreditsList` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `quotaIsEnabled` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `quotaStatement` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `quotaSummary` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `quotaTariffList` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🚫 |
| **Create** | `addAccountToProject` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `addHost` | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `addIpToNic` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `addLdapConfiguration` | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `addNicToVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `addVpnUser` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `archiveEvents` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `assignCertToLoadBalancer` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `assignToGlobalLoadBalancerRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `assignToLoadBalancerRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `assignVirtualMachine` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `assignVolume` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `associateIpAddress` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `associateLun` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `attachIso` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | 🚫 |
|  | `attachVolume` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | ✅ |
|  | `authorizeSamlSso` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `authorizeSecurityGroupEgress` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `authorizeSecurityGroupIngress` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `copyIso` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `copyTemplate` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createAccount` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createAffinityGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createAutoScalePolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createAutoScaleVmGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createAutoScaleVmProfile` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createCondition` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createDiskOffering` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | ✅ | 🚫 | 🚫 |
|  | `createEgressFirewallRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createFirewallRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `createGlobalLoadBalancerRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createInstanceGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createInternalLoadBalancerElement` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createIpForwardingRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createLBHealthCheckPolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createLBStickinessPolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createLoadBalancer` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createLoadBalancerRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `createLunOnFiler` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createNetwork` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createNetworkACL` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `createNetworkACLList` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createNetworkOffering` | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | ✅ | 🚫 | 🚫 |
|  | `createOvsElement` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createPool` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createPortForwardingRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createProject` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createRemoteAccessVpn` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createSecurityGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createServiceOffering` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | ✅ | 🚫 | 🚫 |
|  | `createSnapshot` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `createSnapshotPolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createSSHKeyPair` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createStaticRoute` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createTags` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createTemplate` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createUser` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createVirtualRouterElement` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createVMSnapshot` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createVolume` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | ✅ |
|  | `createVolumeOnFiler` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createVPC` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createVPCOffering` | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | ✅ | 🚫 | 🚫 |
|  | `createVpnConnection` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createVpnCustomerGateway` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `createVpnGateway` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deployVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `importLdapUsers` | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `ldapCreateAccount` | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `linkDomainToLdap` | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `lockAccount` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `lockUser` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `registerIso` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | 🚫 |
|  | `registerSSHKeyPair` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `registerTemplate` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | 🚫 |
|  | `registerUserKeys` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `uploadSslCert` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `uploadVolume` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | 🚫 |
| **Update** | `activateProject` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `cancelHostMaintenance` | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | ✅ | 🚫 | 🚫 |
|  | `cancelStorageMaintenance` | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | ✅ | 🚫 | 🚫 |
|  | `changeServiceForRouter` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `changeServiceForVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `cloudianIsEnabled` | ✅ | 🚫 | 🚫 | 🚫 | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `configureInternalLoadBalancerElement` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `configureOvsElement` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `configureVirtualRouterElement` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `detachIso` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | 🚫 |
|  | `detachVolume` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | ✅ |
|  | `disableAccount` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `disableAutoScaleVmGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `disableStaticNat` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `disableUser` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `enableAccount` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `enableAutoScaleVmGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `enableStaticNat` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `enableStorageMaintenance` | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | ✅ | 🚫 | 🚫 |
|  | `enableUser` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `isAccountAllowedToCreateOfferingsWithTags` | ✅ | 🚫 | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `migrateVolume` | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `modifyPool` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `prepareHostForMaintenance` | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | ✅ | 🚫 | 🚫 |
|  | `rebootRouter` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `rebootVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | 🚫 |
|  | `recoverVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `replaceNetworkACLList` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `resetPasswordForVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `resetSSHKeyForVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `resetVpnConnection` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `resizeVolume` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `restartNetwork` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `restartVPC` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `restoreVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `revertSnapshot` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `revertToVMSnapshot` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `scaleKubernetesCluster` | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `scaleVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `setupUserTwoFactorAuthentication` | ✅ | 🚫 | 🚫 | 🚫 | ✅ | ✅ | ✅ | ✅ | 🚫 |
|  | `startKubernetesCluster` | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | ✅ | ✅ | 🚫 |
|  | `startRouter` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `startVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | 🚫 |
|  | `stopKubernetesCluster` | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | ✅ | ✅ | 🚫 |
|  | `stopRouter` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `stopVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | ✅ | ✅ | 🚫 |
|  | `suspendProject` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateAccount` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateAutoScalePolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateAutoScaleVmGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateAutoScaleVmProfile` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateConfiguration` | ✅ | 🚫 | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateDefaultNicForVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateDiskOffering` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateEgressFirewallRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateFirewallRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `updateGlobalLoadBalancerRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateInstanceGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateIpAddress` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateIso` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateIsoPermissions` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateLBHealthCheckPolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateLBStickinessPolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateLoadBalancer` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateLoadBalancerRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `updateNetwork` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateNetworkACLItem` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateNetworkACLList` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updatePortForwardingRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateProject` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateProjectInvitation` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateRemoteAccessVpn` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateResourceCount` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateResourceLimit` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateServiceOffering` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateSnapshotPolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateTemplate` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateTemplatePermissions` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateUser` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateVMAffinityGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateVmNicIp` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateVPC` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateVpnConnection` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateVpnCustomerGateway` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `updateVpnGateway` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `validateUserTwoFactorAuthenticationCode` | ✅ | 🚫 | 🚫 | 🚫 | ✅ | ✅ | ✅ | ✅ | 🚫 |
| **Delete** | `deleteAccount` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteAccountFromProject` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteAffinityGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteAutoScalePolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteAutoScaleVmGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteAutoScaleVmProfile` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteCondition` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteDiskOffering` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteEgressFirewallRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteEvents` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteFirewallRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `deleteGlobalLoadBalancerRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteHost` | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteInstanceGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteIpForwardingRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteIso` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteLBHealthCheckPolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteLBStickinessPolicy` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteLdapConfiguration` | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteLoadBalancer` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteLoadBalancerRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `deleteNetwork` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteNetworkACL` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `deleteNetworkACLList` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deletePool` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deletePortForwardingRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteProject` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteProjectInvitation` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteRemoteAccessVpn` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteSecurityGroup` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteServiceOffering` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteSnapshot` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `deleteSnapshotPolicies` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteSSHKeyPair` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteSslCert` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteStaticRoute` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteTags` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteTemplate` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteUser` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteVMSnapshot` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteVolume` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `deleteVPC` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteVpnConnection` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteVpnCustomerGateway` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `deleteVpnGateway` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `destroyLunOnFiler` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `destroyRouter` | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `destroyVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `destroyVolumeOnFiler` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `disassociateIpAddress` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `dissociateLun` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `expungeVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `removeCertFromLoadBalancer` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `removeFromGlobalLoadBalancerRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `removeFromLoadBalancerRule` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | ✅ |
|  | `removeIpFromNic` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `removeNicFromVirtualMachine` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `removeVpnUser` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `revokeSecurityGroupEgress` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |
|  | `revokeSecurityGroupIngress` | ✅ | ✅ | ✅ | ✅ | 🚫 | 🚫 | 🚫 | 🚫 | 🚫 |

---

## Permission Count Summary

| Category | Root Admin | Resource Admin | Domain Admin | User | Read-Only Admin | Read-Only User | Support Admin | Support User | Proj. K8s Svc |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Read** | 111 | 108 | 100 | 89 | 106 | 85 | 106 | 87 | 11 |
| **Create** | 78 | 76 | 71 | 59 | 0 | 0 | 10 | 6 | 8 |
| **Update** | 87 | 74 | 76 | 58 | 3 | 3 | 14 | 10 | 5 |
| **Delete** | 60 | 60 | 58 | 53 | 0 | 0 | 0 | 0 | 7 |
| **Total** | 336 | 318 | 305 | 259 | 109 | 88 | 130 | 103 | 31 |

---

## Role Reference

| # | Full Name | Role Type | `is_default` | Defined In |
| --- | --- | --- | :---: | --- |
| 1 | Root Admin | Admin | ✅ | `create-default-role-api-mappings.sql` – wildcard `*` ALLOW |
| 2 | Resource Admin | ResourceAdmin | ✅ | `create-default-role-api-mappings.sql` |
| 3 | Domain Admin | DomainAdmin | ✅ | `create-default-role-api-mappings.sql` |
| 4 | User | User | ✅ | `create-default-role-api-mappings.sql` |
| 5 | Read-Only Admin – Default | Admin | ✅ | `schema-41400to41500` + `Upgrade41400to41500.java` |
| 6 | Read-Only User – Default | User | ✅ | `schema-41400to41500` + `Upgrade41400to41500.java` |
| 7 | Support Admin – Default | Admin | ✅ | `schema-41400to41500` + `Upgrade41400to41500.java` |
| 8 | Support User – Default | User | ✅ | `schema-41400to41500` + `Upgrade41400to41500.java` |
| 9 | Project Kubernetes Service Role | User | 🚫 | `KubernetesClusterManagerImpl.java` (created on-demand per cluster) |

## Read-Only Admin wildcard evaluation (first-match-wins)

```
list*                  → ALLOW
getUploadParamsFor*    → DENY  (overrides get* below)
get*                   → ALLOW
cloudianIsEnabled      → ALLOW
queryAsyncJobResult    → ALLOW
quotaIsEnabled         → ALLOW
quotaTariffList        → ALLOW
quotaSummary           → ALLOW
quotaStatement         → ALLOW  (added by schema-41720to41800)
quotaBalance           → ALLOW  (added by schema-41720to41800)
setupUserTwoFactorAuthentication          → ALLOW  (added by schema-41910to41920)
validateUserTwoFactorAuthenticationCode   → ALLOW  (added by schema-41910to41920)
quotaCreditsList       → ALLOW  (added by schema-42010to42100)
*                      → DENY
```

## Read-Only User derivation

All `list%` and `get%` (excluding `getUploadParamsFor%`) ALLOW rules are copied from the
**User** role at migration time, then a fixed set of extras is appended, and a catch-all
`* DENY` terminates the rule list.

## Support roles

- **Support Admin** = all Read-Only Admin ALLOWs + VM lifecycle + storage maintenance + offering creation + ISO/template registration
- **Support User** = all Read-Only User ALLOWs + VM lifecycle + volume/ISO/template ops + `getUploadParamsFor*` ALLOW

## Key migration changes

| Migration File | Change |
| --- | --- |
| `schema-41400to41500.sql` + `Upgrade41400to41500.java` | Creates roles 5–8 with initial permissions |
| `schema-41610to41700.sql` | Adds `listConfigurations`, `updateConfiguration` to Domain Admin |
| `schema-41720to41800.sql` | Removes `migrateVolume` from all non-Admin `is_default` roles; adds `assignVolume` to Resource Admin & Domain Admin; adds `quotaStatement`/`quotaBalance` to Read-Only Admin & Read-Only User; adds `isAccountAllowedToCreateOfferingsWithTags` to Domain Admin |
| `schema-41910to41920.sql` + `schema-42000to42010.sql` | Adds 2FA APIs to Read-Only and Support roles (idempotent pair) |
| `schema-42010to42100.sql` | Adds `quotaCreditsList` to every role that already has `quotaStatement` |
