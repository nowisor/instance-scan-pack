import { ScriptOnlyCheck } from '@servicenow/sdk/core'

export const restAnonymousAccessCheck = ScriptOnlyCheck({
    $id: Now.ID['nowisor-rest-anonymous-access'],
    name: 'REST Anonymous Access Audit',
    active: true,
    category: 'security',
    priority: '1',
    shortDescription:
        'Audits the glide.basicauth.required.* family to confirm REST, SOAP, WSDL, XSD, scripted, databroker, and UNL endpoints require authentication',
    description:
        "When any glide.basicauth.required.* property is not 'true', the corresponding endpoint family (REST API, scripted REST processors, SOAP, WSDL, XSD, databroker REST processor, or UNL) accepts unauthenticated requests, exposing the platform to anonymous enumeration and direct table access without credentials. All seven properties are verified-real on Zurich Patch 6 with default value 'true'.",
    resolutionDetails: `Set every glide.basicauth.required.* property to true via System Properties:
- glide.basicauth.required.api
- glide.basicauth.required.scriptedprocessor
- glide.basicauth.required.soap
- glide.basicauth.required.wsdl
- glide.basicauth.required.xsd
- glide.basicauth.required.databrokerrestapiprocessor
- glide.basicauth.required.unl

Framework mapping:
- NIS2 Article 21§2(d): supply chain security including security-related aspects concerning the relationships between each entity and its direct suppliers
- ISO 27001 A.5.16: identity management
- DORA Article 9: ICT risk management framework

Verified against ServiceNow Zurich Patch 6 (build glide-zurich-07-01-2025__patch6-01-16-2026).
All seven property registrations confirmed in sys_properties; default value 'true'.`,
    script: Now.include('../../../scripts/check-rest-anonymous-access.js'),
})
