# Security Analyst Guide

A comprehensive guide for cybersecurity professionals using the STIX 2.1 Java Library for threat intelligence and incident response.

## Table of Contents

1. [Understanding STIX for Security Operations](#understanding-stix-for-security-operations)
2. [Threat Intelligence Management](#threat-intelligence-management)
3. [Incident Documentation](#incident-documentation)
4. [IOC Extraction and Sharing](#ioc-extraction-and-sharing)
5. [Attack Pattern Mapping](#attack-pattern-mapping)
6. [Threat Actor Profiling](#threat-actor-profiling)
7. [Integration with Security Tools](#integration-with-security-tools)
8. [Real-World Scenarios](#real-world-scenarios)

## Understanding STIX for Security Operations

STIX (Structured Threat Information Expression) provides a standardized language for describing cyber threat intelligence. This library helps you create, parse, and share threat data in STIX 2.1 format.

### Key Concepts for Analysts

- **Indicators**: Observable patterns that suggest malicious activity
- **Threat Actors**: Individuals or groups responsible for attacks
- **Campaigns**: Coordinated attack operations
- **Attack Patterns**: Methods used by threat actors (TTPs)
- **Observables**: Raw technical data (IPs, domains, hashes)
- **Courses of Action**: Mitigation and response strategies

## Threat Intelligence Management

### Creating Threat Intelligence Reports

Document and share threat intelligence findings:

```java
public class ThreatIntelReport {
    public Bundle createAPTReport(String aptName, String campaign,
                                  List<String> indicators,
                                  List<String> ttps) {

        // Document the threat actor
        ThreatActor actor = ThreatActor.builder()
            .name(aptName)
            .addLabel("nation-state")
            .description("Advanced persistent threat group")
            .sophistication("advanced")
            .resourceLevel("government")
            .primaryMotivation("espionage")
            .addAlias(aptName + " Group")
            .build();

        // Document the campaign
        Campaign camp = Campaign.builder()
            .name(campaign)
            .description("Targeted attacks against financial sector")
            .firstSeen(new StixInstant("2025-01-01T00:00:00Z"))
            .objective("Data theft and espionage")
            .build();

        // Create indicators
        List<Indicator> indicatorObjects = indicators.stream()
            .map(this::createIndicator)
            .collect(Collectors.toList());

        // Map to ATT&CK
        List<AttackPattern> attackPatterns = ttps.stream()
            .map(this::createAttackPattern)
            .collect(Collectors.toList());

        // Build relationships
        List<Relationship> relationships = new ArrayList<>();

        // Campaign attribution
        relationships.add(Relationship.builder()
            .relationshipType("attributed-to")
            .sourceRef(camp)
            .targetRef(actor)
            .confidence(85)
            .build());

        // Link indicators to campaign
        for (Indicator ind : indicatorObjects) {
            relationships.add(Relationship.builder()
                .relationshipType("indicates")
                .sourceRef(ind)
                .targetRef(camp)
                .build());
        }

        // Create intelligence report
        Report report = Report.builder()
            .name(aptName + " Campaign Analysis")
            .published(new StixInstant())
            .addLabel("threat-report")
            .addObjectRef(actor)
            .addObjectRef(camp)
            .addAllObjectRefs(indicatorObjects)
            .addAllObjectRefs(attackPatterns)
            .description("Comprehensive analysis of " + aptName + " activities")
            .build();

        // Bundle everything
        Bundle.Builder bundleBuilder = Bundle.builder()
            .addObject(report)
            .addObject(actor)
            .addObject(camp)
            .addAllObjects(indicatorObjects)
            .addAllObjects(attackPatterns)
            .addAllObjects(relationships);

        return bundleBuilder.build();
    }

    private Indicator createIndicator(String pattern) {
        return Indicator.builder()
            .pattern(pattern)
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(90))
            .addLabel("malicious-activity")
            .confidence(80)
            .build();
    }

    private AttackPattern createAttackPattern(String technique) {
        return AttackPattern.builder()
            .name(technique)
            .addExternalReference(ExternalReference.builder()
                .sourceName("mitre-attack")
                .externalId(extractMitreId(technique))
                .url("https://attack.mitre.org/techniques/" + extractMitreId(technique))
                .build())
            .build();
    }
}
```

### Managing IOC Feeds

Process and enrich threat intelligence feeds:

```java
public class IOCFeedManager {

    public Bundle processIOCFeed(String feedName, InputStream csvFeed) {
        Bundle.Builder bundleBuilder = Bundle.builder();
        List<Indicator> indicators = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(csvFeed))) {

            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                String iocType = parts[0];
                String iocValue = parts[1];
                String confidence = parts[2];

                Indicator indicator = createIndicatorFromIOC(
                    iocType, iocValue, Integer.parseInt(confidence));
                indicators.add(indicator);
            }
        }

        // Add metadata
        Note feedInfo = Note.builder()
            .content("IOC feed: " + feedName +
                    "\nTotal indicators: " + indicators.size() +
                    "\nProcessed: " + new StixInstant())
            .addAllObjectRefs(indicators)
            .build();

        bundleBuilder.addAllObjects(indicators)
                     .addObject(feedInfo);

        return bundleBuilder.build();
    }

    private Indicator createIndicatorFromIOC(String type,
                                            String value,
                                            int confidence) {
        String pattern;
        String label;

        switch (type.toLowerCase()) {
            case "ip":
                pattern = "[ipv4-addr:value = '" + value + "']";
                label = "malicious-activity";
                break;
            case "domain":
                pattern = "[domain-name:value = '" + value + "']";
                label = "malicious-activity";
                break;
            case "md5":
                pattern = "[file:hashes.MD5 = '" + value + "']";
                label = "malicious-activity";
                break;
            case "sha256":
                pattern = "[file:hashes.SHA-256 = '" + value + "']";
                label = "malicious-activity";
                break;
            case "email":
                pattern = "[email-addr:value = '" + value + "']";
                label = "malicious-activity";
                break;
            case "url":
                pattern = "[url:value = '" + value + "']";
                label = "malicious-activity";
                break;
            default:
                throw new IllegalArgumentException("Unknown IOC type: " + type);
        }

        return Indicator.builder()
            .pattern(pattern)
            .patternType("stix")
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(30))
            .addLabel(label)
            .confidence(confidence)
            .description("IOC from " + type + " feed")
            .build();
    }
}
```

## Incident Documentation

### Documenting Security Incidents

Create comprehensive incident documentation:

```java
public class IncidentDocumentation {

    public Bundle documentIncident(IncidentData data) {
        // Victim organization
        Identity victim = Identity.builder()
            .name(data.getVictimOrganization())
            .identityClass("organization")
            .sectors(data.getIndustrySector())
            .build();

        // The incident itself
        Incident incident = Incident.builder()
            .name(data.getIncidentName())
            .description(data.getDescription())
            // Add timeline
            .created(data.getDetectionTime())
            .modified(new StixInstant())
            // Add other metadata
            .customProperty("x_severity", data.getSeverity())
            .customProperty("x_incident_id", data.getIncidentId())
            .customProperty("x_data_breach", data.isDataBreach())
            .build();

        // Attack vectors used
        List<AttackPattern> attackVectors = data.getAttackVectors().stream()
            .map(vector -> AttackPattern.builder()
                .name(vector)
                .description(data.getVectorDescription(vector))
                .build())
            .collect(Collectors.toList());

        // Malware involved
        List<Malware> malwareList = data.getMalwareNames().stream()
            .map(name -> Malware.builder()
                .name(name)
                .addLabel(data.getMalwareType(name))
                .description(data.getMalwareDescription(name))
                .build())
            .collect(Collectors.toList());

        // Indicators found during investigation
        List<Indicator> indicators = data.getIOCs().stream()
            .map(ioc -> Indicator.builder()
                .pattern(ioc.getPattern())
                .validFrom(data.getDetectionTime())
                .addLabel("malicious-activity")
                .description("Found during incident " + data.getIncidentId())
                .build())
            .collect(Collectors.toList());

        // Courses of action taken
        List<CourseOfAction> mitigations = new ArrayList<>();

        CourseOfAction containment = CourseOfAction.builder()
            .name("Containment Actions")
            .description("Initial containment measures")
            .action(String.join("\n", data.getContainmentSteps()))
            .build();
        mitigations.add(containment);

        CourseOfAction eradication = CourseOfAction.builder()
            .name("Eradication Actions")
            .description("Removal of threat from environment")
            .action(String.join("\n", data.getEradicationSteps()))
            .build();
        mitigations.add(eradication);

        CourseOfAction recovery = CourseOfAction.builder()
            .name("Recovery Actions")
            .description("System restoration and monitoring")
            .action(String.join("\n", data.getRecoverySteps()))
            .build();
        mitigations.add(recovery);

        // Create relationships
        List<Relationship> relationships = new ArrayList<>();

        // Incident targets victim
        relationships.add(Relationship.builder()
            .relationshipType("targets")
            .sourceRef(incident)
            .targetRef(victim)
            .build());

        // Attack patterns used in incident
        for (AttackPattern pattern : attackVectors) {
            relationships.add(Relationship.builder()
                .relationshipType("uses")
                .sourceRef(incident)
                .targetRef(pattern)
                .build());
        }

        // Malware delivered in incident
        for (Malware malware : malwareList) {
            relationships.add(Relationship.builder()
                .relationshipType("uses")
                .sourceRef(incident)
                .targetRef(malware)
                .build());
        }

        // Mitigations for incident
        for (CourseOfAction coa : mitigations) {
            relationships.add(Relationship.builder()
                .relationshipType("mitigates")
                .sourceRef(coa)
                .targetRef(incident)
                .build());
        }

        // Create incident report
        Report incidentReport = Report.builder()
            .name("Incident Report: " + data.getIncidentId())
            .published(new StixInstant())
            .addLabel("incident")
            .description("Complete documentation of security incident")
            .addObjectRef(incident)
            .addObjectRef(victim)
            .addAllObjectRefs(attackVectors)
            .addAllObjectRefs(malwareList)
            .addAllObjectRefs(indicators)
            .addAllObjectRefs(mitigations)
            .build();

        // Bundle everything
        Bundle.Builder bundle = Bundle.builder()
            .addObject(incidentReport)
            .addObject(incident)
            .addObject(victim)
            .addAllObjects(attackVectors)
            .addAllObjects(malwareList)
            .addAllObjects(indicators)
            .addAllObjects(mitigations)
            .addAllObjects(relationships);

        return bundle.build();
    }
}
```

## IOC Extraction and Sharing

### Extracting IOCs from Various Sources

```java
public class IOCExtractor {

    public List<Indicator> extractFromSIEM(SIEMAlert alert) {
        List<Indicator> indicators = new ArrayList<>();

        // Extract IP addresses
        for (String ip : alert.getSourceIPs()) {
            indicators.add(Indicator.builder()
                .pattern("[ipv4-addr:value = '" + ip + "']")
                .validFrom(alert.getTimestamp())
                .addLabel("suspicious-activity")
                .confidence(alert.getConfidence())
                .description("Source IP from SIEM alert " + alert.getId())
                .build());
        }

        // Extract domains
        for (String domain : alert.getDomains()) {
            indicators.add(Indicator.builder()
                .pattern("[domain-name:value = '" + domain + "']")
                .validFrom(alert.getTimestamp())
                .addLabel("suspicious-activity")
                .confidence(alert.getConfidence())
                .build());
        }

        // Extract file hashes
        for (FileHash hash : alert.getFileHashes()) {
            String pattern = String.format(
                "[file:hashes.%s = '%s']",
                hash.getAlgorithm(), hash.getValue()
            );
            indicators.add(Indicator.builder()
                .pattern(pattern)
                .validFrom(alert.getTimestamp())
                .addLabel("malicious-activity")
                .confidence(alert.getConfidence())
                .build());
        }

        return indicators;
    }

    public Bundle createSharingBundle(List<Indicator> indicators,
                                     String tlpLevel,
                                     String sourceOrg) {
        // Create identity for source
        Identity source = Identity.builder()
            .name(sourceOrg)
            .identityClass("organization")
            .build();

        // Add TLP marking
        MarkingDefinition tlp = MarkingDefinition.builder()
            .definitionType("tlp")
            .definition(Tlp.builder()
                .tlp(tlpLevel.toLowerCase())
                .build())
            .build();

        // Apply marking to all indicators
        List<Indicator> markedIndicators = indicators.stream()
            .map(ind -> Indicator.builder()
                .from(ind)
                .addObjectMarkingRef(tlp)
                .createdByRef(source)
                .build())
            .collect(Collectors.toList());

        return Bundle.builder()
            .addObject(source)
            .addObject(tlp)
            .addAllObjects(markedIndicators)
            .build();
    }
}
```

## Attack Pattern Mapping

### Mapping to MITRE ATT&CK

```java
public class AttackMapping {

    public AttackPattern mapToATTACK(String techniqueId,
                                    String tacticName,
                                    ObservedBehavior behavior) {

        AttackPattern pattern = AttackPattern.builder()
            .name(behavior.getTechniqueName())
            .description(behavior.getDescription())

            // Add MITRE ATT&CK reference
            .addExternalReference(ExternalReference.builder()
                .sourceName("mitre-attack")
                .externalId(techniqueId)
                .url("https://attack.mitre.org/techniques/" + techniqueId)
                .build())

            // Add kill chain phase
            .addKillChainPhase(KillChainPhase.builder()
                .killChainName("mitre-attack")
                .phaseName(tacticName.toLowerCase())
                .build())

            // Add custom properties for additional context
            .customProperty("x_platforms", behavior.getPlatforms())
            .customProperty("x_permissions_required",
                          behavior.getPermissions())
            .customProperty("x_data_sources",
                          behavior.getDataSources())
            .build();

        return pattern;
    }

    public Bundle createTTPBundle(ThreatActor actor,
                                 List<String> techniques) {
        Bundle.Builder bundle = Bundle.builder();

        // Add threat actor
        bundle.addObject(actor);

        // Map each technique
        for (String technique : techniques) {
            AttackPattern pattern = mapToATTACK(
                technique,
                getTacticForTechnique(technique),
                observeBehavior(technique)
            );
            bundle.addObject(pattern);

            // Create relationship
            bundle.addObject(Relationship.builder()
                .relationshipType("uses")
                .sourceRef(actor)
                .targetRef(pattern)
                .build());
        }

        return bundle.build();
    }
}
```

## Threat Actor Profiling

### Building Threat Actor Profiles

```java
public class ThreatActorProfiler {

    public ThreatActor profileActor(ActorIntelligence intel) {
        ThreatActor.Builder actor = ThreatActor.builder()
            .name(intel.getName())
            .description(generateDescription(intel));

        // Classify the actor
        if (intel.isNationState()) {
            actor.addLabel("nation-state");
            actor.sophistication("advanced");
            actor.resourceLevel("government");
        } else if (intel.isCybercriminal()) {
            actor.addLabel("criminal");
            actor.sophistication(intel.getSophistication());
            actor.resourceLevel(intel.getResourceLevel());
        } else if (intel.isHacktivist()) {
            actor.addLabel("hacktivist");
            actor.sophistication("intermediate");
            actor.resourceLevel("individual");
        }

        // Add motivations
        actor.primaryMotivation(intel.getPrimaryMotivation());
        for (String motivation : intel.getSecondaryMotivations()) {
            actor.addSecondaryMotivation(motivation);
        }

        // Add aliases
        for (String alias : intel.getAliases()) {
            actor.addAlias(alias);
        }

        // Add roles
        for (String role : intel.getRoles()) {
            actor.addRole(role);
        }

        // Add goals
        for (String goal : intel.getGoals()) {
            actor.addGoal(goal);
        }

        return actor.build();
    }

    private String generateDescription(ActorIntelligence intel) {
        StringBuilder desc = new StringBuilder();
        desc.append(intel.getName())
            .append(" is a ")
            .append(intel.getClassification())
            .append(" threat actor ");

        if (intel.getOriginCountry() != null) {
            desc.append("believed to originate from ")
                .append(intel.getOriginCountry())
                .append(". ");
        }

        desc.append("Primary targets include ")
            .append(String.join(", ", intel.getTargetSectors()))
            .append(". ");

        if (intel.getActiveS ince() != null) {
            desc.append("Active since ")
                .append(intel.getActiveSince())
                .append(". ");
        }

        return desc.toString();
    }
}
```

## Integration with Security Tools

### SIEM Integration

```java
public class SIEMIntegration {

    public void sendToSIEM(Bundle bundle, SIEMConnector siem) {
        // Extract indicators for SIEM rules
        bundle.getObjects().stream()
            .filter(obj -> obj instanceof Indicator)
            .map(obj -> (Indicator) obj)
            .forEach(indicator -> {
                SIEMRule rule = convertToSIEMRule(indicator);
                siem.deployRule(rule);
            });
    }

    private SIEMRule convertToSIEMRule(Indicator indicator) {
        String pattern = indicator.getPattern();

        // Parse STIX pattern to SIEM query
        if (pattern.contains("ipv4-addr:value")) {
            String ip = extractValue(pattern);
            return new SIEMRule()
                .withName("STIX-" + indicator.getId())
                .withQuery("src_ip=" + ip + " OR dst_ip=" + ip)
                .withSeverity(mapConfidenceToSeverity(
                    indicator.getConfidence()))
                .withDescription(indicator.getDescription()
                    .orElse("STIX Indicator"));
        }
        // Handle other pattern types...

        return null;
    }
}
```

### Threat Intelligence Platform Integration

```java
public class TIPIntegration {

    public void uploadToTIP(Bundle bundle, TIPClient tip) {
        // Group objects by type
        Map<String, List<BundleableObject>> grouped =
            bundle.getObjects().stream()
                .collect(Collectors.groupingBy(
                    obj -> obj.getType()));

        // Upload indicators
        if (grouped.containsKey("indicator")) {
            tip.uploadIndicators(
                grouped.get("indicator").stream()
                    .map(obj -> (Indicator) obj)
                    .collect(Collectors.toList())
            );
        }

        // Upload threat actors
        if (grouped.containsKey("threat-actor")) {
            tip.uploadActors(
                grouped.get("threat-actor").stream()
                    .map(obj -> (ThreatActor) obj)
                    .collect(Collectors.toList())
            );
        }

        // Upload relationships
        if (grouped.containsKey("relationship")) {
            tip.uploadRelationships(
                grouped.get("relationship").stream()
                    .map(obj -> (Relationship) obj)
                    .collect(Collectors.toList())
            );
        }
    }
}
```

## Real-World Scenarios

### Scenario 1: Ransomware Attack Response

```java
public class RansomwareResponse {

    public Bundle documentRansomwareAttack(
            String ransomwareName,
            List<String> encryptedExtensions,
            String bitcoinAddress,
            List<String> c2Servers) {

        // Document the malware
        Malware ransomware = Malware.builder()
            .name(ransomwareName)
            .addLabel("ransomware")
            .description("Ransomware that encrypts files and demands payment")
            .isFamily(true)
            .addCapability("encrypts-data")
            .addCapability("demands-ransom")
            .build();

        // Create indicators
        List<Indicator> indicators = new ArrayList<>();

        // File extension indicators
        for (String ext : encryptedExtensions) {
            indicators.add(Indicator.builder()
                .pattern("[file:name MATCHES '.*\\." + ext + "$']")
                .validFrom(new StixInstant())
                .addLabel("malicious-activity")
                .description("Encrypted file extension used by " + ransomwareName)
                .build());
        }

        // Bitcoin address
        indicators.add(Indicator.builder()
            .pattern("[x-bitcoin-address:value = '" + bitcoinAddress + "']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .description("Bitcoin address for ransom payment")
            .build());

        // C2 servers
        for (String c2 : c2Servers) {
            indicators.add(Indicator.builder()
                .pattern("[domain-name:value = '" + c2 + "' OR " +
                        "ipv4-addr:value = '" + c2 + "']")
                .validFrom(new StixInstant())
                .addLabel("malicious-activity")
                .description("C2 server for " + ransomwareName)
                .build());
        }

        // Mitigation
        CourseOfAction mitigation = CourseOfAction.builder()
            .name("Ransomware Mitigation")
            .description("Steps to prevent and respond to ransomware")
            .action(
                "1. Isolate infected systems immediately\n" +
                "2. Identify ransomware variant\n" +
                "3. Check for available decryptors\n" +
                "4. Restore from clean backups if available\n" +
                "5. Block C2 communication\n" +
                "6. Reset credentials\n" +
                "7. Patch vulnerabilities\n" +
                "8. Implement EDR/XDR solutions"
            )
            .build();

        return Bundle.builder()
            .addObject(ransomware)
            .addAllObjects(indicators)
            .addObject(mitigation)
            .addObject(Relationship.builder()
                .relationshipType("mitigates")
                .sourceRef(mitigation)
                .targetRef(ransomware)
                .build())
            .build();
    }
}
```

### Scenario 2: Phishing Campaign Analysis

```java
public class PhishingAnalysis {

    public Bundle analyzePhishingCampaign(
            PhishingCampaignData data) {

        // The campaign
        Campaign phishingCampaign = Campaign.builder()
            .name(data.getCampaignName())
            .description("Phishing campaign targeting " +
                       data.getTargetIndustry())
            .firstSeen(data.getFirstSeen())
            .lastSeen(data.getLastSeen())
            .objective("Credential theft")
            .build();

        // Attack pattern
        AttackPattern phishing = AttackPattern.builder()
            .name("Spear Phishing Link")
            .description("Phishing emails with malicious links")
            .addExternalReference(ExternalReference.builder()
                .sourceName("mitre-attack")
                .externalId("T1566.002")
                .url("https://attack.mitre.org/techniques/T1566/002/")
                .build())
            .build();

        // Infrastructure
        List<Infrastructure> infrastructure = new ArrayList<>();
        for (String domain : data.getPhishingDomains()) {
            infrastructure.add(Infrastructure.builder()
                .name("Phishing domain: " + domain)
                .addInfrastructureType("hosting-service")
                .description("Domain used to host phishing pages")
                .build());
        }

        // Create email indicators
        List<Indicator> indicators = new ArrayList<>();
        for (String subject : data.getEmailSubjects()) {
            indicators.add(Indicator.builder()
                .pattern("[email-message:subject = '" + subject + "']")
                .validFrom(data.getFirstSeen())
                .addLabel("malicious-activity")
                .description("Phishing email subject")
                .build());
        }

        // Victims
        List<Identity> victims = data.getVictimOrganizations().stream()
            .map(org -> Identity.builder()
                .name(org)
                .identityClass("organization")
                .sectors(data.getTargetIndustry())
                .build())
            .collect(Collectors.toList());

        // Build relationships
        Bundle.Builder bundle = Bundle.builder()
            .addObject(phishingCampaign)
            .addObject(phishing)
            .addAllObjects(infrastructure)
            .addAllObjects(indicators)
            .addAllObjects(victims);

        // Campaign uses phishing
        bundle.addObject(Relationship.builder()
            .relationshipType("uses")
            .sourceRef(phishingCampaign)
            .targetRef(phishing)
            .build());

        // Campaign uses infrastructure
        for (Infrastructure infra : infrastructure) {
            bundle.addObject(Relationship.builder()
                .relationshipType("uses")
                .sourceRef(phishingCampaign)
                .targetRef(infra)
                .build());
        }

        // Campaign targets victims
        for (Identity victim : victims) {
            bundle.addObject(Relationship.builder()
                .relationshipType("targets")
                .sourceRef(phishingCampaign)
                .targetRef(victim)
                .build());
        }

        return bundle.build();
    }
}
```

## Best Practices for Security Analysts

### 1. Maintain Indicator Quality

- Always include confidence scores
- Set appropriate valid_from and valid_until dates
- Use descriptive labels from STIX vocabulary
- Include context in descriptions

### 2. Document Relationships

- Link indicators to campaigns or threat actors
- Show attack progression with relationships
- Document attribution with confidence levels
- Map mitigations to specific threats

### 3. Use Appropriate Markings

- Apply TLP (Traffic Light Protocol) markings
- Use statement markings for specific restrictions
- Consider data sensitivity when sharing

### 4. Leverage External References

- Link to MITRE ATT&CK techniques
- Reference CVE numbers for vulnerabilities
- Include links to detailed reports
- Cite intelligence sources

### 5. Regular Updates

- Update indicator validity periods
- Revise threat actor profiles with new intelligence
- Mark deprecated indicators as revoked
- Maintain campaign timelines

## Next Steps

- Explore [Security Use Cases](../security-use-cases/) for specific scenarios
- See [STIX Objects Guide](stix-objects-guide.md) for object details
- Review [Threat Hunting](../security-use-cases/threat-hunting.md) techniques
- Learn about [SIEM Integration](../security-use-cases/siem-integration.md)

---

*[Back to Documentation Index](../README.md)*