# Threat Intelligence Sharing Examples

This guide demonstrates real-world scenarios for sharing threat intelligence using the STIX 2.1 Java Library.

## Table of Contents

1. [APT Campaign Tracking](#apt-campaign-tracking)
2. [Malware Analysis Report](#malware-analysis-report)
3. [Incident Response Documentation](#incident-response-documentation)
4. [Indicator Sharing](#indicator-sharing)
5. [Attack Pattern Mapping](#attack-pattern-mapping)

## APT Campaign Tracking

Track and share information about Advanced Persistent Threat campaigns.

```java
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.sro.objects.*;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.common.StixInstant;

public class APTCampaignExample {

    public Bundle createAPT29Intelligence() {
        // Create the threat actor
        ThreatActor apt29 = ThreatActor.builder()
            .name("APT29")
            .addLabel("nation-state")
            .description("Russian state-sponsored threat group also known as Cozy Bear")
            .addAlias("Cozy Bear")
            .addAlias("The Dukes")
            .addAlias("YTTRIUM")
            .sophistication("advanced")
            .resourceLevel("government")
            .primaryMotivation("espionage")
            .addGoal("intelligence-gathering")
            .addGoal("strategic-advantage")
            .build();

        // Define the campaign
        Campaign solarwindsAttack = Campaign.builder()
            .name("SolarWinds Supply Chain Attack")
            .description("Sophisticated supply chain attack targeting SolarWinds Orion platform")
            .addAlias("SUNBURST")
            .firstSeen(StixInstant.fromString("2020-03-01T00:00:00.000Z"))
            .lastSeen(StixInstant.fromString("2020-12-13T00:00:00.000Z"))
            .objective("Gain persistent access to high-value targets")
            .build();

        // Create the malware
        Malware sunburst = Malware.builder()
            .name("SUNBURST")
            .addLabel("backdoor")
            .description("Sophisticated backdoor delivered through SolarWinds update")
            .addImplementationLanguage("c++")
            .addCapability("command-and-control")
            .addCapability("exfiltration")
            .addCapability("persistence")
            .isFamily(true)
            .build();

        // Infrastructure used
        Infrastructure c2Infrastructure = Infrastructure.builder()
            .name("SUNBURST C2 Infrastructure")
            .addInfrastructureType("command-and-control")
            .description("Command and control servers using domain generation algorithm")
            .build();

        // Attack pattern
        AttackPattern supplyChainCompromise = AttackPattern.builder()
            .name("Supply Chain Compromise")
            .description("Compromise of software build process to inject malicious code")
            .addExternalReference(ExternalReference.builder()
                .sourceName("MITRE ATT&CK")
                .externalId("T1195.002")
                .url("https://attack.mitre.org/techniques/T1195/002/")
                .build())
            .build();

        // Create relationships
        Relationship attributedTo = Relationship.builder()
            .relationshipType("attributed-to")
            .sourceRef(campaign)
            .targetRef(apt29)
            .description("SolarWinds campaign attributed to APT29")
            .confidence(85)
            .build();

        Relationship uses = Relationship.builder()
            .relationshipType("uses")
            .sourceRef(campaign)
            .targetRef(sunburst)
            .description("Campaign deployed SUNBURST malware")
            .build();

        Relationship leverages = Relationship.builder()
            .relationshipType("uses")
            .sourceRef(campaign)
            .targetRef(supplyChainCompromise)
            .description("Campaign used supply chain compromise technique")
            .build();

        Relationship communicatesWith = Relationship.builder()
            .relationshipType("communicates-with")
            .sourceRef(sunburst)
            .targetRef(c2Infrastructure)
            .build();

        // Bundle everything
        return Bundle.builder()
            .addObject(apt29)
            .addObject(campaign)
            .addObject(sunburst)
            .addObject(c2Infrastructure)
            .addObject(supplyChainCompromise)
            .addObject(attributedTo)
            .addObject(uses)
            .addObject(leverages)
            .addObject(communicatesWith)
            .build();
    }
}
```

## Malware Analysis Report

Document and share malware analysis findings.

```java
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.sco.objects.*;
import security.whisper.javastix.bundle.Bundle;
import java.util.HashMap;
import java.util.Map;

public class MalwareAnalysisExample {

    public Bundle createMalwareAnalysisReport() {
        // Create file observable
        Map<String, String> hashes = new HashMap<>();
        hashes.put("MD5", "d41d8cd98f00b204e9800998ecf8427e");
        hashes.put("SHA-256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        File maliciousFile = File.builder()
            .name("malicious.exe")
            .size(524288L)
            .hashes(hashes)
            .mimeType("application/x-msdownload")
            .build();

        // Create process observable
        Process maliciousProcess = Process.builder()
            .pid(4567)
            .name("svchost.exe")
            .commandLine("svchost.exe -k malicious")
            .createdTime(new StixInstant())
            .build();

        // Network traffic
        NetworkTraffic suspiciousTraffic = NetworkTraffic.builder()
            .srcRef("ipv4-addr--1")
            .dstRef("ipv4-addr--2")
            .srcPort(49152)
            .dstPort(443)
            .addProtocol("tcp")
            .addProtocol("https")
            .srcByteCount(1024L)
            .dstByteCount(4096L)
            .build();

        // Create malware object
        Malware analyzedMalware = Malware.builder()
            .name("Trojan.Generic")
            .addLabel("trojan")
            .description("Generic trojan with data exfiltration capabilities")
            .isFamily(false)
            .addCapability("persistence")
            .addCapability("exfiltration")
            .addCapability("anti-analysis")
            .addImplementationLanguage("c++")
            .customProperty("x_sandbox_score", "95")
            .customProperty("x_detection_rate", "73%")
            .build();

        // Malware Analysis
        MalwareAnalysis analysis = MalwareAnalysis.builder()
            .product("Whisper Sandbox")
            .version("2.0")
            .hostVmRef("windows-10-x64")
            .operatingSystemRef("windows-10")
            .installedSoftwareRefs(Arrays.asList("office-2019", "chrome-v98"))
            .configurationVersion("2025.1")
            .submitted(new StixInstant())
            .analysisStarted(new StixInstant())
            .analysisEnded(new StixInstant().plusHours(1))
            .resultName("Trojan.Generic.XYZABC")
            .result("malicious")
            .analysisScoRef(maliciousFile)
            .addSample(maliciousFile)
            .customProperty("x_behavior_score", "95")
            .customProperty("x_evasion_techniques", "[\"Anti-VM\", \"Process Injection\"]")
            .build();

        // Create indicators
        Indicator fileIndicator = Indicator.builder()
            .pattern("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']")
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(90))
            .addLabel("malicious-activity")
            .confidence(95)
            .description("File hash indicator for known malware")
            .build();

        Indicator networkIndicator = Indicator.builder()
            .pattern("[network-traffic:dst_ref.value = '192.0.2.1' AND network-traffic:dst_port = 443]")
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(30))
            .addLabel("malicious-activity")
            .confidence(75)
            .description("C2 communication indicator")
            .build();

        // Create report
        Report analysisReport = Report.builder()
            .name("Malware Analysis Report - Trojan.Generic")
            .published(new StixInstant())
            .addLabel("malware-analysis")
            .description("Comprehensive analysis of Trojan.Generic sample")
            .addObjectRef(analyzedMalware.getId())
            .addObjectRef(analysis.getId())
            .addObjectRef(fileIndicator.getId())
            .addObjectRef(networkIndicator.getId())
            .build();

        return Bundle.builder()
            .addObject(maliciousFile)
            .addObject(analyzedMalware)
            .addObject(analysis)
            .addObject(fileIndicator)
            .addObject(networkIndicator)
            .addObject(analysisReport)
            .build();
    }
}
```

## Incident Response Documentation

Document security incidents for sharing and analysis.

```java
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.bundle.Bundle;

public class IncidentResponseExample {

    public Bundle documentSecurityIncident() {
        // Create the incident
        Incident ransomwareIncident = Incident.builder()
            .name("Ransomware Attack - January 2025")
            .description("Organization hit by ransomware affecting 500+ workstations")
            .customProperty("x_incident_id", "INC-2025-0142")
            .customProperty("x_severity", "HIGH")
            .customProperty("x_impact", "Major business disruption")
            .customProperty("x_detection_time", "2025-01-15T08:30:00Z")
            .customProperty("x_containment_time", "2025-01-15T10:45:00Z")
            .customProperty("x_recovery_time", "2025-01-17T18:00:00Z")
            .build();

        // Affected identity (organization)
        Identity targetOrganization = Identity.builder()
            .name("Example Corporation")
            .identityClass("organization")
            .addSector("technology")
            .description("Fortune 500 technology company")
            .build();

        // Attacker identity (unknown)
        Identity unknownAttacker = Identity.builder()
            .name("Unknown Ransomware Operator")
            .identityClass("unknown")
            .description("Unidentified ransomware group")
            .build();

        // The ransomware
        Malware ransomware = Malware.builder()
            .name("LockBit 3.0")
            .addLabel("ransomware")
            .description("LockBit 3.0 ransomware variant")
            .isFamily(true)
            .addCapability("encryption")
            .addCapability("data-destruction")
            .addCapability("exfiltration")
            .build();

        // Course of action taken
        CourseOfAction responseActions = CourseOfAction.builder()
            .name("Ransomware Response Playbook")
            .description("Standard incident response for ransomware attacks")
            .customProperty("x_steps", "[\"1. Isolate affected systems\", \"2. Preserve evidence\", \"3. Identify variant\", \"4. Restore from backups\", \"5. Apply security patches\"]")
            .build();

        // Vulnerability exploited
        Vulnerability exploitedVuln = Vulnerability.builder()
            .name("ProxyShell")
            .addExternalReference(ExternalReference.builder()
                .sourceName("NVD")
                .externalId("CVE-2021-34473")
                .url("https://nvd.nist.gov/vuln/detail/CVE-2021-34473")
                .build())
            .description("Exchange Server vulnerability used for initial access")
            .build();

        // Impact assessment
        Note impactAssessment = Note.builder()
            .content("Impact Assessment:\n" +
                    "- 500+ workstations encrypted\n" +
                    "- 72 hours of business disruption\n" +
                    "- Estimated loss: $2.5 million\n" +
                    "- Data exfiltration confirmed: 100GB\n" +
                    "- Ransom demand: 50 BTC")
            .addObjectRef(incident.getId())
            .addAuthor("Security Operations Center")
            .created(new StixInstant())
            .build();

        // Create relationships
        Relationship targetedBy = Relationship.builder()
            .relationshipType("targets")
            .sourceRef(unknownAttacker)
            .targetRef(targetOrganization)
            .build();

        Relationship usedMalware = Relationship.builder()
            .relationshipType("uses")
            .sourceRef(unknownAttacker)
            .targetRef(ransomware)
            .build();

        Relationship exploited = Relationship.builder()
            .relationshipType("exploits")
            .sourceRef(ransomware)
            .targetRef(exploitedVuln)
            .build();

        Relationship mitigated = Relationship.builder()
            .relationshipType("mitigates")
            .sourceRef(responseActions)
            .targetRef(ransomware)
            .build();

        // Create the incident report
        Report incidentReport = Report.builder()
            .name("Incident Report: Ransomware Attack January 2025")
            .published(new StixInstant())
            .addLabel("incident-report")
            .description("Complete documentation of ransomware incident")
            .addObjectRef(incident.getId())
            .addObjectRef(targetOrganization.getId())
            .addObjectRef(ransomware.getId())
            .addObjectRef(responseActions.getId())
            .addObjectRef(exploitedVuln.getId())
            .addObjectRef(impactAssessment.getId())
            .build();

        return Bundle.builder()
            .addObject(incident)
            .addObject(targetOrganization)
            .addObject(unknownAttacker)
            .addObject(ransomware)
            .addObject(responseActions)
            .addObject(exploitedVuln)
            .addObject(impactAssessment)
            .addObject(targetedBy)
            .addObject(usedMalware)
            .addObject(exploited)
            .addObject(mitigated)
            .addObject(incidentReport)
            .build();
    }
}
```

## Indicator Sharing

Share Indicators of Compromise (IOCs) with the community.

```java
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.common.StixInstant;
import java.util.Arrays;

public class IndicatorSharingExample {

    public Bundle createIOCBundle() {
        // File hash indicators
        Indicator md5Indicator = Indicator.builder()
            .pattern("[file:hashes.MD5 = 'abc123def456789012345678901234']")
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(90))
            .addLabel("malicious-activity")
            .confidence(100)
            .description("Known malware file hash")
            .addIndicatorType("file-hash")
            .addKillChainPhase(KillChainPhase.builder()
                .killChainName("lockheed-martin-cyber-kill-chain")
                .phaseName("installation")
                .build())
            .build();

        // Network indicators
        Indicator ipIndicator = Indicator.builder()
            .pattern("[ipv4-addr:value = '198.51.100.1' OR ipv4-addr:value = '198.51.100.2']")
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(30))
            .addLabel("malicious-activity")
            .confidence(85)
            .description("Known C2 server IP addresses")
            .addIndicatorType("ip-address")
            .build();

        Indicator domainIndicator = Indicator.builder()
            .pattern("[domain-name:value = 'evil-domain.com' OR domain-name:value = 'bad-site.net']")
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(60))
            .addLabel("malicious-activity")
            .confidence(90)
            .description("Malicious domains used for C2")
            .addIndicatorType("domain")
            .build();

        // URL indicator
        Indicator urlIndicator = Indicator.builder()
            .pattern("[url:value = 'http://evil-domain.com/malware.exe']")
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(30))
            .addLabel("malicious-activity")
            .confidence(95)
            .description("Direct malware download URL")
            .addIndicatorType("url")
            .build();

        // Email indicator
        Indicator emailIndicator = Indicator.builder()
            .pattern("[email-message:sender_ref.value = 'phisher@bad-domain.com' AND email-message:subject MATCHES '.*Invoice.*']")
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(45))
            .addLabel("phishing")
            .confidence(80)
            .description("Phishing email pattern")
            .addIndicatorType("email")
            .build();

        // Registry key indicator
        Indicator registryIndicator = Indicator.builder()
            .pattern("[windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\Software\\\\Malware']")
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(60))
            .addLabel("malicious-activity")
            .confidence(75)
            .description("Malware persistence registry key")
            .addIndicatorType("registry-key")
            .build();

        // Complex pattern combining multiple observables
        String complexPattern = "[file:hashes.MD5 = 'abc123def456789012345678901234' " +
                               "AND file:name = 'malware.exe'] " +
                               "FOLLOWEDBY [network-traffic:dst_ref.value = '198.51.100.1'] " +
                               "WITHIN 300 SECONDS";

        Indicator behaviorIndicator = Indicator.builder()
            .pattern(complexPattern)
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(30))
            .addLabel("malicious-activity")
            .confidence(92)
            .description("Behavioral pattern: malware execution followed by C2 communication")
            .addIndicatorType("behavioral")
            .patternType("stix")
            .patternVersion("2.1")
            .build();

        // Create a grouping for related indicators
        Grouping iocGroup = Grouping.builder()
            .name("Campaign X IOCs - January 2025")
            .context("suspicious-activity")
            .addObjectRef(md5Indicator.getId())
            .addObjectRef(ipIndicator.getId())
            .addObjectRef(domainIndicator.getId())
            .addObjectRef(urlIndicator.getId())
            .addObjectRef(emailIndicator.getId())
            .addObjectRef(registryIndicator.getId())
            .addObjectRef(behaviorIndicator.getId())
            .description("Collection of IOCs related to Campaign X")
            .build();

        // Add context with a malware object
        Malware relatedMalware = Malware.builder()
            .name("Campaign X Malware")
            .addLabel("trojan")
            .description("Trojan used in Campaign X attacks")
            .build();

        // Create relationships
        Relationship indicates1 = Relationship.builder()
            .relationshipType("indicates")
            .sourceRef(md5Indicator)
            .targetRef(relatedMalware)
            .build();

        Relationship indicates2 = Relationship.builder()
            .relationshipType("indicates")
            .sourceRef(ipIndicator)
            .targetRef(relatedMalware)
            .build();

        return Bundle.builder()
            .addObject(md5Indicator)
            .addObject(ipIndicator)
            .addObject(domainIndicator)
            .addObject(urlIndicator)
            .addObject(emailIndicator)
            .addObject(registryIndicator)
            .addObject(behaviorIndicator)
            .addObject(iocGroup)
            .addObject(relatedMalware)
            .addObject(indicates1)
            .addObject(indicates2)
            .build();
    }
}
```

## Attack Pattern Mapping

Map observed techniques to MITRE ATT&CK framework.

```java
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.sro.objects.*;
import security.whisper.javastix.bundle.Bundle;

public class AttackPatternExample {

    public Bundle mapToMitreAttack() {
        // Initial Access
        AttackPattern phishing = AttackPattern.builder()
            .name("Phishing")
            .description("Adversaries send phishing messages to gain access to victim systems")
            .addExternalReference(ExternalReference.builder()
                .sourceName("MITRE ATT&CK")
                .externalId("T1566")
                .url("https://attack.mitre.org/techniques/T1566/")
                .description("Phishing technique")
                .build())
            .addKillChainPhase(KillChainPhase.builder()
                .killChainName("mitre-attack")
                .phaseName("initial-access")
                .build())
            .build();

        // Execution
        AttackPattern powershell = AttackPattern.builder()
            .name("PowerShell")
            .description("Adversaries abuse PowerShell for execution")
            .addExternalReference(ExternalReference.builder()
                .sourceName("MITRE ATT&CK")
                .externalId("T1059.001")
                .url("https://attack.mitre.org/techniques/T1059/001/")
                .build())
            .addKillChainPhase(KillChainPhase.builder()
                .killChainName("mitre-attack")
                .phaseName("execution")
                .build())
            .build();

        // Persistence
        AttackPattern registryRunKeys = AttackPattern.builder()
            .name("Registry Run Keys")
            .description("Adversaries achieve persistence through Registry Run keys")
            .addExternalReference(ExternalReference.builder()
                .sourceName("MITRE ATT&CK")
                .externalId("T1547.001")
                .url("https://attack.mitre.org/techniques/T1547/001/")
                .build())
            .addKillChainPhase(KillChainPhase.builder()
                .killChainName("mitre-attack")
                .phaseName("persistence")
                .build())
            .addKillChainPhase(KillChainPhase.builder()
                .killChainName("mitre-attack")
                .phaseName("privilege-escalation")
                .build())
            .build();

        // Defense Evasion
        AttackPattern obfuscation = AttackPattern.builder()
            .name("Obfuscated Files or Information")
            .description("Adversaries use obfuscation to hide their malicious actions")
            .addExternalReference(ExternalReference.builder()
                .sourceName("MITRE ATT&CK")
                .externalId("T1027")
                .url("https://attack.mitre.org/techniques/T1027/")
                .build())
            .addKillChainPhase(KillChainPhase.builder()
                .killChainName("mitre-attack")
                .phaseName("defense-evasion")
                .build())
            .build();

        // Lateral Movement
        AttackPattern remoteServices = AttackPattern.builder()
            .name("Remote Services")
            .description("Adversaries use valid accounts to log into remote services")
            .addExternalReference(ExternalReference.builder()
                .sourceName("MITRE ATT&CK")
                .externalId("T1021")
                .url("https://attack.mitre.org/techniques/T1021/")
                .build())
            .addKillChainPhase(KillChainPhase.builder()
                .killChainName("mitre-attack")
                .phaseName("lateral-movement")
                .build())
            .build();

        // Collection
        AttackPattern dataFromLocalSystem = AttackPattern.builder()
            .name("Data from Local System")
            .description("Adversaries search local file systems for sensitive data")
            .addExternalReference(ExternalReference.builder()
                .sourceName("MITRE ATT&CK")
                .externalId("T1005")
                .url("https://attack.mitre.org/techniques/T1005/")
                .build())
            .addKillChainPhase(KillChainPhase.builder()
                .killChainName("mitre-attack")
                .phaseName("collection")
                .build())
            .build();

        // Exfiltration
        AttackPattern exfiltrationOverC2 = AttackPattern.builder()
            .name("Exfiltration Over C2 Channel")
            .description("Adversaries steal data over command and control channel")
            .addExternalReference(ExternalReference.builder()
                .sourceName("MITRE ATT&CK")
                .externalId("T1041")
                .url("https://attack.mitre.org/techniques/T1041/")
                .build())
            .addKillChainPhase(KillChainPhase.builder()
                .killChainName("mitre-attack")
                .phaseName("exfiltration")
                .build())
            .build();

        // Create a campaign that uses these techniques
        Campaign observedCampaign = Campaign.builder()
            .name("Advanced Attack Campaign")
            .description("Multi-stage attack campaign observed in January 2025")
            .firstSeen(StixInstant.fromString("2025-01-01T00:00:00.000Z"))
            .build();

        // Link campaign to attack patterns
        Relationship uses1 = Relationship.builder()
            .relationshipType("uses")
            .sourceRef(observedCampaign)
            .targetRef(phishing)
            .description("Campaign initiated through phishing emails")
            .build();

        Relationship uses2 = Relationship.builder()
            .relationshipType("uses")
            .sourceRef(observedCampaign)
            .targetRef(powershell)
            .description("PowerShell used for code execution")
            .build();

        Relationship uses3 = Relationship.builder()
            .relationshipType("uses")
            .sourceRef(observedCampaign)
            .targetRef(registryRunKeys)
            .description("Persistence achieved via Registry modifications")
            .build();

        // Create mitigation course of action
        CourseOfAction mitigation = CourseOfAction.builder()
            .name("Phishing Mitigation")
            .description("User training and email filtering to prevent phishing")
            .build();

        Relationship mitigates = Relationship.builder()
            .relationshipType("mitigates")
            .sourceRef(mitigation)
            .targetRef(phishing)
            .build();

        // Create a report
        Report attackReport = Report.builder()
            .name("Campaign Attack Pattern Analysis")
            .published(new StixInstant())
            .addLabel("attack-pattern")
            .description("Mapping of observed campaign to MITRE ATT&CK")
            .addObjectRef(observedCampaign.getId())
            .addObjectRef(phishing.getId())
            .addObjectRef(powershell.getId())
            .addObjectRef(registryRunKeys.getId())
            .addObjectRef(obfuscation.getId())
            .addObjectRef(remoteServices.getId())
            .addObjectRef(dataFromLocalSystem.getId())
            .addObjectRef(exfiltrationOverC2.getId())
            .build();

        return Bundle.builder()
            .addObject(phishing)
            .addObject(powershell)
            .addObject(registryRunKeys)
            .addObject(obfuscation)
            .addObject(remoteServices)
            .addObject(dataFromLocalSystem)
            .addObject(exfiltrationOverC2)
            .addObject(observedCampaign)
            .addObject(mitigation)
            .addObject(uses1)
            .addObject(uses2)
            .addObject(uses3)
            .addObject(mitigates)
            .addObject(attackReport)
            .build();
    }
}
```

## Next Steps

- Review the [Developer Guide](../user-guide/for-developers.md) for technical details
- Check the [Security Analyst Guide](../user-guide/for-security-analysts.md) for operational use
- Explore [Integration Patterns](integration-patterns.md) for connecting to other systems
- See [Best Practices](best-practices.md) for production deployment

## Support

For questions or issues:
- GitHub Issues: https://github.com/whisper-security/STIX/issues
- Documentation: https://github.com/whisper-security/STIX/docs
- Email: support@whisper.security