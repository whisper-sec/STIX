# Integration Patterns

This guide demonstrates how to integrate the STIX 2.1 Java Library with various security platforms and tools.

## Table of Contents

1. [SIEM Integration](#siem-integration)
2. [Threat Intelligence Platform](#threat-intelligence-platform)
3. [SOAR Integration](#soar-integration)
4. [REST API Service](#rest-api-service)
5. [Message Queue Integration](#message-queue-integration)
6. [Database Persistence](#database-persistence)

## SIEM Integration

### Splunk Integration

```java
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.sdo.objects.Indicator;
import com.splunk.Service;
import com.splunk.ServiceArgs;
import com.splunk.Index;
import java.util.Map;

public class SplunkIntegration {

    private Service splunkService;

    public SplunkIntegration(String host, int port, String username, String password) {
        ServiceArgs loginArgs = new ServiceArgs();
        loginArgs.setHost(host);
        loginArgs.setPort(port);
        loginArgs.setUsername(username);
        loginArgs.setPassword(password);

        this.splunkService = Service.connect(loginArgs);
    }

    public void sendSTIXToSplunk(Bundle bundle) {
        Index stixIndex = splunkService.getIndexes().get("stix_threat_intel");

        // Send each STIX object as an event
        bundle.getObjects().forEach(obj -> {
            String jsonEvent = obj.toJsonString();

            // Add metadata
            Map<String, Object> args = new HashMap<>();
            args.put("sourcetype", "stix:2.1");
            args.put("source", "stix-java-library");
            args.put("host", "threat-intel-system");

            stixIndex.submit(jsonEvent, args);
        });
    }

    public void createSplunkSearch(Indicator indicator) {
        String pattern = indicator.getPattern();
        String splunkQuery = convertSTIXPatternToSPL(pattern);

        // Create saved search
        String searchName = "STIX_Indicator_" + indicator.getId();
        String searchQuery = String.format(
            "index=* %s | table _time, src_ip, dest_ip, action, user",
            splunkQuery
        );

        Map<String, Object> args = new HashMap<>();
        args.put("search", searchQuery);
        args.put("cron_schedule", "*/5 * * * *");  // Every 5 minutes
        args.put("alert.track", "1");
        args.put("alert.severity", "2");

        splunkService.getSavedSearches().create(searchName, args);
    }

    private String convertSTIXPatternToSPL(String stixPattern) {
        // Convert STIX pattern to Splunk query
        // [ipv4-addr:value = '192.0.2.1'] -> src_ip="192.0.2.1" OR dest_ip="192.0.2.1"

        String spl = stixPattern
            .replaceAll("\\[ipv4-addr:value = '([^']+)'\\]",
                       "(src_ip=\"$1\" OR dest_ip=\"$1\")")
            .replaceAll("\\[file:hashes\\.MD5 = '([^']+)'\\]",
                       "file_hash=\"$1\"")
            .replaceAll("\\[domain-name:value = '([^']+)'\\]",
                       "domain=\"$1\"");

        return spl;
    }
}
```

### Elastic/ELK Integration

```java
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.sdo.objects.*;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.common.xcontent.XContentType;
import java.time.format.DateTimeFormatter;

public class ElasticIntegration {

    private RestHighLevelClient elasticClient;
    private static final String STIX_INDEX = "stix-threat-intel";

    public ElasticIntegration(RestHighLevelClient client) {
        this.elasticClient = client;
    }

    public void indexSTIXBundle(Bundle bundle) throws IOException {
        String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

        bundle.getObjects().forEach(obj -> {
            try {
                IndexRequest request = new IndexRequest(STIX_INDEX)
                    .id(obj.getId())
                    .source(obj.toJsonString(), XContentType.JSON);

                elasticClient.index(request, RequestOptions.DEFAULT);
            } catch (IOException e) {
                log.error("Failed to index STIX object: " + obj.getId(), e);
            }
        });
    }

    public void createWatcher(Indicator indicator) {
        // Create Watcher alert for the indicator
        String watcherJson = String.format("""
            {
              "trigger": {
                "schedule": {"interval": "5m"}
              },
              "input": {
                "search": {
                  "request": {
                    "indices": ["filebeat-*", "packetbeat-*"],
                    "body": {
                      "query": {
                        "bool": {
                          "must": [%s]
                        }
                      }
                    }
                  }
                }
              },
              "condition": {
                "compare": {
                  "ctx.payload.hits.total": {"gt": 0}
                }
              },
              "actions": {
                "send_alert": {
                  "webhook": {
                    "url": "http://soc-alert-system/alert",
                    "body": "STIX Indicator Match: %s"
                  }
                }
              }
            }
            """,
            convertPatternToElasticQuery(indicator.getPattern()),
            indicator.getId()
        );

        // Create the watcher
        elasticClient.performRequest(
            "PUT",
            "_watcher/watch/stix_" + indicator.getId(),
            Collections.emptyMap(),
            new StringEntity(watcherJson)
        );
    }
}
```

## Threat Intelligence Platform

### MISP Integration

```java
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.sdo.objects.*;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;

public class MISPIntegration {

    private String mispUrl;
    private String apiKey;
    private HttpClient httpClient;

    public MISPIntegration(String url, String apiKey) {
        this.mispUrl = url;
        this.apiKey = apiKey;
        this.httpClient = HttpClients.createDefault();
    }

    public String createMISPEvent(Bundle bundle) throws Exception {
        // Convert STIX bundle to MISP event
        JSONObject mispEvent = new JSONObject();
        mispEvent.put("info", "STIX Import: " + new Date());
        mispEvent.put("threat_level_id", "2");
        mispEvent.put("published", false);
        mispEvent.put("analysis", "1");
        mispEvent.put("distribution", "3");

        JSONArray attributes = new JSONArray();

        // Process indicators
        bundle.getObjects().stream()
            .filter(obj -> obj instanceof Indicator)
            .map(obj -> (Indicator) obj)
            .forEach(indicator -> {
                JSONObject attr = convertIndicatorToMISPAttribute(indicator);
                attributes.put(attr);
            });

        mispEvent.put("Attribute", attributes);

        // Send to MISP
        HttpPost request = new HttpPost(mispUrl + "/events/add");
        request.setHeader("Authorization", apiKey);
        request.setHeader("Content-Type", "application/json");
        request.setEntity(new StringEntity(mispEvent.toString()));

        HttpResponse response = httpClient.execute(request);
        return EntityUtils.toString(response.getEntity());
    }

    private JSONObject convertIndicatorToMISPAttribute(Indicator indicator) {
        JSONObject attr = new JSONObject();

        String pattern = indicator.getPattern();

        // Parse STIX pattern to MISP attribute
        if (pattern.contains("file:hashes.MD5")) {
            attr.put("type", "md5");
            attr.put("value", extractValue(pattern));
        } else if (pattern.contains("ipv4-addr:value")) {
            attr.put("type", "ip-dst");
            attr.put("value", extractValue(pattern));
        } else if (pattern.contains("domain-name:value")) {
            attr.put("type", "domain");
            attr.put("value", extractValue(pattern));
        } else if (pattern.contains("url:value")) {
            attr.put("type", "url");
            attr.put("value", extractValue(pattern));
        }

        attr.put("comment", indicator.getDescription());
        attr.put("to_ids", true);
        attr.put("distribution", "3");

        return attr;
    }
}
```

### OpenCTI Integration

```java
import security.whisper.javastix.bundle.Bundle;
import graphql.GraphQL;
import graphql.ExecutionResult;

public class OpenCTIIntegration {

    private GraphQL graphQL;
    private String apiToken;

    public OpenCTIIntegration(String openctiUrl, String apiToken) {
        this.apiToken = apiToken;
        // Initialize GraphQL client
        this.graphQL = GraphQL.newGraphQL(schema).build();
    }

    public void importSTIXBundle(Bundle bundle) {
        String mutation = """
            mutation ImportBundle($bundle: String!) {
                stixDomainObjectAdd(input: {
                    stix_bundle: $bundle
                }) {
                    id
                    created
                    modified
                }
            }
        """;

        Map<String, Object> variables = new HashMap<>();
        variables.put("bundle", bundle.toJsonString());

        ExecutionResult result = graphQL.execute(
            ExecutionInput.newExecutionInput()
                .query(mutation)
                .variables(variables)
                .context(Map.of("authorization", "Bearer " + apiToken))
                .build()
        );

        if (result.getErrors() != null && !result.getErrors().isEmpty()) {
            throw new RuntimeException("Failed to import: " + result.getErrors());
        }
    }

    public Bundle queryThreatActors(String name) {
        String query = """
            query SearchThreatActors($name: String!) {
                threatActors(search: $name) {
                    edges {
                        node {
                            id
                            name
                            description
                            labels
                            sophistication
                            resource_level
                            primary_motivation
                        }
                    }
                }
            }
        """;

        Map<String, Object> variables = Map.of("name", name);

        ExecutionResult result = graphQL.execute(
            ExecutionInput.newExecutionInput()
                .query(query)
                .variables(variables)
                .context(Map.of("authorization", "Bearer " + apiToken))
                .build()
        );

        // Convert results to STIX objects
        List<ThreatActor> actors = parseGraphQLResult(result);

        return Bundle.builder()
            .addAllObjects(actors)
            .build();
    }
}
```

## SOAR Integration

### Phantom/Splunk SOAR Integration

```java
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.sdo.objects.*;

public class PhantomSOARIntegration {

    private String phantomUrl;
    private String authToken;
    private RestTemplate restTemplate;

    public PhantomSOARIntegration(String url, String token) {
        this.phantomUrl = url;
        this.authToken = token;
        this.restTemplate = new RestTemplate();
    }

    public void createPlaybookFromSTIX(Bundle bundle) {
        // Extract indicators and create playbook
        List<Indicator> indicators = bundle.getObjects().stream()
            .filter(obj -> obj instanceof Indicator)
            .map(obj -> (Indicator) obj)
            .collect(Collectors.toList());

        for (Indicator indicator : indicators) {
            createPhantomContainer(indicator);
        }
    }

    private void createPhantomContainer(Indicator indicator) {
        Map<String, Object> container = new HashMap<>();
        container.put("name", "STIX Indicator: " + indicator.getName());
        container.put("description", indicator.getDescription());
        container.put("label", "threat_intel");
        container.put("severity", mapConfidenceToSeverity(indicator.getConfidence()));
        container.put("status", "new");

        // Add artifacts
        List<Map<String, Object>> artifacts = new ArrayList<>();
        Map<String, Object> artifact = new HashMap<>();
        artifact.put("name", "STIX Pattern");
        artifact.put("cef", parsePatternToCEF(indicator.getPattern()));
        artifact.put("source_data_identifier", indicator.getId());
        artifacts.add(artifact);

        container.put("artifacts", artifacts);

        // Create container via API
        HttpHeaders headers = new HttpHeaders();
        headers.set("ph-auth-token", authToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(container, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
            phantomUrl + "/rest/container",
            request,
            Map.class
        );

        if (response.getStatusCode() == HttpStatus.OK) {
            String containerId = response.getBody().get("id").toString();
            triggerPlaybook(containerId, "investigate_stix_indicator");
        }
    }

    private void triggerPlaybook(String containerId, String playbookName) {
        Map<String, Object> playbook = new HashMap<>();
        playbook.put("container_id", containerId);
        playbook.put("playbook", playbookName);
        playbook.put("scope", "new");
        playbook.put("run", true);

        HttpHeaders headers = new HttpHeaders();
        headers.set("ph-auth-token", authToken);

        restTemplate.postForEntity(
            phantomUrl + "/rest/playbook_run",
            new HttpEntity<>(playbook, headers),
            Map.class
        );
    }
}
```

## REST API Service

### Spring Boot REST Service

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.sdo.objects.*;
import javax.validation.Valid;

@SpringBootApplication
@RestController
@RequestMapping("/api/stix")
public class STIXRestService {

    private final STIXRepository repository;

    public STIXRestService(STIXRepository repository) {
        this.repository = repository;
    }

    @PostMapping("/bundle")
    public ResponseEntity<Bundle> createBundle(@Valid @RequestBody Bundle bundle) {
        // Validate and store bundle
        Bundle stored = repository.save(bundle);
        return ResponseEntity.ok(stored);
    }

    @GetMapping("/bundle/{id}")
    public ResponseEntity<Bundle> getBundle(@PathVariable String id) {
        return repository.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/indicator")
    public ResponseEntity<Indicator> createIndicator(@Valid @RequestBody IndicatorDTO dto) {
        Indicator indicator = Indicator.builder()
            .pattern(dto.getPattern())
            .validFrom(new StixInstant())
            .validUntil(new StixInstant().plusDays(dto.getValidityDays()))
            .addLabel(dto.getLabel())
            .confidence(dto.getConfidence())
            .description(dto.getDescription())
            .build();

        Indicator stored = repository.saveIndicator(indicator);
        return ResponseEntity.ok(stored);
    }

    @GetMapping("/indicators")
    public ResponseEntity<List<Indicator>> getActiveIndicators() {
        StixInstant now = new StixInstant();
        List<Indicator> active = repository.findIndicatorsValidAt(now);
        return ResponseEntity.ok(active);
    }

    @PostMapping("/search")
    public ResponseEntity<Bundle> searchObjects(@RequestBody SearchRequest request) {
        List<STIXDomainObject> results = repository.search(
            request.getType(),
            request.getFilters(),
            request.getLimit()
        );

        Bundle bundle = Bundle.builder()
            .addAllObjects(results)
            .build();

        return ResponseEntity.ok(bundle);
    }

    @PostMapping("/validate")
    public ResponseEntity<ValidationResult> validateSTIX(@RequestBody String stixJson) {
        try {
            Bundle bundle = StixParsers.parseBundle(stixJson);
            return ResponseEntity.ok(new ValidationResult(true, "Valid STIX 2.1"));
        } catch (Exception e) {
            return ResponseEntity.ok(new ValidationResult(false, e.getMessage()));
        }
    }

    @PostMapping("/convert/csv")
    public ResponseEntity<Bundle> convertCSVToSTIX(@RequestParam MultipartFile file) {
        List<Indicator> indicators = parseCSVToIndicators(file);

        Bundle bundle = Bundle.builder()
            .addAllObjects(indicators)
            .build();

        return ResponseEntity.ok(bundle);
    }

    public static void main(String[] args) {
        SpringApplication.run(STIXRestService.class, args);
    }
}
```

## Message Queue Integration

### Apache Kafka Integration

```java
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import security.whisper.javastix.bundle.Bundle;

public class KafkaSTIXIntegration {

    private KafkaProducer<String, String> producer;
    private KafkaConsumer<String, String> consumer;

    public KafkaSTIXIntegration(Properties kafkaConfig) {
        this.producer = new KafkaProducer<>(kafkaConfig);
        this.consumer = new KafkaConsumer<>(kafkaConfig);
    }

    public void publishThreatIntel(Bundle bundle) {
        String topic = "stix-threat-intel";

        // Publish entire bundle
        ProducerRecord<String, String> record = new ProducerRecord<>(
            topic,
            bundle.getId(),
            bundle.toJsonString()
        );

        producer.send(record, (metadata, exception) -> {
            if (exception != null) {
                log.error("Failed to publish STIX bundle", exception);
            } else {
                log.info("Published bundle to partition {} offset {}",
                    metadata.partition(), metadata.offset());
            }
        });

        // Also publish individual high-priority indicators
        bundle.getObjects().stream()
            .filter(obj -> obj instanceof Indicator)
            .map(obj -> (Indicator) obj)
            .filter(ind -> ind.getConfidence() != null && ind.getConfidence() > 90)
            .forEach(indicator -> {
                ProducerRecord<String, String> indRecord = new ProducerRecord<>(
                    "high-priority-iocs",
                    indicator.getId(),
                    indicator.toJsonString()
                );
                producer.send(indRecord);
            });
    }

    public void consumeThreatIntel() {
        consumer.subscribe(Arrays.asList("stix-threat-intel", "external-threat-feeds"));

        while (true) {
            ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(100));

            for (ConsumerRecord<String, String> record : records) {
                try {
                    Bundle bundle = StixParsers.parseBundle(record.value());
                    processThreatIntel(bundle);
                } catch (Exception e) {
                    log.error("Failed to process STIX bundle", e);
                }
            }

            consumer.commitSync();
        }
    }

    private void processThreatIntel(Bundle bundle) {
        // Process the threat intelligence
        log.info("Processing bundle with {} objects", bundle.getObjects().size());

        // Update threat database
        // Send alerts for high-priority threats
        // Trigger automated responses
    }
}
```

## Database Persistence

### JPA/Hibernate Persistence

```java
import javax.persistence.*;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.sdo.objects.*;

@Entity
@Table(name = "stix_objects")
public class STIXEntity {

    @Id
    private String id;

    @Column(name = "stix_type")
    private String type;

    @Column(columnDefinition = "TEXT")
    private String jsonData;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "modified_at")
    private Instant modifiedAt;

    @Column(name = "valid_from")
    private Instant validFrom;

    @Column(name = "valid_until")
    private Instant validUntil;

    // Getters and setters
}

@Repository
public class STIXRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Transactional
    public void saveBundle(Bundle bundle) {
        bundle.getObjects().forEach(obj -> {
            STIXEntity entity = new STIXEntity();
            entity.setId(obj.getId());
            entity.setType(obj.getType());
            entity.setJsonData(obj.toJsonString());
            entity.setCreatedAt(Instant.now());

            if (obj instanceof Indicator) {
                Indicator ind = (Indicator) obj;
                entity.setValidFrom(ind.getValidFrom().toInstant());
                entity.setValidUntil(ind.getValidUntil().toInstant());
            }

            entityManager.merge(entity);
        });
    }

    public Bundle findBundleById(String bundleId) {
        List<STIXEntity> entities = entityManager
            .createQuery("SELECT e FROM STIXEntity e WHERE e.bundleId = :id", STIXEntity.class)
            .setParameter("id", bundleId)
            .getResultList();

        List<STIXDomainObject> objects = entities.stream()
            .map(e -> StixParsers.parse(e.getJsonData(), e.getType()))
            .collect(Collectors.toList());

        return Bundle.builder()
            .id(bundleId)
            .addAllObjects(objects)
            .build();
    }

    @Transactional
    public void cleanupExpiredIndicators() {
        entityManager.createQuery(
            "DELETE FROM STIXEntity e WHERE e.type = 'indicator' AND e.validUntil < :now")
            .setParameter("now", Instant.now())
            .executeUpdate();
    }
}
```

### MongoDB Persistence

```java
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import security.whisper.javastix.bundle.Bundle;

public class MongoDBSTIXRepository {

    private MongoDatabase database;

    public MongoDBSTIXRepository(MongoClient mongoClient) {
        this.database = mongoClient.getDatabase("threat_intel");
    }

    public void saveBundle(Bundle bundle) {
        MongoCollection<Document> collection = database.getCollection("stix_bundles");

        Document doc = Document.parse(bundle.toJsonString());
        doc.append("_id", bundle.getId());
        doc.append("imported_at", new Date());

        collection.insertOne(doc);

        // Also store individual objects for easier querying
        MongoCollection<Document> objectsCollection = database.getCollection("stix_objects");

        bundle.getObjects().forEach(obj -> {
            Document objDoc = Document.parse(obj.toJsonString());
            objDoc.append("_id", obj.getId());
            objDoc.append("bundle_id", bundle.getId());
            objectsCollection.replaceOne(
                Filters.eq("_id", obj.getId()),
                objDoc,
                new ReplaceOptions().upsert(true)
            );
        });
    }

    public List<Indicator> findActiveIndicators() {
        MongoCollection<Document> collection = database.getCollection("stix_objects");

        Date now = new Date();
        List<Document> docs = collection.find(
            Filters.and(
                Filters.eq("type", "indicator"),
                Filters.lte("valid_from", now),
                Filters.gte("valid_until", now)
            )
        ).into(new ArrayList<>());

        return docs.stream()
            .map(doc -> StixParsers.parseIndicator(doc.toJson()))
            .collect(Collectors.toList());
    }

    public void createIndexes() {
        MongoCollection<Document> collection = database.getCollection("stix_objects");

        // Create indexes for efficient querying
        collection.createIndex(Indexes.ascending("type"));
        collection.createIndex(Indexes.ascending("created"));
        collection.createIndex(Indexes.ascending("modified"));
        collection.createIndex(Indexes.compound(
            Indexes.ascending("type"),
            Indexes.ascending("valid_from"),
            Indexes.ascending("valid_until")
        ));
        collection.createIndex(Indexes.text("name", "description"));
    }
}
```

## Best Practices

1. **Error Handling**: Always implement robust error handling for external integrations
2. **Retry Logic**: Implement exponential backoff for failed API calls
3. **Batch Processing**: Process large bundles in batches to avoid memory issues
4. **Monitoring**: Add metrics and logging for integration health
5. **Security**: Use secure connections (TLS) and proper authentication
6. **Validation**: Validate STIX data before sending to external systems

## Support

For questions about integrations:
- GitHub Issues: https://github.com/whisper-security/STIX/issues
- Documentation: https://github.com/whisper-security/STIX/docs
- Email: support@whisper.security