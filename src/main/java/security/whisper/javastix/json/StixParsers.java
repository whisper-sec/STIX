package security.whisper.javastix.json;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.bundle.BundleObject;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.common.Stix;
import security.whisper.javastix.common.StixBoolean;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.coo.extension.types.*;
import security.whisper.javastix.coo.objects.*;
import security.whisper.javastix.coo.objects.Process;
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.datamarkings.MarkingDefinition;
import security.whisper.javastix.datamarkings.objects.Statement;
import security.whisper.javastix.datamarkings.objects.Tlp;
import security.whisper.javastix.sro.objects.Relationship;
import security.whisper.javastix.sro.objects.Sighting;
import javax.validation.ValidationException;
import java.io.IOException;

/**
 * Default JSON Mapper is configured with JsonMapperBase configs + StixSubTypesModule + StixInstantModule
 */
public class StixParsers {

    private static ObjectMapper jsonMapper = new ObjectMapper()
            .registerModule(new ParameterNamesModule())
            .registerModule(new Jdk8Module())
            .registerModule(new JavaTimeModule())
            .registerModule(new GuavaModule())
            .registerModule(generateStixSubTypesModule())
            .registerModule(generateStixInstantModule())
            .registerModule(generateStixBooleanModule());

    /**
     * Generates a Base Object Mapper with some generic modules.
     *
     */
    public static ObjectMapper generateJsonMapperBase() {
        return new ObjectMapper()
                .registerModule(new ParameterNamesModule())
                .registerModule(new Jdk8Module())
                .registerModule(new JavaTimeModule())
                .registerModule(new GuavaModule());
    }

    public static ObjectMapper getJsonMapper() {
        return jsonMapper;
    }

    /**
     * Override for setting a custom configured ObjectMapper
     *
     */
    public static void setJsonMapper(ObjectMapper objectMapper) {
        jsonMapper = objectMapper;
    }

    /**
     * Generate a Jackson module for all STIX objects (SDOs, SROs, Markings, bundle, observables, and observable extensions)
     *
     */
    public static SimpleModule generateStixSubTypesModule() {
        SimpleModule module = new SimpleModule();

        Class<?>[] sdoClasses = {AttackPattern.class, Campaign.class, CourseOfAction.class,
                Identity.class, Indicator.class, IntrusionSet.class, Malware.class, ObservedData.class,
                Report.class, ThreatActor.class, Tool.class, Vulnerability.class};

        Class<?>[] sroClasses = {Relationship.class, Sighting.class};

        Class<?>[] dataMarkingClasses = {MarkingDefinition.class, Statement.class, Tlp.class};

        Class<?>[] bundleClasses = {Bundle.class};

        Class<?>[] cyberObservableClasses = {Artifact.class, AutonomousSystem.class, Directory.class,
                DomainName.class, EmailAddress.class, EmailMessage.class, File.class, Ipv4Address.class, Ipv6Address.class,
                MacAddress.class, Mutex.class, NetworkTraffic.class, Process.class, Software.class, Url.class,
                UserAccount.class, WindowsRegistryKey.class, X509Certificate.class};

        Class<?>[] cyberObservableExtensionClasses = {ArchiveFileExtension.class, HttpRequestExtension.class, IcmpExtension.class,
                NetworkSocketExtension.class, NtfsFileExtenstion.class, PdfFileExtension.class, RasterImageFileExtension.class,
                TcpExtension.class, UnixAccountExtension.class, WindowsPeBinaryFileExtension.class, WindowsProcessExtension.class,
                WindowsServiceExtension.class};

        module.registerSubtypes(sdoClasses);
        module.registerSubtypes(sroClasses);
        module.registerSubtypes(dataMarkingClasses);
        module.registerSubtypes(bundleClasses);
        module.registerSubtypes(cyberObservableClasses);
        module.registerSubtypes(cyberObservableExtensionClasses);

        return module;
    }

    public static SimpleModule generateStixInstantModule() {
        SimpleModule module = new SimpleModule();
        module.addSerializer(StixInstant.class, new StixInstantSerializer());
        module.addDeserializer(StixInstant.class, new StixInstantDeserializer());
        return module;
    }

    public static SimpleModule generateStixBooleanModule() {
        SimpleModule module = new SimpleModule();
        module.addSerializer(StixBoolean.class, new StixBooleanSerializer());
        module.addDeserializer(StixBoolean.class, new StixBooleanDeserializer());
        return module;
    }

    public static BundleObject parseBundle(String bundleJsonString) throws IOException, StixParserValidationException {
        try {
            return getJsonMapper().readValue(bundleJsonString, BundleObject.class);
        } catch (IOException ex) {
            if (ValidationException.class.isAssignableFrom(ex.getCause().getClass())) {
                throw new StixParserValidationException((ValidationException) ex.getCause());
            } else {
                throw ex;
            }
        }
    }

    public static BundleableObject parseObject(String objectJsonString) throws IOException, StixParserValidationException {
        try {
            return getJsonMapper().readValue(objectJsonString, BundleableObject.class);
        } catch (IOException ex) {
            if (ValidationException.class.isAssignableFrom(ex.getCause().getClass())) {
                throw new StixParserValidationException((ValidationException) ex.getCause());
            } else {
                throw ex;
            }
        }
    }

        public static <T extends Stix> T parse(String bundleJsonString, Class<T> stixClass) throws IOException, StixParserValidationException {
        try {
            return getJsonMapper().readValue(bundleJsonString, stixClass);
        } catch (IOException ex) {
            if (ValidationException.class.isAssignableFrom(ex.getCause().getClass())) {
                throw new StixParserValidationException((ValidationException) ex.getCause());
            } else {
                throw ex;
            }
        }
    }
}
