package security.whisper.javastix.coo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.coo.CyberObservableObject;
import security.whisper.javastix.validation.constraints.businessrule.BusinessRule;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotNull;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * process
 * <p>
 * The Process Object represents common properties of an instance of a computer
 * program as executed on an operating system.
 *
 */
@Value.Immutable @Serial.Version(1L)
@DefaultTypeValue(value = "process", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Coo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Process.class) @JsonDeserialize(builder = Process.Builder.class)
@JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
@JsonTypeName("process")
@JsonPropertyOrder({ "type", "extensions", "is_hidden", "pid", "name", "created", "cwd", "arguments", "command_line",
        "environment_variables", "opened_connection_refs", "creator_user_ref", "binary_ref", "parent_ref",
        "child_refs" })
@BusinessRule(ifExp = "true", thenExp = "getExtensions().isEmpty() == false || isHidden().isPresent() == true || getPid().isPresent() == true || getName().isPresent() == true || getCreated().isPresent() == true || getCwd().isPresent() == true || getArguments().isEmpty() == false || getCommandLine().isPresent() == true || getEnvironmentVariables().isEmpty() == false || getOpenedConnectionRefs().isEmpty() == false || getCreatorUserRef().isPresent() == true || getBinaryRef().isPresent() == true || getParentRef().isPresent() == true || getChildRefs().isEmpty() == false", errorMessage = "A Process Object MUST contain at least one property (other than type) from this object (or one of its extensions).")
public interface ProcessCoo extends CyberObservableObject {

    @JsonProperty("is_hidden")
    @JsonPropertyDescription("Specifies whether the process is hidden.")
    @NotNull
    Optional<Boolean> isHidden();

    @JsonProperty("pid")
    @JsonPropertyDescription("Specifies the Process ID, or PID, of the process.")
    Optional<Long> getPid();

    @JsonProperty("name")
    @JsonPropertyDescription("Specifies the name of the process.")
    Optional<String> getName();

    @JsonProperty("created")
    @JsonPropertyDescription("Specifies the date/time at which the process was created.")
    Optional<StixInstant> getCreated();

    @JsonProperty("cwd")
    @JsonPropertyDescription("Specifies the current working directory of the process.")
    Optional<String> getCwd();

    //@TODO need better clarification in the STIX SPEC about if this should be a SET or LIST. Are duplicate arguments allowed?
    @JsonProperty("arguments")
    @JsonPropertyDescription("Specifies the list of arguments used in executing the process.")
    default List<String> getArguments() {
        return null;
    }

    @JsonProperty("command_line")
    @JsonPropertyDescription("Specifies the full command line used in executing the process, including the process name (depending on the operating system).")
    default Optional<String> getCommandLine() {
        return Optional.empty();
    }

    @JsonProperty("environment_variables")
    @JsonPropertyDescription("Specifies the list of environment variables associated with the process as a dictionary.")
    default Map<String, String> getEnvironmentVariables() {
        return null;
    }

    @JsonProperty("opened_connection_refs")
    @JsonPropertyDescription("Specifies the list of network connections opened by the process, as a reference to one or more Network Traffic Objects.")
    default Set<String> getOpenedConnectionRefs() {
        return null;
    }

    @JsonProperty("creator_user_ref")
    @JsonPropertyDescription("Specifies the user that created the process, as a reference to a User Account Object.")
    default Optional<String> getCreatorUserRef() {
        return Optional.empty();
    }

    @JsonProperty("binary_ref")
    @JsonPropertyDescription("Specifies the executable binary that was executed as the process, as a reference to a File Object.")
    default Optional<String> getBinaryRef() {
        return Optional.empty();
    }

    @JsonProperty("parent_ref")
    @JsonPropertyDescription("Specifies the other process that spawned (i.e. is the parent of) this one, as represented by a Process Object.")
    default Optional<String> getParentRef() {
        return Optional.empty();
    }

    @JsonProperty("child_refs")
    @JsonPropertyDescription("Specifies the other processes that were spawned by (i.e. children of) this process, as a reference to one or more other Process Objects.")
    default Set<String> getChildRefs() {
        return null;
    }

    /**
     * Deterministically generates the ID for this process based on its PID and name.
     * Uses PID if available, otherwise uses name, otherwise uses command line.
     */
    @Override
    @Value.Derived
    default String getId() {
        StringBuilder identifier = new StringBuilder();

        if (getPid().isPresent()) {
            identifier.append("pid:").append(getPid().get());
        }

        if (getName().isPresent()) {
            if (identifier.length() > 0) identifier.append(":");
            identifier.append(getName().get());
        } else if (getCommandLine().isPresent()) {
            if (identifier.length() > 0) identifier.append(":");
            identifier.append(getCommandLine().get());
        }

        if (identifier.length() == 0) {
            identifier.append("process:unknown");
        }

        return "process--" + UUID.nameUUIDFromBytes(identifier.toString().getBytes(StandardCharsets.UTF_8));
    }

}
