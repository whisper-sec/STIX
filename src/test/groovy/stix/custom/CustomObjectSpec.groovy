package stix.custom

import com.fasterxml.jackson.databind.ObjectMapper
import security.whisper.javastix.bundle.BundleableObject
import security.whisper.javastix.custom.StixCustomObject
import security.whisper.javastix.custom.objects.CustomObject
import security.whisper.javastix.json.StixParsers
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class CustomObjectSpec extends Specification {

    @Shared ObjectMapper mapper = new ObjectMapper()

    @Unroll
    def "Generic Object Test 1"() {
        when: "Attempt to Parse a custom object"
            String jsonString = getClass().getResource("/stix/custom/custom_object_1.json").getText("UTF-8")

        then:
            StixCustomObject originalObject = (StixCustomObject)StixParsers.parseObject(jsonString)
            StixCustomObject originalObjectGeneric = StixParsers.parse(jsonString, CustomObject.class)
            BundleableObject bundleableObject = StixParsers.parse(jsonString, BundleableObject.class)
//            println originalObject
//            println originalObjectGeneric
//            println bundleableObject
//            println "********"
    }
}
