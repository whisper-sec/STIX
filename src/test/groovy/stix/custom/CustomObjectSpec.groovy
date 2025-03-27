package stix.custom

import com.fasterxml.jackson.databind.ObjectMapper
import com.noctisnet.stix.bundle.BundleableObject
import com.noctisnet.stix.custom.StixCustomObject
import com.noctisnet.stix.custom.objects.CustomObject
import com.noctisnet.stix.json.StixParsers
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
