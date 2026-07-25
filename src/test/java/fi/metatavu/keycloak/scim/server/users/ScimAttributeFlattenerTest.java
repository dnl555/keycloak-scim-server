package fi.metatavu.keycloak.scim.server.users;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link ScimAttributeFlattener}. Cover the two identity-provider shapes that
 * reach the server: a value-filter PATCH path (Azure/Entra) and a whole multi-valued array
 * (Okta / on create), plus index resolution against existing data.
 */
class ScimAttributeFlattenerTest {

    private static final String CORE = "urn:ietf:params:scim:schemas:core:2.0:User:";
    private static final String ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:";

    @Test
    void valueFilterPath_newUser_writesIndexZeroWithType() {
        Map<String, String> writes = ScimAttributeFlattener.flatten(
            "phoneNumbers[type eq \"work\"].value", "555-0101", Map.of());

        assertEquals("555-0101", writes.get(CORE + "phoneNumbers.value[0]"));
        assertEquals("work", writes.get(CORE + "phoneNumbers.type[0]"));
    }

    @Test
    void valueFilterPath_matchesExistingTypeIndex() {
        // migrated layout: mobile at [0], work at [1]
        Map<String, List<String>> existing = Map.of(
            CORE + "phoneNumbers.type[0]", List.of("mobile"),
            CORE + "phoneNumbers.type[1]", List.of("work"));

        Map<String, String> writes = ScimAttributeFlattener.flatten(
            "phoneNumbers[type eq \"work\"].value", "555-0000", existing);

        // must update the work entry [1], not create a duplicate
        assertEquals("555-0000", writes.get(CORE + "phoneNumbers.value[1]"));
        assertTrue(writes.keySet().stream().noneMatch(k -> k.endsWith("value[0]")));
    }

    @Test
    void valueFilterPath_unseenType_appendsNextIndex() {
        Map<String, List<String>> existing = Map.of(
            CORE + "phoneNumbers.type[0]", List.of("mobile"));

        Map<String, String> writes = ScimAttributeFlattener.flatten(
            "phoneNumbers[type eq \"work\"].value", "555-1111", existing);

        assertEquals("555-1111", writes.get(CORE + "phoneNumbers.value[1]"));
        assertEquals("work", writes.get(CORE + "phoneNumbers.type[1]"));
    }

    @Test
    void addressSubAttributes_shareTheSameTypeIndex() {
        Map<String, List<String>> existing = Map.of(
            CORE + "addresses.type[0]", List.of("work"));

        Map<String, String> street = ScimAttributeFlattener.flatten(
            "addresses[type eq \"work\"].streetAddress", "123 Example St", existing);
        Map<String, String> locality = ScimAttributeFlattener.flatten(
            "addresses[type eq \"work\"].locality", "Springfield", existing);

        assertEquals("123 Example St", street.get(CORE + "addresses.streetAddress[0]"));
        assertEquals("Springfield", locality.get(CORE + "addresses.locality[0]"));
    }

    @Test
    void wholeArray_okta_flattensEachElement() {
        List<Map<String, Object>> phones = List.of(
            Map.of("value", "555-0102", "type", "work", "primary", true));

        Map<String, String> writes = ScimAttributeFlattener.flatten("phoneNumbers", phones, Map.of());

        assertEquals("555-0102", writes.get(CORE + "phoneNumbers.value[0]"));
        assertEquals("work", writes.get(CORE + "phoneNumbers.type[0]"));
        assertEquals("true", writes.get(CORE + "phoneNumbers.primary[0]"));
    }

    @Test
    void simpleScalar_storedUnderBareCoreUrn() {
        Map<String, String> writes = ScimAttributeFlattener.flatten("nickName", "Ace", Map.of());
        assertEquals("Ace", writes.get(CORE + "nickName"));
    }

    @Test
    void enterpriseAttribute_usesEnterprisePrefix() {
        assertEquals(ENTERPRISE + "employeeNumber",
            ScimAttributeFlattener.flatten("employeeNumber", "000000001", Map.of()).keySet().iterator().next());
    }

    @Test
    void nonTypeFilter_isNotFlattened() {
        Map<String, String> writes = ScimAttributeFlattener.flatten(
            "members[value eq \"abc\"].display", "x", Map.of());
        assertTrue(writes.isEmpty());
    }
}
