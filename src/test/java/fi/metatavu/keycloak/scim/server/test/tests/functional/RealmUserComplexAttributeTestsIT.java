package fi.metatavu.keycloak.scim.server.test.tests.functional;

import fi.metatavu.keycloak.scim.server.test.ScimClient;
import fi.metatavu.keycloak.scim.server.test.TestConsts;
import fi.metatavu.keycloak.scim.server.test.client.ApiException;
import fi.metatavu.keycloak.scim.server.test.client.model.PatchRequest;
import fi.metatavu.keycloak.scim.server.test.client.model.PatchRequestOperationsInner;
import fi.metatavu.keycloak.scim.server.test.client.model.User;
import fi.metatavu.keycloak.scim.server.test.tests.AbstractInternalAuthRealmScimTest;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Verifies that complex and multi-valued SCIM attributes an identity provider sends (which the
 * server does not otherwise map) are stored as flattened unmanaged attributes under the SCIM
 * schema URN keys, instead of being dropped. Covers both provider shapes: a value-filter PATCH
 * path (Azure/Entra) and a whole multi-valued array on create (Okta).
 */
@Testcontainers
public class RealmUserComplexAttributeTestsIT extends AbstractInternalAuthRealmScimTest {

    private static final String CORE = "urn:ietf:params:scim:schemas:core:2.0:User:";

    @Test
    void valueFilterPatch_storesFlattenedPhoneUnderUrnKey() throws ApiException {
        ScimClient scimClient = getAuthenticatedScimClient();
        User created = createUser(scimClient, "entra-phone-user");

        scimClient.patchUser(created.getId(), replace("phoneNumbers[type eq \"work\"].value", "555-0101"));

        Map<String, List<String>> attributes = findRealmUser(TestConsts.TEST_REALM, created.getId()).getAttributes();
        assertNotNull(attributes);
        assertEquals(List.of("555-0101"), attributes.get(CORE + "phoneNumbers.value[0]"));
        assertEquals(List.of("work"), attributes.get(CORE + "phoneNumbers.type[0]"));
    }

    @Test
    void wholeArrayCreate_storesFlattenedPhoneUnderUrnKeys() throws ApiException {
        ScimClient scimClient = getAuthenticatedScimClient();

        User user = new User();
        user.setUserName("okta-phone-user");
        user.setActive(true);
        user.setSchemas(List.of("urn:ietf:params:scim:schemas:core:2.0:User"));
        user.putAdditionalProperty("phoneNumbers",
            List.of(Map.of("value", "555-0102", "type", "work", "primary", "true")));

        User created = scimClient.createUser(user);
        assertNotNull(created);

        Map<String, List<String>> attributes = findRealmUser(TestConsts.TEST_REALM, created.getId()).getAttributes();
        assertNotNull(attributes);
        assertEquals(List.of("555-0102"), attributes.get(CORE + "phoneNumbers.value[0]"));
        assertEquals(List.of("work"), attributes.get(CORE + "phoneNumbers.type[0]"));
        assertEquals(List.of("true"), attributes.get(CORE + "phoneNumbers.primary[0]"));
    }

    @Test
    void valueFilterPatch_updatesExistingTypeIndexInPlace() throws ApiException {
        ScimClient scimClient = getAuthenticatedScimClient();
        User created = createUser(scimClient, "entra-reindex-user");

        // lay down mobile at [0], work at [1]
        scimClient.patchUser(created.getId(), replace("phoneNumbers[type eq \"mobile\"].value", "111"));
        scimClient.patchUser(created.getId(), replace("phoneNumbers[type eq \"work\"].value", "222"));
        // update work again: must reuse [1], not create a duplicate
        scimClient.patchUser(created.getId(), replace("phoneNumbers[type eq \"work\"].value", "999"));

        Map<String, List<String>> attributes = findRealmUser(TestConsts.TEST_REALM, created.getId()).getAttributes();
        assertEquals(List.of("111"), attributes.get(CORE + "phoneNumbers.value[0]"));
        assertEquals(List.of("999"), attributes.get(CORE + "phoneNumbers.value[1]"));
        assertEquals(List.of("work"), attributes.get(CORE + "phoneNumbers.type[1]"));
    }

    @Test
    void valueFilterPatch_addressSubAttributesShareTheSameIndex() throws ApiException {
        ScimClient scimClient = getAuthenticatedScimClient();
        User created = createUser(scimClient, "entra-address-user");

        scimClient.patchUser(created.getId(), replace("addresses[type eq \"work\"].streetAddress", "123 Example St"));
        scimClient.patchUser(created.getId(), replace("addresses[type eq \"work\"].locality", "Springfield"));

        Map<String, List<String>> attributes = findRealmUser(TestConsts.TEST_REALM, created.getId()).getAttributes();
        assertEquals(List.of("123 Example St"), attributes.get(CORE + "addresses.streetAddress[0]"));
        assertEquals(List.of("Springfield"), attributes.get(CORE + "addresses.locality[0]"));
        assertEquals(List.of("work"), attributes.get(CORE + "addresses.type[0]"));
    }

    private User createUser(ScimClient scimClient, String userName) throws ApiException {
        User user = new User();
        user.setUserName(userName);
        user.setActive(true);
        user.setSchemas(List.of("urn:ietf:params:scim:schemas:core:2.0:User"));
        User created = scimClient.createUser(user);
        assertNotNull(created);
        return created;
    }

    private PatchRequest replace(String path, Object value) {
        return new PatchRequest()
            .schemas(List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"))
            .operations(List.of(new PatchRequestOperationsInner()
                .op("replace")
                .path(path)
                .value(value)));
    }
}
