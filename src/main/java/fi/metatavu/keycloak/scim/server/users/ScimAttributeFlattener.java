package fi.metatavu.keycloak.scim.server.users;

import fi.metatavu.keycloak.scim.server.filter.ComparisonFilter;
import fi.metatavu.keycloak.scim.server.filter.ScimFilter;
import fi.metatavu.keycloak.scim.server.filter.ScimFilterParser;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Flattens complex and multi-valued SCIM user attributes into the flattened Keycloak attribute
 * keys defined by the SCIM schema URN
 * ({@code urn:ietf:params:scim:schemas:core:2.0:User:<attr>.<sub>[<index>]}). This lets values an
 * identity provider sends as an RFC 7644 value-filter path (e.g.
 * {@code phoneNumbers[type eq "work"].value}) or as a whole multi-valued array be stored as
 * unmanaged user attributes instead of being dropped. The layout matches what the earlier SCIM
 * extension used, so no duplicate keys are created for data migrated from it. Callers must only
 * apply these writes when the realm's unmanaged attribute policy is ENABLED.
 */
public final class ScimAttributeFlattener {

    static final String CORE_PREFIX = "urn:ietf:params:scim:schemas:core:2.0:User:";
    static final String ENTERPRISE_PREFIX = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:";

    private static final Set<String> ENTERPRISE_ATTRIBUTES = Set.of(
        "employeeNumber", "costCenter", "organization", "division", "department", "manager");

    // attr[ <filter> ]   with an optional  .subAttribute
    private static final Pattern VALUE_FILTER_PATH = Pattern.compile("^([^\\[]+)\\[([^\\]]+)](?:\\.(.+))?$");

    private static final ScimFilterParser FILTER_PARSER = new ScimFilterParser();

    private ScimAttributeFlattener() {
    }

    /**
     * Computes the flattened Keycloak attribute writes for an unmapped SCIM value, or an empty map
     * when the value cannot be flattened (caller then skips it as before).
     *
     * @param path normalized SCIM path (schema URN prefix already stripped)
     * @param value operation value: a scalar, or a list for a whole multi-valued attribute
     * @param existingAttributes the user's current attributes (used to resolve a value-filter index)
     * @return flattened key -> value writes, empty when not applicable
     */
    static Map<String, String> flatten(String path, Object value, Map<String, List<String>> existingAttributes) {
        if (path == null) {
            return Map.of();
        }
        Map<String, List<String>> existing = existingAttributes == null ? Map.of() : existingAttributes;
        if (path.contains("[")) {
            if (value instanceof String scalar) {
                return flattenValueFilterPath(path, scalar, existing);
            }
            return Map.of();
        }
        if (value instanceof List<?> array) {
            return flattenArray(path, array);
        }
        if (value instanceof String scalar) {
            return Map.of(prefixFor(path) + path, scalar);
        }
        return Map.of();
    }

    /**
     * Returns the schema URN prefix a SCIM user attribute is stored under.
     */
    static String prefixFor(String attribute) {
        return ENTERPRISE_ATTRIBUTES.contains(attribute) ? ENTERPRISE_PREFIX : CORE_PREFIX;
    }

    /**
     * Flattens a value-filter path such as {@code phoneNumbers[type eq "work"].value}, resolving
     * the type to the user's existing index for that type or the next free one.
     */
    static Map<String, String> flattenValueFilterPath(String path, String value, Map<String, List<String>> existingAttributes) {
        Matcher matcher = VALUE_FILTER_PATH.matcher(path);
        if (!matcher.matches()) {
            return Map.of();
        }
        String attribute = matcher.group(1).trim();
        String filterExpression = matcher.group(2).trim();
        String subAttribute = matcher.group(3) == null ? null : matcher.group(3).trim();
        if (subAttribute == null) {
            return Map.of();
        }
        String type = extractTypeEquals(filterExpression);
        if (type == null) {
            return Map.of();
        }
        String prefix = prefixFor(attribute);
        int index = resolveIndexForType(prefix, attribute, type, existingAttributes);
        Map<String, String> writes = new LinkedHashMap<>();
        writes.put(prefix + attribute + "." + subAttribute + "[" + index + "]", value);
        writes.put(prefix + attribute + ".type[" + index + "]", type);
        return writes;
    }

    /**
     * Flattens a whole multi-valued array such as
     * {@code phoneNumbers = [{"value":"...","type":"work"}]}.
     */
    static Map<String, String> flattenArray(String attribute, List<?> array) {
        String prefix = prefixFor(attribute);
        Map<String, String> writes = new LinkedHashMap<>();
        for (int index = 0; index < array.size(); index++) {
            if (array.get(index) instanceof Map<?, ?> element) {
                for (Map.Entry<?, ?> entry : element.entrySet()) {
                    if (entry.getValue() != null) {
                        writes.put(prefix + attribute + "." + entry.getKey() + "[" + index + "]", String.valueOf(entry.getValue()));
                    }
                }
            }
        }
        return writes;
    }

    private static String extractTypeEquals(String filterExpression) {
        try {
            ScimFilter filter = FILTER_PARSER.parse(filterExpression);
            if (filter instanceof ComparisonFilter comparison
                && "type".equalsIgnoreCase(comparison.attribute())
                && comparison.operator() == ScimFilter.Operator.EQ) {
                return comparison.value();
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private static int resolveIndexForType(String prefix, String attribute, String type, Map<String, List<String>> existingAttributes) {
        String typeKeyPrefix = prefix + attribute + ".type[";
        int maxIndex = -1;
        for (Map.Entry<String, List<String>> entry : existingAttributes.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith(typeKeyPrefix) && key.endsWith("]")) {
                try {
                    int index = Integer.parseInt(key.substring(typeKeyPrefix.length(), key.length() - 1));
                    maxIndex = Math.max(maxIndex, index);
                    if (entry.getValue() != null && entry.getValue().contains(type)) {
                        return index;
                    }
                } catch (NumberFormatException ignored) {
                    // not an indexed type key; ignore
                }
            }
        }
        return maxIndex + 1;
    }
}
