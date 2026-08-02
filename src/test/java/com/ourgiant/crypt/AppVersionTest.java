package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppVersionTest {

    @Test
    void resolvesToAFilteredVersionString() {
        String version = AppVersion.get();

        assertFalse(version.isBlank());
        assertFalse(version.startsWith("${"), "version.properties placeholder was not filtered: " + version);
    }

    @Test
    void matchesSemanticVersionPattern() {
        String version = AppVersion.get();

        assertTrue(version.matches("\\d+\\.\\d+\\.\\d+"), "expected M.m.patch version, got: " + version);
    }
}
