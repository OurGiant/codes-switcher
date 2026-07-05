package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GpgVersionTest {

    private static final String REQUIRED = "2.4.8";

    @Test
    void exactVersionIsSufficient() {
        assertTrue(GpgVersion.isSufficient("gpg (GnuPG) 2.4.8", REQUIRED));
    }

    @Test
    void newerPatchVersionIsSufficient() {
        assertTrue(GpgVersion.isSufficient("gpg (GnuPG) 2.4.9", REQUIRED));
    }

    @Test
    void newerMinorVersionIsSufficient() {
        assertTrue(GpgVersion.isSufficient("gpg (GnuPG) 2.5.0", REQUIRED));
    }

    @Test
    void newerMajorVersionIsSufficient() {
        assertTrue(GpgVersion.isSufficient("gpg (GnuPG) 3.0.0", REQUIRED));
    }

    @Test
    void olderPatchVersionIsInsufficient() {
        assertFalse(GpgVersion.isSufficient("gpg (GnuPG) 2.4.7", REQUIRED));
    }

    @Test
    void olderMinorVersionIsInsufficient() {
        assertFalse(GpgVersion.isSufficient("gpg (GnuPG) 2.2.27", REQUIRED));
    }

    @Test
    void unparsableVersionIsInsufficient() {
        assertFalse(GpgVersion.isSufficient("GPG not found", REQUIRED));
    }

    @Test
    void emptyStringIsInsufficient() {
        assertFalse(GpgVersion.isSufficient("", REQUIRED));
    }
}
