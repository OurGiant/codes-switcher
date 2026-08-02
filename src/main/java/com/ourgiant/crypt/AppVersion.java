package com.ourgiant.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public final class AppVersion {

    private static final String UNKNOWN = "unknown";

    private AppVersion() {
    }

    public static String get() {
        String version = AppVersion.class.getPackage().getImplementationVersion();
        if (version != null && !version.isBlank()) {
            return version;
        }
        return readFromPropertiesFallback();
    }

    private static String readFromPropertiesFallback() {
        try (InputStream in = AppVersion.class.getResourceAsStream("/version.properties")) {
            if (in != null) {
                Properties props = new Properties();
                props.load(in);
                String version = props.getProperty("version");
                if (version != null && !version.isBlank() && !version.startsWith("${")) {
                    return version;
                }
            }
        } catch (IOException e) {
            // Fall through to unknown below.
        }
        return UNKNOWN;
    }
}
