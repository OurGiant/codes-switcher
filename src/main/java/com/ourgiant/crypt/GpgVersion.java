package com.ourgiant.crypt;

public class GpgVersion {

    private GpgVersion() {
    }

    public static boolean isSufficient(String versionOutput, String requiredVersion) {
        try {
            // Extract version number (e.g., "gpg (GnuPG) 2.4.8" -> "2.4.8")
            String[] parts = versionOutput.split("\\s+");
            for (String part : parts) {
                if (part.matches("\\d+\\.\\d+\\.\\d+")) {
                    String[] current = part.split("\\.");
                    String[] required = requiredVersion.split("\\.");

                    for (int i = 0; i < Math.min(current.length, required.length); i++) {
                        int curr = Integer.parseInt(current[i]);
                        int req = Integer.parseInt(required[i]);
                        if (curr > req) return true;
                        if (curr < req) return false;
                    }
                    return true;
                }
            }
        } catch (Exception e) {
            // If parsing fails, assume insufficient
        }
        return false;
    }
}
