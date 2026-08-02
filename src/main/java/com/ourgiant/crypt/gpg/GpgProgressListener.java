package com.ourgiant.crypt.gpg;

@FunctionalInterface
public interface GpgProgressListener {
    void onMessage(String message);
}
