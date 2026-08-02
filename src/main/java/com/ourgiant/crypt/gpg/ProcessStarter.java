package com.ourgiant.crypt.gpg;

import java.io.IOException;
import java.util.List;

@FunctionalInterface
public interface ProcessStarter {
    Process start(List<String> command) throws IOException;
}
