package com.ourgiant.crypt;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StegoPanelsTest {

    @Test
    void outputIsAlwaysPng() {
        assertEquals(Path.of("/tmp/a.png"), StegoPanels.pngPath(Path.of("/tmp/a.png")));
        assertEquals(Path.of("/tmp/a.PNG"), StegoPanels.pngPath(Path.of("/tmp/a.PNG")));
        assertEquals(Path.of("/tmp/photo.png"), StegoPanels.pngPath(Path.of("/tmp/photo.jpg")));
        assertEquals(Path.of("/tmp/photo.png"), StegoPanels.pngPath(Path.of("/tmp/photo.JPEG")));
        assertEquals(Path.of("/tmp/photo.png"), StegoPanels.pngPath(Path.of("/tmp/photo")));
        assertEquals(Path.of("/tmp/my.file.png"), StegoPanels.pngPath(Path.of("/tmp/my.file")));
    }
}
