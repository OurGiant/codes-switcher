---
name: verify
description: How to build, launch, and drive Codes Switcher to verify a Swing UI change actually works on this dev setup. Use before trusting the generic verify-java-swing skill's screenshot step; read that skill too for the underlying techniques (modal-dialog deadlock, synthetic MouseEvent dispatch, process safety).
---

# Verifying Codes Switcher

This is the project-specific companion to the generic `verify-java-swing`
skill (techniques) and `java-swing-project-setup` (build/structure
standard this project follows). Read those first — this file is what to
actually type for *this* project.

## Build here, run there

Maven only exists in the Docker container, not on the host:

```bash
docker exec festive_bardeen bash -c "cd /projects/codes-switcher && mvn -q package -DskipTests"
```

If `festive_bardeen` doesn't respond, find the current container:
`docker ps -a --format '{{.Names}} {{.Status}} {{.Image}}'` and
`docker start <name>` if stopped — the name can drift across sessions.

`/projects` is bind-mounted from the host's `~/projects`, so the jar lands
at `target/decrypter-all.jar`, visible on the host. The container is
headless (no `DISPLAY`) — run the jar on the **host**, not inside the
container, or it dies at `JFrame` construction with `HeadlessException`.

```bash
java -jar target/decrypter-all.jar
```

Main class (the tool picker): `com.ourgiant.crypt.AppLauncher`. The two
tools are also directly runnable:

```bash
java -cp target/decrypter-all.jar com.ourgiant.crypt.GPGDecryptor
java -cp target/decrypter-all.jar com.ourgiant.crypt.EncodingDecodingApp
```

## pom.xml edits can look ignored — force-sync the bind mount before assuming your change is wrong

Confirmed on this project: after editing `pom.xml` on the host, a
subsequent `mvn package` inside the container built a jar whose shaded
temp-file name (visible in the build log) still referenced the *old*
version string, and the container's own `grep` of `pom.xml` showed the
stale content — not just a stale build artifact. `docker cp` the file in
before trusting the build:

```bash
docker cp pom.xml festive_bardeen:/projects/codes-switcher/pom.xml
docker exec festive_bardeen grep -n '<version>' /projects/codes-switcher/pom.xml   # confirm it matches the host
```

This isn't limited to `pom.xml` — the same staleness has been seen on
`.java` files too (per `java-swing-project-setup` §2). If a build seems to
ignore a just-made edit, `docker cp` the specific file in before spending
time looking for a bug that isn't there.

## Screenshots: Robot actually works here — confirmed by sampling pixels, don't assume otherwise

This host has a real X11 display (`DISPLAY=:1`, `xdpyinfo` succeeds), and
`Robot.createScreenCapture(...)` was confirmed to return genuine,
non-black pixel data — average sampled RGB ~202 across a live
`AppLauncher` window, not just a visually-eyeballed PNG. Try it first here
rather than jumping to the reflection/log-based fallback other sibling
projects needed on their Wayland/COSMIC sessions.

## Driving the two tools for real

Both `GPGDecryptor.decryptFile()` (via the extracted
`com.ourgiant.crypt.gpg.GpgOperations`) and `EncodingDecodingApp`'s
encode/decode buttons have been verified end-to-end with a real click and
real backing operation, not just reflection state checks:

- **Encoder/Decoder**: set `inputTextArea`'s text via reflection, call
  `encodeButton.doClick()` on the EDT, read `outputTextArea` back.
- **GPG Decryptor**: this host has a real `gpg` binary installed, so a
  genuine round trip is possible — encrypt a fixture with
  `gpg --batch --yes --pinentry-mode loopback --passphrase "..." -c -o file.gpg file.txt`,
  set the encrypted/output/passphrase fields via reflection, click
  `decryptButton`, then poll `Window.getWindows()` for the modal success
  `JDialog` (it appears *asynchronously* after the background
  `SwingWorker` finishes — `decryptFile()` itself returns immediately, so
  `invokeAndWait(decryptButton::doClick)` is safe and does **not** hit the
  modal-dialog deadlock described in `verify-java-swing` §3), dismiss it,
  and diff the output file's content against the original plaintext.

## Nothing else confirmed yet

No other project-specific gotchas (first-run state location, dialog
sizing quirks, etc.) have turned up yet. Add them here as they do, the
way `kiro-control-panel`'s `verify` skill records its `JEditorPane` sizing
gotcha.
