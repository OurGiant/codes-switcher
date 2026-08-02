---
name: ship-issue
description: The standard workflow for shipping a bug fix or feature to Codes Switcher — file a GitHub issue, branch off main, implement, verify, bump the patch version, and open a PR. Use whenever picking up a bug fix or feature for this repo.
---

# Shipping a change to Codes Switcher

Follow `java-swing-ship-issue` (the generic workflow shared across the
Java Swing project family) with these Codes Switcher specifics:

- **Project path**: `/projects/codes-switcher` inside the build container
  (`festive_bardeen` as of this writing — see `java-swing-project-setup`
  §2 if it doesn't respond).
- **Verify**: use this repo's own `.claude/skills/verify/SKILL.md` for
  build/launch mechanics, the confirmed bind-mount staleness gotcha, and
  the confirmed-working `Robot` screenshot path.
- **GPG install/decrypt changes need extra care**: the risky
  process-shelling and filesystem logic (`decryptFile`, `checkGpgVersion`,
  `compileFromSource`/`prepareBuildDirectory`) lives in
  `com.ourgiant.crypt.gpg.GpgOperations`, kept Swing-free specifically so
  it's unit-testable — see `GpgOperationsTest` for the mocking pattern via
  the `ProcessStarter` seam. A change here should extend that test
  coverage rather than only being checked by hand through the GUI. If a
  test needs to touch `~/gpg-build`, redirect it via the
  `codes.switcher.gpgBuildDir` system property (see `GpgOperations`'
  `BUILD_DIR_PROPERTY` and the `maven-surefire-plugin` config in
  `pom.xml`) rather than touching a real developer's home directory.
- **Layered structure**: `GpgOperations` and its `GpgProgressListener`/
  `ProcessStarter` collaborators must stay free of `javax.swing.*`
  imports — GUI classes (`GPGDecryptor`, `EncodingDecodingApp`,
  `AppLauncher`) depend on domain logic one-way, never the reverse, per
  `java-swing-project-setup` §3. `TextCodec` and `GpgVersion` are also
  Swing-free and should stay that way.
- No repo-specific branch-naming or extra PR-checklist step beyond the
  generic workflow has been established here yet; follow
  `java-swing-ship-issue` as-is until one is.
