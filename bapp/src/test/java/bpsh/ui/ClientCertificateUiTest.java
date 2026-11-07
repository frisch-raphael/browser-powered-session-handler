package bpsh.ui;

import bpsh.browser.BrowserFlowRunner;
import bpsh.config.ConfigManager;
import bpsh.model.AuthenticationFailure;
import bpsh.model.JourneyDefinition;
import bpsh.model.JourneyKey;
import bpsh.mtls.JourneyTlsProxy;
import bpsh.mtls.Pkcs11Failures;
import bpsh.mtls.Pkcs11IdentityManager;
import bpsh.mtls.Pkcs11IdentityManagerTest;
import bpsh.secrets.SecretStore;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies certificate form state and saved identities without connecting to a security device. */
class ClientCertificateUiTest {
    @TempDir Path root;
    @Test void publicCertificateSummaryUsesNamesAndValidityBeforeTechnicalIdentifiers() {
        var certificate = new Pkcs11IdentityManager.CertificateInfo("CN=Rapha\\, Analyst,O=Example Corp,EMAILADDRESS=analyst@example.test", "CN=Corporate CA,O=Example Corp", "abc123",
                java.time.Instant.parse("2026-01-01T12:00:00Z"), java.time.Instant.parse("2027-01-01T12:00:00Z"), "a".repeat(64));
        String summary = CertificatePresentation.summary(certificate);
        assertTrue(summary.startsWith("Rapha, Analyst")); assertTrue(summary.contains("Organization: Example Corp")); assertTrue(summary.contains("Email: analyst@example.test"));
        assertTrue(summary.contains("Issued by: Corporate CA")); assertTrue(summary.contains("2026")); assertTrue(summary.contains("2027"));
        assertFalse(summary.contains("abc123")); assertFalse(summary.contains(certificate.sha256()));
        assertTrue(CertificatePresentation.technical(certificate).contains("Serial: abc123"));
        assertEquals("O=Example Corp", CertificatePresentation.name("O=Example Corp"));
    }

    private JourneyRegistryTest.NativeUi harness() {
        var harness = new JourneyRegistryTest().new NativeUi(); harness.root = root; return harness;
    }

    @Test void missingCertificateWithNoMiddlewareRevealsTheRequiredVisibleMiddlewareInput() throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.edt(() -> { editor.checks().get("mtls").doClick(0); ((JTabbedPane) h.member(editor.ui, "wizard")).setSelectedIndex(4); ((JButton) h.member(editor.ui, "testButton")).doClick(0); });
            var module = editor.fields().get("module"); h.await(() -> ((JTextArea) module.getClientProperty("validationMessage")).isVisible());
            h.edt(() -> {
                assertEquals(3, ((JTabbedPane) h.member(editor.ui, "wizard")).getSelectedIndex());
                assertTrue(editor.fields().get("module").isVisible()); assertFalse(((JPanel) h.member(editor.ui, "certificateSettings")).isVisible());
                assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).isLogOpen());
            });
        }
    }

    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings = {"missing", "empty", "malformed"})
    void unreadableCaBundlesIdentifyTheCaInputBeforeAnyCertificateOrProxyUse(String mode) throws Exception {
        Path ca = root.resolve("ca.pem");
        if (!mode.equals("missing")) java.nio.file.Files.writeString(ca, mode.equals("empty") ? "" : "synthetic invalid PEM");
        var mtls = new JourneyDefinition.Mtls(root.resolve("fake.dll").toString(), new JourneyDefinition.Slot(JourneyDefinition.SlotKind.ID, 7),
                "a".repeat(64), java.util.List.of(java.net.URI.create("https://login.example")), ca.toString());
        var failure = assertThrows(AuthenticationFailure.class, () -> new JourneyTlsProxy(mtls, null, null, java.time.Clock.systemUTC()));
        assertEquals(AuthenticationFailure.Input.TRUSTED_CA, failure.input().input());
        assertEquals(AuthenticationFailure.Cause.TRUST, failure.reason()); assertNull(failure.getCause());
        assertFalse(failure.getMessage().contains(ca.toString()));
    }

    @Test void singleDeviceIsDiscoveredWithoutPinAndNoManualSlotControlsAreDisplayed() throws Exception {
        var h = harness();
        Path module = java.nio.file.Files.writeString(root.resolve("fake-module.dll"), "unit fixture");
        var chosen = new java.util.concurrent.atomic.AtomicReference<Pkcs11IdentityManager.Device>();
        var loads = new java.util.concurrent.atomic.AtomicInteger();
        var tokens = java.util.List.of(new Pkcs11IdentityManager.TokenInfo(7392, "My security token", "Vendor", "Model", "serial"));
        try (var editor = h.new Editor(null, null, discoveryBackend(tokens, chosen, loads))) {
            h.edt(() -> {
                h.call(editor.ui, "newJourney", new Class<?>[]{});
                editor.checks().get("mtls").doClick();
                editor.fields().get("module").setText(module.toString());
                assertFalse(editor.fields().containsKey("slot"));
                assertFalse(h.member(editor.ui, "slotKind") instanceof java.awt.Component);
                assertFalse(((JPanel) h.member(editor.ui, "certificateSettings")).isVisible());
            });
            h.await(() -> { try { return h.member(editor.ui, "displayedDevice") != null; } catch (Exception error) { return false; } });
            h.edt(() -> {
                assertEquals("7392", h.member(editor.ui, "slotValue"));
                assertEquals(JourneyDefinition.SlotKind.ID, h.member(editor.ui, "slotKind"));
                assertEquals(0, loads.get()); assertNull(chosen.get(), "Discovery must not configure a logged-in provider.");
                assertTrue(((JPasswordField) h.member(editor.ui, "pin")).isVisible());
                assertFalse(((JTextArea) h.member(editor.ui, "certificateDetails")).isVisible());
                assertFalse(((JLabel) ((JTextArea) h.member(editor.ui, "certificateDetails")).getClientProperty("rowLabel")).isVisible());
                ((JPasswordField) h.member(editor.ui, "pin")).setText("synthetic-pin");
                h.call(editor.ui, "listCertificates", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> loads.get() == 1);
            assertEquals(new JourneyDefinition.Slot(JourneyDefinition.SlotKind.ID, 7392), chosen.get().slot());
        }
    }

    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void multipleDevicesWaitForAnInlineChoiceBeforeShowingPinOrCertificateActions(boolean select) throws Exception {
        var h = harness(); Path module = java.nio.file.Files.writeString(root.resolve("fake-module.dll"), "unit fixture");
        var chosen = new java.util.concurrent.atomic.AtomicReference<Pkcs11IdentityManager.Device>(); var loads = new java.util.concurrent.atomic.AtomicInteger();
        var tokens = java.util.List.of(new Pkcs11IdentityManager.TokenInfo(11, "Personal token", "Vendor", "Model", "one"), new Pkcs11IdentityManager.TokenInfo(99, "Work token", "Vendor", "Model", "two"));
        try (var editor = h.new Editor(null, null, discoveryBackend(tokens, chosen, loads))) {
            h.edt(() -> {
                h.call(editor.ui, "newJourney", new Class<?>[]{}); editor.checks().get("mtls").doClick();
                editor.fields().get("module").setText(module.toString());
            });
            SecurityDevicePicker picker = h.member(editor.ui, "devicePicker");
            JComboBox<Pkcs11IdentityManager.TokenInfo> choices = h.member(picker, "choices");
            h.await(() -> choices.getItemCount() == 2);
            h.edt(() -> {
                assertNull(picker.selected()); assertNull(choices.getSelectedItem());
                assertFalse(((JPanel) h.member(editor.ui, "certificateSettings")).isVisible());
                assertFalse(((JPasswordField) h.member(editor.ui, "pin")).isVisible());
                assertEquals(0, loads.get()); assertNull(chosen.get());
                if (select) {
                    choices.setSelectedItem(tokens.get(1));
                    assertTrue(((JPanel) h.member(editor.ui, "certificateSettings")).isVisible());
                    assertTrue(((JPasswordField) h.member(editor.ui, "pin")).isVisible());
                    ((JPasswordField) h.member(editor.ui, "pin")).setText("synthetic-pin");
                    h.call(editor.ui, "listCertificates", new Class<?>[]{boolean.class}, false);
                }
            });
            if (select) { h.await(() -> loads.get() == 1); assertEquals(new JourneyDefinition.Slot(JourneyDefinition.SlotKind.ID, 99), chosen.get().slot()); }
            else { assertEquals(0, loads.get()); assertNull(chosen.get()); h.edt(() -> assertEquals("0", h.member(editor.ui, "slotValue"))); }
        }
    }

    /** @param tokens Discovered devices. @param chosen Captures the only configured device. @param loads Counts PIN submissions. @return Symbolic native boundary with no hardware calls. */
    private static Pkcs11IdentityManager.NativeAccess discoveryBackend(java.util.List<Pkcs11IdentityManager.TokenInfo> tokens,
            java.util.concurrent.atomic.AtomicReference<Pkcs11IdentityManager.Device> chosen, java.util.concurrent.atomic.AtomicInteger loads) {
        return new Pkcs11IdentityManager.NativeAccess() {
            @Override public java.util.List<Pkcs11IdentityManager.TokenInfo> tokens(Path module) { assertFalse(SwingUtilities.isEventDispatchThread()); return tokens; }
            @Override public java.security.Provider configure(Pkcs11IdentityManager.Device device) { chosen.set(device); return Pkcs11IdentityManagerTest.provider(); }
            @Override public java.security.KeyStore load(java.security.Provider provider, char[] pin) throws Exception { loads.incrementAndGet(); assertArrayEquals("synthetic-pin".toCharArray(), pin); return Pkcs11IdentityManagerTest.empty(); }
        };
    }

    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings = {"ready", "delayed", "leave"})
    void missingMtlsPinRevealsItsInputWithoutOpeningTheLogAndWaitsForDeviceDiscovery(String mode) throws Exception {
        var h = harness(); Path module = java.nio.file.Files.writeString(root.resolve("fake-module.dll"), "unit fixture");
        var started = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(mode.equals("ready") ? 0 : 1);
        var backend = new Pkcs11IdentityManager.NativeAccess() {
            @Override public java.util.List<Pkcs11IdentityManager.TokenInfo> tokens(Path path) throws Exception {
                started.countDown(); release.await(); return java.util.List.of(new Pkcs11IdentityManager.TokenInfo(7392, "Token", "Vendor", "Model", "serial"));
            }
            @Override public java.security.Provider configure(Pkcs11IdentityManager.Device device) { fail("Missing-PIN validation must precede device login"); return null; }
            @Override public java.security.KeyStore load(java.security.Provider provider, char[] pin) { fail("No PIN may be submitted"); return null; }
        };
        String stored = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false), "/journeys/0", "mtls",
                Map.of("modulePath", module.toString(), "slot", Map.of("kind", "id", "value", 7392), "certificateSha256", "a".repeat(64), "origins", java.util.List.of("https://login.example")));
        try (var editor = h.new Editor(stored, (entry, recovery, deadline, cancelled) -> {
            // Exercise the production preflight; null browser/native services must never be reached.
            try (var values = SecretStore.Values.empty()) {
                return new BrowserFlowRunner(null, null, null, java.time.Clock.systemUTC()).run(entry.identity(), entry.definition(), values,
                        recovery, System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5), cancelled);
            }
        }, backend)) {
            try {
                var key = editor.registry.snapshot().resolve("employee").identity().key(); h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
                assertTrue(started.await(3, java.util.concurrent.TimeUnit.SECONDS));
                if (mode.equals("ready")) h.await(() -> { try { return h.member(editor.ui, "displayedDevice") != null; } catch (Exception error) { return false; } });
                h.edt(() -> { ((JTabbedPane) h.member(editor.ui, "wizard")).setSelectedIndex(4); ((JButton) h.member(editor.ui, "testButton")).doClick(0); });
                h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
                h.await(() -> { try { return ((JTabbedPane) h.member(editor.ui, "wizard")).getSelectedIndex() == 3; } catch (Exception error) { return false; } });
                if (mode.equals("leave")) h.edt(() -> ((JTabbedPane) h.member(editor.ui, "wizard")).setSelectedIndex(4));
                release.countDown();
                h.await(() -> { try { return h.member(editor.ui, "displayedDevice") != null; } catch (Exception error) { return false; } });
                h.edt(() -> {
                    var pin = (JPasswordField) h.member(editor.ui, "pin"); var guidance = (JTextArea) pin.getClientProperty("validationMessage");
                    if (mode.equals("leave")) { assertEquals(4, ((JTabbedPane) h.member(editor.ui, "wizard")).getSelectedIndex()); assertFalse(guidance.isVisible()); }
                    else { assertTrue(pin.isVisible()); assertTrue(pin.isEnabled()); assertTrue(guidance.isVisible()); assertTrue(guidance.getText().contains("mTLS PIN")); }
                    var status = (SessionStatusBar) h.member(editor.ui, "status"); assertFalse(status.isLogOpen());
                    assertEquals("New test events available", ((JToggleButton) h.member(status, "eventLog")).getAccessibleContext().getAccessibleDescription());
                });
            } finally { release.countDown(); }
        }
    }

    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings = {"module", "device", "pin", "certificate", "ca"})
    void runtimeCertificateErrorsRevealTheirIdentifiedControlWithoutOpeningTheLog(String mode) throws Exception {
        var h = harness(); Path module = java.nio.file.Files.writeString(root.resolve("fake-module.dll"), "unit fixture");
        var tokens = java.util.List.of(new Pkcs11IdentityManager.TokenInfo(7392, "Token", "Vendor", "Model", "serial"));
        String stored = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false), "/journeys/0", "mtls",
                Map.of("modulePath", module.toString(), "slot", Map.of("kind", "id", "value", 7392), "certificateSha256", "a".repeat(64), "origins", java.util.List.of("https://login.example")));
        try (var editor = h.new Editor(stored, (entry, recovery, deadline, cancelled) -> {
            throw switch (mode) {
                case "module" -> Pkcs11Failures.from(Pkcs11Failures.Operation.MODULE, new java.nio.file.NoSuchFileException("private-path"));
                case "device" -> Pkcs11Failures.from(Pkcs11Failures.Operation.INITIALIZE, new java.security.ProviderException("CKR_TOKEN_NOT_PRESENT"));
                case "pin" -> Pkcs11Failures.from(Pkcs11Failures.Operation.LOGIN, new java.security.ProviderException("CKR_PIN_INCORRECT"));
                case "certificate" -> Pkcs11Failures.from(Pkcs11Failures.Operation.CERTIFICATES, new java.security.ProviderException("CKR_KEY_HANDLE_INVALID"));
                default -> new AuthenticationFailure(AuthenticationFailure.Phase.PROXY, AuthenticationFailure.Cause.TRUST, "The CA bundle is unreadable.").atInput(AuthenticationFailure.Input.TRUSTED_CA);
            };
        }, discoveryBackend(tokens, new java.util.concurrent.atomic.AtomicReference<>(), new java.util.concurrent.atomic.AtomicInteger()))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return h.member(editor.ui, "displayedDevice") != null; } catch (Exception error) { return false; } });
            h.edt(() -> {
                ((JPasswordField) h.member(editor.ui, "pin")).setText("synthetic-pin");
                ((JTabbedPane) h.member(editor.ui, "wizard")).setSelectedIndex(4); ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
            String member = switch (mode) { case "device" -> "devicePicker"; case "pin" -> "pin"; case "certificate" -> "chooseCertificateButton"; default -> null; };
            JComponent target = member == null ? editor.fields().get(mode.equals("module") ? "module" : "ca") : h.member(editor.ui, member);
            h.await(() -> ((JTextArea) target.getClientProperty("validationMessage")).isVisible());
            h.edt(() -> {
                assertEquals(3, ((JTabbedPane) h.member(editor.ui, "wizard")).getSelectedIndex());
                assertTrue(target.isVisible()); assertTrue(target.isEnabled());
                if (mode.equals("ca")) assertTrue(((JPanel) h.member(editor.ui, "certificateAdvanced")).isVisible());
                assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).isLogOpen());
            });
        }
    }

    @Test void changingAChosenDeviceClearsItsPinAndCertificateBeforeShowingTheNewDeviceFields() throws Exception {
        var h = harness(); Path module = java.nio.file.Files.writeString(root.resolve("fake-module.dll"), "unit fixture");
        var tokens = java.util.List.of(new Pkcs11IdentityManager.TokenInfo(11, "First device", "Vendor", "Model", "one"), new Pkcs11IdentityManager.TokenInfo(99, "Second device", "Vendor", "Model", "two"));
        var loads = new java.util.concurrent.atomic.AtomicInteger();
        String stored = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false), "/journeys/0", "mtls",
                Map.of("modulePath", module.toString(), "slot", Map.of("kind", "id", "value", 11), "certificateSha256", "a".repeat(64), "origins", java.util.List.of("https://login.example")));
        try (var editor = h.new Editor(stored, null, discoveryBackend(tokens, new java.util.concurrent.atomic.AtomicReference<>(), loads))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return h.member(editor.ui, "displayedDevice") != null; } catch (Exception error) { return false; } });
            h.edt(() -> {
                var pin = (JPasswordField) h.member(editor.ui, "pin"); pin.setText("synthetic-pin");
                assertFalse(((JTextArea) h.member(editor.ui, "certificateDetails")).isVisible());
                var picker = (SecurityDevicePicker) h.member(editor.ui, "devicePicker");
                ((JComboBox<?>) h.member(picker, "choices")).setSelectedItem(tokens.get(1));
                assertEquals("99", h.member(editor.ui, "slotValue")); assertEquals(0, pin.getPassword().length);
                assertEquals("", h.member(editor.ui, "selectedCertificateSha256"));
                assertFalse(((JTextArea) h.member(editor.ui, "certificateDetails")).isVisible());
                assertFalse(((JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible()); assertEquals(0, loads.get());
            });
        }
    }

    @Test void obsoleteMiddlewareDiscoveryCannotRevealInputsOrSelectThePreviousDevice() throws Exception {
        var h = harness(); Path first = java.nio.file.Files.writeString(root.resolve("first.dll"), "unit fixture");
        Path second = java.nio.file.Files.writeString(root.resolve("second.dll"), "unit fixture");
        var started = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(1);
        var backend = new Pkcs11IdentityManager.NativeAccess() {
            @Override public java.util.List<Pkcs11IdentityManager.TokenInfo> tokens(Path module) throws Exception {
                if (module.equals(first.toRealPath())) { started.countDown(); release.await(); return java.util.List.of(new Pkcs11IdentityManager.TokenInfo(11, "Obsolete", "Vendor", "Model", "one")); }
                return java.util.List.of(new Pkcs11IdentityManager.TokenInfo(99, "Current", "Vendor", "Model", "two"));
            }
            @Override public java.security.Provider configure(Pkcs11IdentityManager.Device device) { fail("Discovery must not log in"); return null; }
            @Override public java.security.KeyStore load(java.security.Provider provider, char[] pin) { fail("Discovery must not submit a PIN"); return null; }
        };
        try (var editor = h.new Editor(null, null, backend)) {
            try {
                h.edt(() -> { h.call(editor.ui, "newJourney", new Class<?>[]{}); editor.checks().get("mtls").doClick(); editor.fields().get("module").setText(first.toString()); });
                assertTrue(started.await(3, java.util.concurrent.TimeUnit.SECONDS));
                h.edt(() -> { editor.fields().get("module").setText(second.toString()); assertFalse(((JPasswordField) h.member(editor.ui, "pin")).isVisible()); });
                h.await(() -> { try { return h.member(editor.ui, "displayedDevice") != null; } catch (Exception error) { return false; } });
                h.edt(() -> assertEquals("99", h.member(editor.ui, "slotValue")));
            } finally { release.countDown(); }
            h.edt(() -> assertEquals("99", h.member(editor.ui, "slotValue")));
        }
    }

    @Test void onlyTheLibraryPickerAppearsUntilALibraryPathIsChosen() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                h.call(editor.ui, "newJourney", new Class<?>[]{});
                editor.checks().get("mtls").doClick();
                JPanel settings = h.member(editor.ui, "certificateSettings");
                JPasswordField pin = h.member(editor.ui, "pin");
                assertTrue(editor.fields().get("module").isVisible()); assertFalse(settings.isVisible()); assertFalse(pin.isVisible());
                editor.fields().get("module").setText("C:/owned-test/middleware.dll");
                assertTrue(((SecurityDevicePicker) h.member(editor.ui, "devicePicker")).isVisible());
                assertFalse(settings.isVisible()); assertFalse(pin.isVisible()); assertFalse(pin.isEnabled());
                editor.fields().get("module").setText("");
                assertFalse(settings.isVisible()); assertFalse(pin.isVisible()); assertFalse(pin.isEnabled());
                editor.fields().get("module").setText("   "); assertFalse(settings.isVisible());
                assertTrue(editor.clock.workers.isEmpty());
            });
        }
    }

    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void failedCertificateChoiceDoesNotRevealInspectionForAnUnselectedOrChangedDevice(boolean savedSelection) throws Exception {
        var h = harness(); String stored = JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false);
        if (savedSelection) stored = JourneyRegistryTest.edit(stored, "/journeys/0", "mtls", Map.of("modulePath", "C:/owned-test/original.dll", "certificateSha256", "a".repeat(64), "origins", java.util.List.of("https://login.example")));
        try (var editor = h.new Editor(stored)) {
            var key = editor.registry.snapshot().resolve("employee").identity().key();
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                assertFalse(((JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible());
                if (!savedSelection) editor.checks().get("mtls").doClick();
                editor.fields().get("module").setText("C:/owned-test/missing.dll");
                ((JPasswordField) h.member(editor.ui, "pin")).setText("synthetic-pin");
                assertEquals("", h.member(editor.ui, "selectedCertificateSha256"));
                assertFalse(((JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible());
                h.call(editor.ui, "discoverDevices", new Class<?>[]{boolean.class}, true);
            });
            h.await(() -> !editor.diagnosticMessages.isEmpty());
            h.await(() -> { try { return !(boolean) h.member(editor.ui, "deviceDiscoveryRunning"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                SecurityDevicePicker picker = h.member(editor.ui, "devicePicker");
                JTextArea failure = h.member(picker, "summary");
                assertTrue(failure.isVisible()); assertTrue(failure.getText().contains("not found"));
                assertTrue(failure.getText().contains("absolute path"), "The chooser must display recovery guidance, not just the problem.");
                editor.fields().get("module").setText("C:/owned-test/another-missing.dll");
                assertFalse(failure.getText().contains("not found"), "A previous discovery error must clear when middleware changes.");
                assertEquals("", h.member(editor.ui, "selectedCertificateSha256"));
                assertFalse(((JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible());
                assertFalse(((JTextArea) h.member(editor.ui, "certificateDetails")).isVisible());
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.edt(() -> assertFalse(((JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible()));
        }
    }

    @Test void certificateIdentityStaysInternalAndPinIsUsedWithoutAnOptIn() throws Exception {
        var h = harness(); String fingerprint = "a".repeat(64);
        Path module = java.nio.file.Files.writeString(root.resolve("fake-module.dll"), "unit fixture");
        var tokens = java.util.List.of(new Pkcs11IdentityManager.TokenInfo(7392, "Token", "Vendor", "Model", "serial"));
        String stored = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false),
                "/journeys/0", "mtls", Map.of("modulePath", module.toString(), "slot", Map.of("kind", "id", "value", 7392), "certificateSha256", fingerprint,
                        "origins", java.util.List.of("https://login.example")));
        try (var editor = h.new Editor(stored, null, discoveryBackend(tokens, new java.util.concurrent.atomic.AtomicReference<>(), new java.util.concurrent.atomic.AtomicInteger()))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key();
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.await(() -> { try { return h.member(editor.ui, "displayedDevice") != null; } catch (Exception error) { return false; } });
            try (var values = editor.secrets.snapshot(key)) { assertNull(values.pin()); }
            h.edt(() -> {
                JPasswordField pin = h.member(editor.ui, "pin");
                assertTrue(pin.isVisible()); assertTrue(pin.isEnabled()); assertEquals(0, pin.getPassword().length);
                assertFalse(editor.checks().containsKey("pinSupplied")); assertFalse(editor.fields().containsKey("fingerprint"));
                assertFalse(((JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible(), "A saved fingerprint is not a loaded certificate");
                var details = (JTextArea) h.member(editor.ui, "certificateDetails");
                assertEquals("", details.getText()); assertFalse(details.isVisible()); assertFalse(((JLabel) details.getClientProperty("rowLabel")).isVisible());
                assertFalse(((JTextArea) h.member(editor.ui, "certificateDetails")).getText().contains(fingerprint));
                pin.setText("synthetic-pin");
                assertFalse(((JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible(), "Entering a PIN alone must not claim the certificate was loaded");
                assertFalse(details.isVisible());
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertEquals(fingerprint, editor.registry.snapshot().resolve(key).definition().mtls().certificateSha256());
            try (var values = editor.secrets.snapshot(key)) {
                char[] pin = values.pin();
                try { assertArrayEquals("synthetic-pin".toCharArray(), pin); } finally { if (pin != null) Arrays.fill(pin, '\0'); }
            }
            try (var saved = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) {
                assertEquals(fingerprint, saved.journeys().getFirst().mtls().certificateSha256());
                assertTrue(saved.secrets().isEmpty(), "Session-only PINs must stay out of the project file.");
            }
            h.edt(() -> {
                ((JPasswordField) h.member(editor.ui, "pin")).setText("");
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            try (var values = editor.secrets.snapshot(key)) { assertNull(values.pin(), "An empty editor must not invent a PIN value."); }
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading") && h.member(editor.ui, "displayedDevice") != null; } catch (Exception error) { return false; } });
            h.edt(() -> {
                assertEquals(fingerprint, h.member(editor.ui, "selectedCertificateSha256"));
                assertEquals(0, ((JPasswordField) h.member(editor.ui, "pin")).getPassword().length);
                assertFalse(((JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible());
                var details = (JTextArea) h.member(editor.ui, "certificateDetails");
                assertEquals("", details.getText()); assertFalse(details.isVisible()); assertFalse(((JLabel) details.getClientProperty("rowLabel")).isVisible());
            });
            assertTrue(editor.clock.workers.isEmpty(), "Editing and saving must not submit a PIN.");
        }
    }
}
