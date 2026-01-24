import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class Extension implements BurpExtension
{
    private static final String EXT_NAME = "Browser Powered Session Handler";

    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName(EXT_NAME);

        ConfigManager configManager = new ConfigManager(api.persistence().extensionData(), api.logging());
        AtomicReference<Config> configRef = new AtomicReference<>(configManager.loadFromStorage());
        AtomicBoolean enabled = new AtomicBoolean(true);

        ApiClient apiClient = new ApiClient(api.logging(), configRef);
        LocalTokenCache localTokenCache = new LocalTokenCache(apiClient, configRef);
        ApiServiceManager apiServiceManager = new ApiServiceManager(api.logging(), api.extension().filename());

        UiController uiController = new UiController(
                api,
                configManager,
                apiClient,
                localTokenCache,
                apiServiceManager,
                configRef,
                enabled
        );

        api.userInterface().registerSuiteTab(EXT_NAME, uiController.buildUi());
        uiController.applyConfigToUi(configRef.get());

        api.http().registerHttpHandler(new HttpSessionHandler(api, configRef, apiClient, localTokenCache, enabled));

        api.extension().registerUnloadingHandler(apiServiceManager::stop);

        api.logging().logToOutput(EXT_NAME + " loaded");
    }
}
