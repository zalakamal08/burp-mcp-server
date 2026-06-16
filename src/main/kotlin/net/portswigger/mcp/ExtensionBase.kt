package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager

@Suppress("unused")
class ExtensionBase : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        val version = extensionVersion()
        api.extension().setName("Burp MCP Server v$version")
        api.logging().logToOutput("Burp MCP Server v$version loaded")

        val config = McpConfig(api.persistence().extensionData(), api.logging())
        val serverManager = KtorServerManager(api)

        val proxyJarManager = ProxyJarManager(api.logging())

        val configUi = ConfigUi(
            config = config, providers = listOf(
                ClaudeDesktopProvider(api.logging(), proxyJarManager),
                ManualProxyInstallerProvider(api.logging(), proxyJarManager),
            )
        )

        configUi.onEnabledToggled { enabled ->
            configUi.getConfig()

            if (enabled) {
                serverManager.start(config) { state ->
                    configUi.updateServerState(state)
                }
            } else {
                serverManager.stop { state ->
                    configUi.updateServerState(state)
                }
            }
        }

        api.userInterface().registerSuiteTab("MCP", configUi.component)

        api.extension().registerUnloadingHandler {
            serverManager.shutdown()
            configUi.cleanup()
            config.cleanup()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
            }
        }
    }

    // Reads the build version from the JAR manifest so the loaded build is identifiable
    // in Burp's UI and Output (helps confirm which JAR is actually running).
    private fun extensionVersion(): String = try {
        ExtensionBase::class.java.`package`?.implementationVersion
            ?: ExtensionBase::class.java.protectionDomain?.codeSource?.location?.let { url ->
                java.util.jar.JarFile(java.io.File(url.toURI())).use { jar ->
                    jar.manifest?.mainAttributes?.getValue("Implementation-Version")
                }
            }
            ?: "dev"
    } catch (e: Exception) {
        "dev"
    }
}