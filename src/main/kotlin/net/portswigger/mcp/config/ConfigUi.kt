package net.portswigger.mcp.config

import io.ktor.util.network.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.Swing
import net.portswigger.mcp.config.components.*
import net.portswigger.mcp.providers.Provider
import java.awt.BorderLayout
import javax.swing.*
import javax.swing.Box.*
import javax.swing.JOptionPane.ERROR_MESSAGE

class ConfigUi(private val config: McpConfig, private val providers: List<Provider>) {

    private val panel = JPanel(BorderLayout())
    val component: JComponent get() = panel

    private val listenerHandles = mutableListOf<ListenerHandle>()

    private val hostField = JTextField(15)
    private val portField = JTextField(5)
    private val reinstallNotice = WarningLabel("Make sure to reinstall after changing server settings")
    private val validationErrorLabel = WarningLabel()

    private val enabledToggle: ToggleSwitch = Design.createToggleSwitch(false) { enabled ->
        if (suppressToggleEvents) return@createToggleSwitch

        if (enabled) {
            ConfigValidation.validateServerConfig(hostField.text, portField.text)?.let { error ->
                validationErrorLabel.text = error
                validationErrorLabel.isVisible = true
                suppressToggleEvents = true
                enabledToggle.setState(false, animate = true)
                suppressToggleEvents = false
                return@createToggleSwitch
            }
        }

        validationErrorLabel.isVisible = false
        config.enabled = enabled
        toggleListener?.invoke(enabled)
    }

    private lateinit var serverConfigurationPanel: ServerConfigurationPanel
    private lateinit var installationPanel: InstallationPanel
    private lateinit var toolsSelectionPanel: ToolsSelectionPanel

    private var toggleListener: ((Boolean) -> Unit)? = null
    private var suppressToggleEvents: Boolean = false

    init {
        enabledToggle.setState(config.enabled, animate = false)
        hostField.text = config.host
        portField.text = config.port.toString()

        initializeComponents()
        buildUi()
    }

    private fun initializeComponents() {
        serverConfigurationPanel = ServerConfigurationPanel(
            config = config,
            enabledToggle = enabledToggle,
            validationErrorLabel = validationErrorLabel,
            hostField = hostField,
            portField = portField
        )

        installationPanel = InstallationPanel(
            config = config,
            providers = providers,
            reinstallNotice = reinstallNotice,
            parentComponent = panel
        )

        toolsSelectionPanel = ToolsSelectionPanel(config).also {
            // Checkboxes start locked if the extension is currently enabled (server will start)
            it.setCheckboxesEnabled(!config.enabled)
        }
    }

    fun cleanup() {
        listenerHandles.forEach { it.remove() }
        listenerHandles.clear()
    }

    fun onEnabledToggled(listener: (Boolean) -> Unit) {
        toggleListener = listener
    }

    fun getConfig(): McpConfig {
        config.host = hostField.text
        portField.text.toIntOrNull()?.let { config.port = it }
        return config
    }

    fun updateServerState(state: ServerState) {
        CoroutineScope(Dispatchers.Swing).launch {
            suppressToggleEvents = true

            // Host/port are only editable when the server is NOT running
            val fieldsEditable = state is ServerState.Stopped || state is ServerState.Failed
            serverConfigurationPanel.setConnectionFieldsEnabled(fieldsEditable)

            when (state) {
                ServerState.Starting, ServerState.Stopping -> {
                    enabledToggle.isEnabled = false
                    toolsSelectionPanel.setCheckboxesEnabled(false)
                }

                ServerState.Running -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(true, animate = false)
                    toolsSelectionPanel.setCheckboxesEnabled(false)
                }

                ServerState.Stopped -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(false, animate = false)
                    toolsSelectionPanel.setCheckboxesEnabled(true)
                }

                is ServerState.Failed -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(false, animate = false)
                    toolsSelectionPanel.setCheckboxesEnabled(true)

                    val friendlyMessage = when (state.exception) {
                        is UnresolvedAddressException -> "Unable to resolve address"
                        else -> state.exception.message ?: state.exception.javaClass.simpleName
                    }

                    Dialogs.showMessageDialog(
                        panel, "Failed to start Burp MCP Server: $friendlyMessage", ERROR_MESSAGE
                    )
                }
            }

            suppressToggleEvents = false
        }
    }

    private fun buildUi() {
        val content = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(
                Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG
            )
        }

        val scrollPane = JScrollPane(content).apply {
            border = null
            background = Design.Colors.surface
            viewport.background = Design.Colors.surface
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            verticalScrollBar.unitIncrement = 16
        }

        content.add(serverConfigurationPanel)
        content.add(createVerticalStrut(Design.Spacing.MD))
        content.add(toolsSelectionPanel)
        content.add(createVerticalGlue())
        content.add(reinstallNotice)
        content.add(createVerticalStrut(10))
        content.add(installationPanel)

        panel.add(scrollPane, BorderLayout.CENTER)
    }
}