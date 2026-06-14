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
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
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
        val p = Design.Spacing.LG
        val gap = Design.Spacing.SM

        // Left column: Exposed Tools panel fills the space and handles its own scrolling
        val leftColumn = JPanel(BorderLayout()).apply {
            isOpaque = false
            border = BorderFactory.createEmptyBorder(p, p, p, gap)
            add(toolsSelectionPanel, BorderLayout.CENTER)
        }

        // Right column: Server Configuration + Installation stacked
        val rightContent = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            border = BorderFactory.createEmptyBorder(p, gap, p, p)
            add(serverConfigurationPanel)
            add(createVerticalStrut(Design.Spacing.MD))
            add(createVerticalGlue())
            add(reinstallNotice)
            add(createVerticalStrut(Design.Spacing.SM))
            add(installationPanel)
        }

        val mainPanel = JPanel(GridBagLayout()).apply {
            background = Design.Colors.surface
            val c = GridBagConstraints().apply { fill = GridBagConstraints.BOTH; weighty = 1.0 }
            c.gridx = 0; c.weightx = 0.6
            add(leftColumn, c)
            c.gridx = 1; c.weightx = 0.4
            add(rightContent, c)
        }

        panel.add(mainPanel, BorderLayout.CENTER)
    }
}