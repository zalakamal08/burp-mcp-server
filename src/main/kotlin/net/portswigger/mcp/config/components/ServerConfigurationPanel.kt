package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.ToggleSwitch
import java.awt.FlowLayout
import javax.swing.*
import javax.swing.Box.createHorizontalStrut
import javax.swing.Box.createVerticalStrut

class ServerConfigurationPanel(
    private val config: McpConfig,
    private val enabledToggle: ToggleSwitch,
    private val validationErrorLabel: WarningLabel,
    private val hostField: JTextField,
    private val portField: JTextField
) : JPanel() {

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        updateColors()
        alignmentX = LEFT_ALIGNMENT

        buildPanel()
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
    }

    private fun updateColors() {
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        )
    }

    private fun buildPanel() {
        add(Design.createSectionLabel("Server Configuration"))
        add(createVerticalStrut(Design.Spacing.MD))

        // Enable / Disable toggle
        val enabledPanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 4)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
        }
        enabledPanel.add(JLabel("Enabled").apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
        })
        enabledPanel.add(createHorizontalStrut(Design.Spacing.MD))
        enabledPanel.add(enabledToggle)
        add(enabledPanel)
        add(createVerticalStrut(Design.Spacing.LG))

        // Host / Port fields (always visible; editable only when server is stopped)
        val formPanel = createFormPanel(
            "Server host:" to hostField,
            "Server port:" to portField
        )
        add(formPanel)
        add(createVerticalStrut(Design.Spacing.MD))

        add(validationErrorLabel)
    }

    /** Lock or unlock the host/port fields based on whether the server is running. */
    fun setConnectionFieldsEnabled(enabled: Boolean) {
        hostField.isEnabled = enabled
        portField.isEnabled = enabled
    }

    private fun createFormPanel(vararg fields: Pair<String, JComponent>): JPanel {
        val formPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
        }

        for ((labelText, field) in fields) {
            val row = JPanel(FlowLayout(FlowLayout.LEFT, 0, Design.Spacing.SM)).apply {
                isOpaque = false
                alignmentX = LEFT_ALIGNMENT
            }
            row.add(JLabel(labelText).apply {
                font = Design.Typography.bodyLarge
                foreground = Design.Colors.onSurface
                preferredSize = java.awt.Dimension(100, 28)
            })
            row.add(createHorizontalStrut(Design.Spacing.MD))
            if (field is JTextField) {
                field.preferredSize = java.awt.Dimension(200, 28)
                field.font = Design.Typography.bodyLarge
            }
            row.add(field)
            formPanel.add(row)
        }

        return formPanel
    }

    // Kept for listener compatibility in ConfigUi — now a no-op since checkboxes are removed.
    fun updateHistoryAccessCheckboxes() = Unit
}