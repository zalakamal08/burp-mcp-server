package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.ToolDef
import net.portswigger.mcp.config.ToolDefinitions
import java.awt.Dimension
import javax.swing.*
import javax.swing.Box.createHorizontalStrut
import javax.swing.Box.createVerticalStrut

class ToolsSelectionPanel(private val config: McpConfig) : JPanel() {

    private val checkboxes = mutableMapOf<String, JCheckBox>()

    private val hintLabel = object : JLabel("Disable the extension to modify tool selection") {
        init { updateColors() }
        override fun updateUI() { super.updateUI(); updateColors() }
        private fun updateColors() {
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.warning
        }
    }.apply { alignmentX = LEFT_ALIGNMENT }

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
            BorderFactory.createEmptyBorder(
                Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD
            )
        )
    }

    private fun buildPanel() {
        add(Design.createSectionLabel("Exposed Tools"))
        add(createVerticalStrut(Design.Spacing.SM))
        add(hintLabel)
        add(createVerticalStrut(Design.Spacing.MD))

        val orderedCategories = ToolDefinitions.categoryOrder.filter { it in ToolDefinitions.byCategory }

        orderedCategories.forEachIndexed { idx, category ->
            val tools = ToolDefinitions.byCategory[category] ?: return@forEachIndexed
            add(createCategoryGroup(category, tools))
            if (idx < orderedCategories.lastIndex) {
                add(createVerticalStrut(Design.Spacing.SM))
            }
        }
    }

    private fun createCategoryGroup(category: String, tools: List<ToolDef>): JPanel {
        val row = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
        }

        val catLabel = object : JLabel(category) {
            init { updateColors() }
            override fun updateUI() { super.updateUI(); updateColors() }
            private fun updateColors() {
                font = Design.Typography.labelLarge
                foreground = Design.Colors.onSurface
            }
        }.apply {
            val w = 110
            preferredSize = Dimension(w, preferredSize.height)
            minimumSize = Dimension(w, 0)
            maximumSize = Dimension(w, Int.MAX_VALUE)
            horizontalAlignment = SwingConstants.LEFT
            alignmentY = TOP_ALIGNMENT
        }

        val checkPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            alignmentY = TOP_ALIGNMENT
            alignmentX = LEFT_ALIGNMENT
        }

        tools.forEach { tool ->
            val label = tool.displayName + if (tool.proOnly) " (Pro)" else ""
            val cb = object : JCheckBox(label, config.isToolEnabled(tool.name)) {
                init { updateColors() }
                override fun updateUI() { super.updateUI(); updateColors() }
                private fun updateColors() {
                    isOpaque = false
                    font = Design.Typography.bodyMedium
                    foreground = Design.Colors.onSurface
                }
            }.apply {
                alignmentX = LEFT_ALIGNMENT
                addActionListener { config.setToolEnabled(tool.name, isSelected) }
            }
            checkboxes[tool.name] = cb
            checkPanel.add(cb)
        }

        row.add(catLabel)
        row.add(createHorizontalStrut(Design.Spacing.SM))
        row.add(checkPanel)
        return row
    }

    /**
     * Lock checkboxes while the extension is running; unlock when stopped.
     * Shows a hint label when locked so the user knows why they cannot edit.
     */
    fun setCheckboxesEnabled(enabled: Boolean) {
        checkboxes.values.forEach { it.isEnabled = enabled }
        hintLabel.isVisible = !enabled
    }
}
