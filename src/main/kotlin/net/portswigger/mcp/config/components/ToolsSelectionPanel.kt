package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.ToolDef
import net.portswigger.mcp.config.ToolDefinitions
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
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

    private val selectAllButton = Design.createFilledButton("Select All").apply {
        addActionListener { applyToAll(true) }
    }

    private val deselectAllButton = Design.createOutlinedButton("Deselect All").apply {
        addActionListener { applyToAll(false) }
    }

    init {
        layout = BorderLayout()
        updateColors()
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
        // Fixed header — never scrolls
        val header = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT

            add(Design.createSectionLabel("Exposed Tools"))
            add(createVerticalStrut(Design.Spacing.SM))
            add(hintLabel)
            add(createVerticalStrut(Design.Spacing.SM))

            val btnRow = JPanel(FlowLayout(FlowLayout.LEFT, Design.Spacing.SM, 0)).apply {
                isOpaque = false
                alignmentX = LEFT_ALIGNMENT
                add(selectAllButton)
                add(deselectAllButton)
            }
            add(btnRow)
            add(createVerticalStrut(Design.Spacing.MD))
        }

        // Scrollable checkbox area
        val checkboxPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
        }

        val orderedCategories = ToolDefinitions.categoryOrder.filter { it in ToolDefinitions.byCategory }
        orderedCategories.forEachIndexed { idx, category ->
            val tools = ToolDefinitions.byCategory[category] ?: return@forEachIndexed
            checkboxPanel.add(createCategoryGroup(category, tools))
            if (idx < orderedCategories.lastIndex) {
                checkboxPanel.add(createVerticalStrut(Design.Spacing.SM))
            }
        }

        val scroll = JScrollPane(checkboxPanel).apply {
            border = null
            isOpaque = false
            viewport.isOpaque = false
            viewport.background = Design.Colors.surface
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            verticalScrollBar.unitIncrement = 16
        }

        add(header, BorderLayout.NORTH)
        add(scroll, BorderLayout.CENTER)
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

    private fun applyToAll(enabled: Boolean) {
        checkboxes.forEach { (toolName, cb) ->
            if (cb.isEnabled) {
                cb.isSelected = enabled
                config.setToolEnabled(toolName, enabled)
            }
        }
    }

    fun setCheckboxesEnabled(enabled: Boolean) {
        checkboxes.values.forEach { it.isEnabled = enabled }
        selectAllButton.isEnabled = enabled
        deselectAllButton.isEnabled = enabled
        hintLabel.isVisible = !enabled
    }
}
