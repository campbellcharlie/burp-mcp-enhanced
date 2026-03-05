package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.*
import net.portswigger.mcp.security.findBurpFrame
import java.awt.Component
import java.awt.Cursor
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.event.MouseMotionAdapter
import javax.swing.*
import javax.swing.JOptionPane.ERROR_MESSAGE
import javax.swing.JOptionPane.YES_NO_OPTION
import javax.swing.JOptionPane.YES_OPTION

class RawSocketTargetsPanel(private val config: McpConfig) : JPanel() {

    private var listenerHandle: ListenerHandle? = null
    private var refreshListener: (() -> Unit)? = null

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

    fun cleanup() {
        listenerHandle?.remove()
        listenerHandle = null
        refreshListener = null
    }

    private fun buildPanel() {
        add(Design.createSectionLabel("Raw Socket Allowlist"))
        add(Box.createVerticalStrut(Design.Spacing.MD))

        val desc1 = JLabel("Controls which targets raw socket tools may connect to (TCP/TLS).").apply {
            alignmentX = LEFT_ALIGNMENT
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.onSurfaceVariant
            border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.SM, 0)
        }
        val desc2 = JLabel("Examples: *.web-security-academy.net, *.exploit-server.net, example.com:443").apply {
            alignmentX = LEFT_ALIGNMENT
            font = Design.Typography.labelMedium
            foreground = Design.Colors.onSurfaceVariant
            border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.MD, 0)
        }
        add(desc1)
        add(desc2)

        val listModel = DefaultListModel<String>()
        val targetsList = createTargetsList(listModel)
        updateTargetsList(listModel)

        refreshListener = {
            SwingUtilities.invokeLater { updateTargetsList(listModel) }
        }
        listenerHandle = config.addRawSocketTargetsChangeListener(refreshListener!!)

        val scrollPane = JScrollPane(targetsList).apply {
            val baseHeight = 220
            val baseWidth = 400
            val scaleFactor = Design.Spacing.MD / 16f
            val responsiveHeight = (baseHeight * scaleFactor).toInt().coerceAtLeast(150)
            val responsiveWidth = (baseWidth * scaleFactor).toInt().coerceAtLeast(250)

            maximumSize = Dimension(Int.MAX_VALUE, responsiveHeight)
            preferredSize = Dimension(responsiveWidth, responsiveHeight)
            minimumSize = Dimension((responsiveWidth * 0.625f).toInt(), (responsiveHeight * 0.68f).toInt())
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Design.Colors.listBorder, 1),
                BorderFactory.createEmptyBorder(1, 1, 1, 1)
            )
            background = Design.Colors.listBackground
            viewport.background = Design.Colors.listBackground
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
        }

        val tableContainer = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            border = BorderFactory.createEmptyBorder(0, 0, Design.Spacing.MD, 0)
            add(scrollPane)
        }
        add(tableContainer)

        val buttonsPanel = JPanel(FlowLayout(FlowLayout.LEFT, Design.Spacing.SM, Design.Spacing.SM)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            border = BorderFactory.createEmptyBorder(Design.Spacing.SM, 0, 0, 0)
        }

        val addButton = Design.createFilledButton("Add").apply {
            addActionListener {
                val input = Dialogs.showInputDialog(
                    findBurpFrame(),
                    "Enter target (hostname or hostname:port):\nExamples: *.web-security-academy.net, example.com:443, *.api.com"
                )
                if (!input.isNullOrBlank()) {
                    val trimmed = input.trim()
                    if (TargetValidation.isValidTarget(trimmed)) {
                        config.addRawSocketAllowedTarget(trimmed)
                    } else {
                        Dialogs.showMessageDialog(
                            findBurpFrame(),
                            "Invalid target format. Use hostname, IP address, hostname:port, or wildcard (*.domain)",
                            ERROR_MESSAGE
                        )
                    }
                }
            }
        }

        val removeButton = Design.createOutlinedButton("Remove").apply {
            addActionListener {
                val selectedIndex = targetsList.selectedIndex
                if (selectedIndex >= 0 && selectedIndex < listModel.size) {
                    val value = listModel.getElementAt(selectedIndex)
                    config.removeRawSocketAllowedTarget(value)
                }
            }
        }

        val clearButton = Design.createOutlinedButton("Clear All").apply {
            addActionListener {
                val result = Dialogs.showConfirmDialog(findBurpFrame(), "Remove all raw socket allowlist entries?", YES_NO_OPTION)
                if (result == YES_OPTION) config.clearRawSocketAllowedTargets()
            }
        }

        buttonsPanel.add(addButton)
        buttonsPanel.add(removeButton)
        buttonsPanel.add(clearButton)
        add(buttonsPanel)
    }

    private fun createTargetsList(listModel: DefaultListModel<String>): JList<String> {
        return object : JList<String>(listModel) {
            private var rolloverIndex = -1

            init {
                selectionMode = ListSelectionModel.SINGLE_SELECTION
                visibleRowCount = 5
                font = Design.Typography.bodyMedium
                background = Design.Colors.listBackground
                foreground = Design.Colors.onSurface
                border = BorderFactory.createEmptyBorder(
                    Design.Spacing.SM, Design.Spacing.MD, Design.Spacing.SM, Design.Spacing.MD
                )
                cellRenderer = createCellRenderer()
                addMouseMotionListener(createMouseMotionListener())
                addMouseListener(createMouseListener())
                addKeyListener(createKeyListener(listModel))
                isFocusable = true
            }

            private fun createCellRenderer() = object : DefaultListCellRenderer() {
                override fun getListCellRendererComponent(
                    list: JList<*>, value: Any?, index: Int, isSelected: Boolean, cellHasFocus: Boolean
                ): Component {
                    super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
                    border = BorderFactory.createEmptyBorder(
                        Design.Spacing.SM, Design.Spacing.MD, Design.Spacing.SM, Design.Spacing.MD
                    )

                    val isRollover = index == rolloverIndex && !isSelected
                    when {
                        isSelected -> {
                            background = Design.Colors.listSelectionBackground
                            foreground = Design.Colors.listSelectionForeground
                        }
                        isRollover -> {
                            background = Design.Colors.listHoverBackground
                            foreground = Design.Colors.onSurface
                        }
                        else -> {
                            background = if (index % 2 == 0) Design.Colors.listBackground else Design.Colors.listAlternatingBackground
                            foreground = Design.Colors.onSurface
                        }
                    }
                    return this
                }
            }

            private fun createMouseMotionListener() = object : MouseMotionAdapter() {
                override fun mouseMoved(e: MouseEvent) {
                    try {
                        val index = locationToIndex(e.point)
                        val newIdx = if (index >= 0 && index < model.size && getCellBounds(index, index)?.contains(e.point) == true) {
                            cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                            index
                        } else {
                            cursor = Cursor.getDefaultCursor()
                            -1
                        }
                        if (rolloverIndex != newIdx) {
                            rolloverIndex = newIdx
                            repaint()
                        }
                    } catch (_: Exception) {
                        rolloverIndex = -1
                        cursor = Cursor.getDefaultCursor()
                    }
                }
            }

            private fun createMouseListener() = object : MouseAdapter() {
                override fun mouseExited(e: MouseEvent) {
                    if (rolloverIndex != -1) {
                        rolloverIndex = -1
                        cursor = Cursor.getDefaultCursor()
                        repaint()
                    }
                }
            }

            private fun createKeyListener(listModel: DefaultListModel<String>) = object : KeyAdapter() {
                override fun keyPressed(e: KeyEvent) {
                    when (e.keyCode) {
                        KeyEvent.VK_DELETE, KeyEvent.VK_BACK_SPACE -> {
                            val idx = selectedIndex
                            if (idx >= 0 && idx < model.size) {
                                val value = listModel.getElementAt(idx)
                                config.removeRawSocketAllowedTarget(value)
                                e.consume()
                            }
                        }
                    }
                }
            }
        }
    }

    private fun updateTargetsList(listModel: DefaultListModel<String>) {
        listModel.clear()
        config.getRawSocketAllowedTargetsList().forEach { listModel.addElement(it) }
    }
}

