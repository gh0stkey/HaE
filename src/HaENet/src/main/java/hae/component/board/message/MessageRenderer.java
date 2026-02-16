package hae.component.board.message;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

public class MessageRenderer extends DefaultTableCellRenderer {

    private final LinkedList<MessageEntry> log;
    private final Map<String, Color> colorMap = new HashMap<>();
    private final JTable table; // 保存对表格的引用

    public MessageRenderer(LinkedList<MessageEntry> log, JTable table) {
        this.log = log;
        // 与BurpSuite的颜色保持一致
        this.colorMap.put("red", new Color(0xFF, 0x64, 0x64));
        this.colorMap.put("orange", new Color(0xFF, 0xC8, 0x64));
        this.colorMap.put("yellow", new Color(0xFF, 0xFF, 0x64));
        this.colorMap.put("green", new Color(0x64, 0xFF, 0x64));
        this.colorMap.put("cyan", new Color(0x64, 0xFF, 0xFF));
        this.colorMap.put("blue", new Color(0x64, 0x64, 0xFF));
        this.colorMap.put("pink", new Color(0xFF, 0xC8, 0xC8));
        this.colorMap.put("magenta", new Color(0xFF, 0x64, 0xFF));
        this.colorMap.put("gray", new Color(0xB4, 0xB4, 0xB4));
        this.colorMap.put("none", new Color(0, 0, 0, 0));
        this.table = table;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int column) {
        Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // 添加边界检查以防止IndexOutOfBoundsException
        int modelRow = table.convertRowIndexToModel(row);
        MessageEntry messageEntry;
        synchronized (log) {
            if (modelRow < 0 || modelRow >= log.size()) {
                // 如果索引无效，返回默认渲染组件（使用默认背景色）
                component.setBackground(Color.WHITE);
                component.setForeground(Color.BLACK);
                return component;
            }
            messageEntry = log.get(modelRow);
        }

        // 设置颜色
        String colorByLog = messageEntry.getColor();
        Color color = colorMap.get(colorByLog);

        // 如果颜色映射中没有找到对应颜色，使用默认白色
        if (color == null) {
            color = Color.WHITE;
        }

        if (isSelected) {
            component.setBackground(UIManager.getColor("Table.selectionBackground"));
        } else {
            component.setBackground(color);
        }

        component.setForeground(Color.BLACK);

        return component;
    }

    @Override
    public void firePropertyChange(String propertyName, Object oldValue, Object newValue) {
        super.firePropertyChange(propertyName, oldValue, newValue);
        // 监听表格排序的属性变化
        if ("tableCellRenderer".equals(propertyName)) {
            // 更新每一行数据的颜色
            for (int i = 0; i < table.getRowCount(); i++) {
                table.repaint(table.getCellRect(i, 0, true));
            }
        }
    }
}
