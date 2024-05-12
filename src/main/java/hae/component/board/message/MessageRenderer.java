package hae.component.board.message;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MessageRenderer extends DefaultTableCellRenderer {

    private final List<MessageEntry> log;
    private final Map<String, Color> colorMap = new HashMap<>();
    private final JTable table; // 保存对表格的引用

    public MessageRenderer(List<MessageEntry> log, JTable table) {
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
        this.table = table;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int column) {
        Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        MessageEntry messageEntry = log.get(table.convertRowIndexToModel(row)); // 使用convertRowIndexToModel方法转换行索引

        // 设置颜色
        String colorByLog = messageEntry.getColor();
        Color color = colorMap.get(colorByLog);

        if (isSelected) {
            // 通过更改RGB颜色来达成阴影效果
            component.setBackground(new Color(color.getRed() - 0x20, color.getGreen() - 0x20, color.getBlue() - 0x20));
        } else {
            // 否则使用原始颜色
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
