package burp.ui.board;

import java.awt.Color;
import java.awt.Component;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

public class CustomTableCellRenderer extends DefaultTableCellRenderer {

    private List<LogEntry> log;
    private Map<String, Color> colorMap = new HashMap<>();
    private JTable table; // 保存对表格的引用

    public CustomTableCellRenderer(List<LogEntry> log, JTable table) {
        this.log = log;
        this.colorMap.put("red", Color.RED);
        this.colorMap.put("orange", Color.ORANGE);
        this.colorMap.put("yellow", Color.YELLOW);
        this.colorMap.put("green", Color.GREEN);
        this.colorMap.put("cyan", Color.CYAN);
        this.colorMap.put("blue", Color.BLUE);
        this.colorMap.put("pink", Color.PINK);
        this.colorMap.put("magenta", Color.MAGENTA);
        this.colorMap.put("gray", Color.GRAY);
        this.table = table;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
            boolean hasFocus, int row, int column) {
        Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        LogEntry logEntry = log.get(table.convertRowIndexToModel(row)); // 使用convertRowIndexToModel方法转换行索引

        // 设置颜色
        String colorByLog = logEntry.getColor();
        Color color = colorMap.get(colorByLog);

        if (isSelected) {
            // 如果行被选中，设置阴影颜色
            component.setBackground(new Color(173, 216, 230)); // Light Blue
        } else {
            // 否则使用原始颜色
            component.setBackground(color);
        }

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
