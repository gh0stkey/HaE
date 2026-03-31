package hae.utils;

import java.awt.*;

/**
 * FlowLayout subclass that fully supports wrapping of components.
 * Unlike FlowLayout, preferredLayoutSize accounts for the actual
 * container width so that parent layouts allocate the correct height.
 */
public class WrapLayout extends FlowLayout {

    public WrapLayout() {
        super();
    }

    public WrapLayout(int align) {
        super(align);
    }

    public WrapLayout(int align, int hgap, int vgap) {
        super(align, hgap, vgap);
    }

    @Override
    public Dimension preferredLayoutSize(Container target) {
        return layoutSize(target, true);
    }

    @Override
    public Dimension minimumLayoutSize(Container target) {
        return layoutSize(target, false);
    }

    private Dimension layoutSize(Container target, boolean preferred) {
        synchronized (target.getTreeLock()) {
            Insets insets = target.getInsets();
            int maxWidth = target.getWidth() - insets.left - insets.right - getHgap() * 2;

            if (maxWidth <= 0) {
                // Container not yet sized; fall back to single-line calculation
                return preferred ? super.preferredLayoutSize(target) : super.minimumLayoutSize(target);
            }

            int rowWidth = 0;
            int rowHeight = 0;
            int totalHeight = 0;
            int componentCount = target.getComponentCount();

            for (int i = 0; i < componentCount; i++) {
                Component c = target.getComponent(i);
                if (!c.isVisible()) continue;

                Dimension d = preferred ? c.getPreferredSize() : c.getMinimumSize();

                if (rowWidth + d.width > maxWidth && rowWidth > 0) {
                    totalHeight += rowHeight + getVgap();
                    rowWidth = 0;
                    rowHeight = 0;
                }

                if (rowWidth > 0) {
                    rowWidth += getHgap();
                }
                rowWidth += d.width;
                rowHeight = Math.max(rowHeight, d.height);
            }

            totalHeight += rowHeight;
            totalHeight += insets.top + insets.bottom + getVgap() * 2;

            int width = Math.max(maxWidth, 0) + insets.left + insets.right + getHgap() * 2;
            return new Dimension(width, totalHeight);
        }
    }
}
