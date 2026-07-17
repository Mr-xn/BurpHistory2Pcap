import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * BurpHistory2Pcap 扩展入口。
 *
 * 日志策略：所有运行信息写入 Burp 的 Extensions / Output 面板，所有异常写入
 * Extensions / Errors 面板 (通过 Montoya {@link Logging})。导出工作线程额外
 * 安装 UncaughtExceptionHandler 作为最后防线，确保任何未捕获的 Throwable
 * (例如 {@code Error} 子类) 都会出现在 Errors 面板而不是静默杀死线程。
 */
public class BurpHistory2Pcap implements BurpExtension, ContextMenuItemsProvider {

    private static final String EXTENSION_NAME = "BurpHistory2Pcap";

    private Frame burpFrame;
    private Logging logging;

    @Override
    public void initialize(MontoyaApi api) {
        this.logging = api.logging();
        this.burpFrame = api.userInterface().swingUtils().suiteFrame();
        api.extension().setName(EXTENSION_NAME);
        api.userInterface().registerContextMenuItemsProvider(this);

        // 记录加载成功及运行环境, 便于排查环境相关的问题。
        logging.logToOutput(EXTENSION_NAME + " loaded.");
        logging.logToOutput("  java.version   = " + System.getProperty("java.version"));
        logging.logToOutput("  java.vendor    = " + System.getProperty("java.vendor"));
        logging.logToOutput("  os.name        = " + System.getProperty("os.name") + " " + System.getProperty("os.version"));
        logging.logToOutput("  pcap writer    = pure Java (no native dependency)");
        logging.logToOutput("Context menu registered. Right-click HTTP history entries to export.");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();

        if (selected == null || selected.isEmpty() || event.toolType() != ToolType.PROXY) {
            return List.of();
        }

        JMenuItem exportItem = new JMenuItem("Export selected HTTP message(s) as PCAP");
        exportItem.addActionListener(e -> handleExport(selected));

        List<Component> menu = new ArrayList<>();
        menu.add(exportItem);
        return menu;
    }

    private WriteOptions renderOptions() {
        JPanel panel = new JPanel(new BorderLayout());

        JLabel fileLabel = new JLabel("Filepath: ");
        JTextField fileField = new JTextField(20);
        JButton browse = new JButton("Browse...");
        browse.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showSaveDialog(panel) == JFileChooser.APPROVE_OPTION) {
                fileField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });

        JPanel filePanel = new JPanel();
        filePanel.setLayout(new BoxLayout(filePanel, BoxLayout.X_AXIS));
        filePanel.add(fileLabel);
        filePanel.add(fileField);
        filePanel.add(browse);

        JCheckBox usePort80 = new JCheckBox("Use port 80 on all packets for better HTTP decode (instead of actual packet port)");
        usePort80.setSelected(true);
        JCheckBox useRealIPs = new JCheckBox("Use real server IP addresses");
        useRealIPs.setSelected(true);

        JPanel checkboxPanel = new JPanel();
        checkboxPanel.setLayout(new BoxLayout(checkboxPanel, BoxLayout.Y_AXIS));
        checkboxPanel.add(usePort80);
        checkboxPanel.add(useRealIPs);

        panel.add(filePanel, BorderLayout.CENTER);
        panel.add(checkboxPanel, BorderLayout.SOUTH);

        int result = JOptionPane.showConfirmDialog(
                burpFrame,
                panel,
                "Save PCAP",
                JOptionPane.OK_CANCEL_OPTION
        );
        if (result != JOptionPane.OK_OPTION) {
            return null;
        }

        return new WriteOptions(fileField.getText(), usePort80.isSelected(), useRealIPs.isSelected());
    }

    private void handleExport(List<HttpRequestResponse> selected) {
        WriteOptions writeOptions = renderOptions();
        if (writeOptions == null) {
            // 用户取消, 不算错误, 不记录。
            return;
        }

        Thread t = new Thread(() -> exportOnWorkerThread(selected, writeOptions), EXTENSION_NAME + "-export");
        // 最后防线: 任何漏出 exportOnWorkerThread 的 Throwable 都会进 Errors 面板,
        // 绝不会再出现"线程静默死亡、面板全空"的情况。
        t.setUncaughtExceptionHandler((thread, throwable) -> {
            logging.logToError("Uncaught exception in export thread " + thread.getName(), throwable);
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                    burpFrame,
                    "Export failed: " + throwable,
                    "Error",
                    JOptionPane.ERROR_MESSAGE
            ));
        });
        t.start();
    }

    private void exportOnWorkerThread(List<HttpRequestResponse> selected, WriteOptions writeOptions) {
        String filename = writeOptions.filepath();
        if (!filename.endsWith(".pcap")) filename += ".pcap";
        final String finalFilename = filename;

        logging.logToOutput("Export started: " + selected.size() + " message(s) -> " + finalFilename
                + " (forcePort80=" + writeOptions.forcePort80() + ", useRealIPs=" + writeOptions.resolveHostnames() + ")");
        for (int i = 0; i < selected.size(); i++) {
            HttpRequestResponse entry = selected.get(i);
            String host = safeHost(entry);
            int status = safeStatusCode(entry);
            logging.logToOutput("  [" + (i + 1) + "/" + selected.size() + "] host=" + host + " status=" + status);
        }

        try (BurpPcapWriter writer = new BurpPcapWriter(
                finalFilename, writeOptions.forcePort80(), writeOptions.resolveHostnames())) {
            writer.writeEntries(selected);
            int packets = writer.totalPacketsWritten();
            logging.logToOutput("Export complete: " + packets + " packet(s) written to " + finalFilename);
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                    burpFrame,
                    "PCAP saved: " + finalFilename,
                    "Export complete",
                    JOptionPane.INFORMATION_MESSAGE
            ));
        } catch (Throwable ex) {
            // 捕获 Throwable (而非 Exception/UnsatisfiedLinkError), 这样 Error 子类
            // (例如 ExceptionInInitializerError、IllegalAccessError) 也会被记录并提示,
            // 不再静默失败。
            logging.logToError("Export failed for " + finalFilename, ex);
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                    burpFrame,
                    "Export failed: " + ex,
                    "Error",
                    JOptionPane.ERROR_MESSAGE
            ));
        }
    }

    private static String safeHost(HttpRequestResponse entry) {
        try {
            return entry.request().httpService().host();
        } catch (Exception ignored) {
            return "<unknown>";
        }
    }

    private static int safeStatusCode(HttpRequestResponse entry) {
        // HttpRequestResponse.statusCode() 在新 API 里被标记为待移除, 改用 response().statusCode()
        // (没响应时返回 -1)。
        try {
            if (entry.hasResponse() && entry.response() != null) {
                return entry.response().statusCode();
            }
        } catch (Exception ignored) {
        }
        return -1;
    }

    private record WriteOptions(String filepath, boolean forcePort80, boolean resolveHostnames) {}
}
