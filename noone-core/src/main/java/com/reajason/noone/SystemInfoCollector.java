package com.reajason.noone;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.*;

/**
 * 系统信息收集器
 * 用于获取目标机器的基础信息
 */
public class SystemInfoCollector {

    public static Map<String, Object> run(Map<String, Object> args) {
        Map<String, Object> systemInfo = new HashMap<>();

        try {
            // 基本信息
            systemInfo.put("osName", System.getProperty("os.name"));
            systemInfo.put("osVersion", System.getProperty("os.version"));
            systemInfo.put("osArch", System.getProperty("os.arch"));
            systemInfo.put("javaVersion", System.getProperty("java.version"));
            systemInfo.put("javaVendor", System.getProperty("java.vendor"));
            systemInfo.put("userName", System.getProperty("user.name"));
            systemInfo.put("userHome", System.getProperty("user.home"));
            systemInfo.put("userDir", System.getProperty("user.dir"));

            // 网络信息
            systemInfo.put("hostname", getHostname());
            systemInfo.put("ipAddresses", getIpAddresses());
            systemInfo.put("macAddresses", getMacAddresses());

            // JVM信息
            systemInfo.put("jvmInfo", getJvmInfo());

            // 环境变量
            systemInfo.put("environment", getEnvironmentVariables());

            // 系统属性
            systemInfo.put("systemProperties", getSystemProperties());

            // 时间信息
            systemInfo.put("currentTime", System.currentTimeMillis());
            systemInfo.put("timezone", TimeZone.getDefault().getID());

            // 内存信息
            systemInfo.put("memoryInfo", getMemoryInfo());

            // 处理器信息
            systemInfo.put("processorInfo", getProcessorInfo());

            // 当前堆栈信息
            systemInfo.put("curStackTrace", getCurrentThreadStack());

            // 线程 dump
            systemInfo.put("threadDump", getAllThreadsInfo());

        } catch (Exception e) {
            systemInfo.put("error", "Failed to collect system info: " + e.getMessage());
        }

        return systemInfo;
    }

    /**
     * 获取主机名
     */
    private static String getHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * 获取IP地址列表
     */
    private static List<String> getIpAddresses() {
        List<String> ipAddresses = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();
                if (networkInterface.isUp() && !networkInterface.isLoopback()) {
                    Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        InetAddress address = addresses.nextElement();
                        if (!address.isLoopbackAddress()) {
                            ipAddresses.add(address.getHostAddress());
                        }
                    }
                }
            }
        } catch (Exception e) {
            // 忽略异常
        }
        return ipAddresses;
    }

    /**
     * 获取MAC地址列表
     */
    private static List<String> getMacAddresses() {
        List<String> macAddresses = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();
                if (networkInterface.isUp() && !networkInterface.isLoopback()) {
                    byte[] mac = networkInterface.getHardwareAddress();
                    if (mac != null) {
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < mac.length; i++) {
                            sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                        }
                        macAddresses.add(sb.toString());
                    }
                }
            }
        } catch (Exception e) {
            // 忽略异常
        }
        return macAddresses;
    }

    /**
     * 获取JVM信息
     */
    private static Map<String, Object> getJvmInfo() {
        Map<String, Object> jvmInfo = new HashMap<>();
        try {
            RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
            jvmInfo.put("startTime", runtimeMXBean.getStartTime());
            jvmInfo.put("uptime", runtimeMXBean.getUptime());
            jvmInfo.put("inputArguments", runtimeMXBean.getInputArguments());
            jvmInfo.put("classPath", runtimeMXBean.getClassPath());
            jvmInfo.put("libraryPath", runtimeMXBean.getLibraryPath());
            jvmInfo.put("bootClassPath", runtimeMXBean.getBootClassPath());
            jvmInfo.put("systemProperties", runtimeMXBean.getSystemProperties());
        } catch (Exception e) {
            jvmInfo.put("error", "Failed to get JVM info: " + e.getMessage());
        }
        return jvmInfo;
    }

    /**
     * 获取环境变量
     */
    private static Map<String, String> getEnvironmentVariables() {
        Map<String, String> env = new HashMap<>();
        try {
            ProcessBuilder pb = new ProcessBuilder();
            Map<String, String> environment = pb.environment();
            env.putAll(environment);
        } catch (Exception e) {
            // 如果ProcessBuilder不可用，尝试System.getenv()
            try {
                Map<String, String> environment = System.getenv();
                env.putAll(environment);
            } catch (Exception ex) {
                env.put("error", "Failed to get environment variables: " + ex.getMessage());
            }
        }
        return env;
    }

    /**
     * 获取系统属性
     */
    private static Map<String, String> getSystemProperties() {
        Map<String, String> properties = new HashMap<>();
        try {
            Properties sysProps = System.getProperties();
            for (String key : sysProps.stringPropertyNames()) {
                properties.put(key, sysProps.getProperty(key));
            }
        } catch (Exception e) {
            properties.put("error", "Failed to get system properties: " + e.getMessage());
        }
        return properties;
    }

    /**
     * 获取内存信息
     */
    private static Map<String, Object> getMemoryInfo() {
        Map<String, Object> memoryInfo = new HashMap<>();
        try {
            Runtime runtime = Runtime.getRuntime();
            memoryInfo.put("totalMemory", runtime.totalMemory());
            memoryInfo.put("freeMemory", runtime.freeMemory());
            memoryInfo.put("maxMemory", runtime.maxMemory());
            memoryInfo.put("usedMemory", runtime.totalMemory() - runtime.freeMemory());
        } catch (Exception e) {
            memoryInfo.put("error", "Failed to get memory info: " + e.getMessage());
        }
        return memoryInfo;
    }

    /**
     * 获取处理器信息
     */
    private static Map<String, Object> getProcessorInfo() {
        Map<String, Object> processorInfo = new HashMap<>();
        try {
            processorInfo.put("availableProcessors", Runtime.getRuntime().availableProcessors());
            processorInfo.put("processorArchitecture", System.getProperty("os.arch"));
            processorInfo.put("processorEndianness", System.getProperty("sun.cpu.endian"));
        } catch (Exception e) {
            processorInfo.put("error", "Failed to get processor info: " + e.getMessage());
        }
        return processorInfo;
    }

    /**
     * 获取当前线程堆栈信息
     */
    public static List<String> getCurrentThreadStack() {
        List<String> stackTrace = new ArrayList<>();
        try {
            Thread currentThread = Thread.currentThread();
            StackTraceElement[] elements = currentThread.getStackTrace();
            for (StackTraceElement element : elements) {
                stackTrace.add(element.toString());
            }
        } catch (Exception e) {
            stackTrace.add("Failed to get stack trace: " + e.getMessage());
        }
        return stackTrace;
    }

    /**
     * 获取所有线程信息
     */
    public static List<Map<String, Object>> getAllThreadsInfo() {
        List<Map<String, Object>> threadsInfo = new ArrayList<>();
        try {
            Thread[] threads = new Thread[Thread.activeCount()];
            Thread.enumerate(threads);

            for (Thread thread : threads) {
                if (thread != null) {
                    Map<String, Object> threadInfo = new HashMap<>();
                    threadInfo.put("id", thread.getId());
                    threadInfo.put("name", thread.getName());
                    threadInfo.put("priority", thread.getPriority());
                    threadInfo.put("state", thread.getState().toString());
                    threadInfo.put("daemon", thread.isDaemon());
                    threadInfo.put("alive", thread.isAlive());
                    threadsInfo.add(threadInfo);
                }
            }
        } catch (Exception e) {
            Map<String, Object> errorInfo = new HashMap<>();
            errorInfo.put("error", "Failed to get threads info: " + e.getMessage());
            threadsInfo.add(errorInfo);
        }
        return threadsInfo;
    }
}
