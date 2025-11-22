package gateway;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * gatewaySdk
 * @author gateway
 *
 */
public  class gatewaySdk {
	/**
	 * rsa algorithm
	 */
	final static String ALGORITHM = "AES/CBC/PKCS5PADDING";

    /**
     * aes algorithm
     */
	final static String HASH_ALGORITHM = "SHA256withRSA";

    /**
     * encrypt auth info
     */
	static String EncryptAuthInfo = "";
	
	/**
	 * user deposit
	 * @param orderId order number - maxlength(40)
	 * @param amount order amount - maxlength(20)
	 * @param currency Empty default: MYR - maxlength(16)
	 * @param payMethod FPX, TNG_MY, ALIPAY_CN, GRABPAY_MY, BOOST_MY - maxlength(16)
	 * @param customerName customer name - maxlength(64)
	 * @param customerEmail customer email - maxlength(64)
	 * @param customerPhone customer phone - maxlength(20)
	 * @return code,message,paymentUrl,transactionId
	 */
    public static HashMap<String, String> deposit(String orderId, Double amount, String currency,
        String payMethod, String customerName, String customerEmail, String customerPhone)
    {
        HashMap<String, String> result = new HashMap<String, String>();
        try
        {
            String token = getToken();
            if (token.isEmpty())return result;
            String requestUrl = "gateway/" + gatewayCfg.VERSION_NO + "/createPayment";
            HashMap<String, String> cnst = generateConstant(requestUrl);
            // If callbackUrl and redirectUrl are empty, take the values ​​of [curl] and [rurl] in the developer center.
            // Remember, the format of json and the order of json attributes must be the same as the SDK specifications.
            // The sorting rules of Json attribute data are arranged from [a-z]
            String bodyJson = "{\"customer\":{\"email\":\""+ customerEmail + "\",\"name\":\""+ customerName + "\",\"phone\":\""+ customerPhone + "\"},\"method\":\""+ payMethod + "\",\"order\":{\"additionalData\":\"\",\"amount\":\""+ amount.toString() + "\",\"currencyType\":\""+ (currency.equals("") ? "MYR" : currency) + "\",\"id\":\""+ orderId + "\",\"title\":\"Payment\"}}";
            //String bodyJson = "{\"callbackUrl\\\":\"https://www.google.com\",\"customer\":{\"email\":\""+ customerEmail + "\",\"name\":\""+ customerName + "\",\"phone\":\""+ customerPhone + "\"},\"method\":\""+ payMethod + "\",\"order\":{\"additionalData\":\"\",\"amount\":\""+ amount.toString() + "\",\"currencyType\":\""+ (currency.equals("") ? "MYR" : currency) + "\",\"id\":\""+ orderId + "\",\"title\":\"Payment\"},\"redirectUrl\":\"https://www.google.com\"}";
            String base64ReqBody = sortedAfterToBased64(bodyJson);
            String signature = createSignature(cnst, base64ReqBody);
            String encryptData = symEncrypt(base64ReqBody);
            String json = "{\"data\":\""+ encryptData + "\"}";
            String[] keys = new String[] { "code", "message", "encryptedData" };
            HashMap<String, String> dict = post(requestUrl, token, signature, json, cnst.get("nonceStr"), cnst.get("timestamp"), keys);
            if (!dict.get("code").isEmpty() && dict.get("code").equals("1") && !dict.get("encryptedData").isEmpty())
            {
                String decryptedData = symDecrypt(dict.get("encryptedData"));
                keys = new String[] { "paymentUrl", "transactionId" };
                dict = findJosnValue(keys, decryptedData);
                if (!dict.get("paymentUrl").isEmpty() && !dict.get("transactionId").isEmpty())
                {
                    result.put("code", "1");
                    result.put("message", "");
                    result.put("paymentUrl", dict.get("paymentUrl"));
                    result.put("transactionId", dict.get("transactionId"));
                    return result;
                }
            }
            result.put("code", "0");
            result.put("message", dict.get("message"));
            return result;
        }
        catch (Exception e)
        {
            result.put("code", "0");
            result.put("message", e.getMessage());
            return result;
        }
    }

    /**
     * user withdraw
     * @param orderId order number - maxlength(40)
     * @param amount order amount - maxlength(20)
     * @param currency Empty default: MYR - maxlength(16)
     * @param bankCode MayBank=MBB,Public Bank=PBB,CIMB Bank=CIMB,Hong Leong Bank=HLB,RHB Bank=RHB,AmBank=AMMB,United Overseas Bank=UOB,Bank Rakyat=BRB,OCBC Bank=OCBC,HSBC Bank=HSBC  - maxlength(16)
     * @param cardholder cardholder - maxlength(64)
     * @param accountNumber account number - maxlength(20)
     * @param refName recipient refName - maxlength(64)
     * @param recipientEmail recipient email - maxlength(64)
     * @param recipientPhone recipient phone - maxlength(20)
     * @return code,message,transactionId
     */
    public static HashMap<String, String> withdraw(String orderId, Double amount, String currency,
        String bankCode, String cardholder, String accountNumber, String refName,String recipientEmail, String recipientPhone)
    {
        HashMap<String, String> result = new HashMap<String, String>();
        try
        {
            String token = getToken();
            if (token.isEmpty())return result;
            String requestUrl = "gateway/" + gatewayCfg.VERSION_NO + "/withdrawRequest";
            HashMap<String, String> cnst = generateConstant(requestUrl);
            // payoutspeed contain "fast", "normal", "slow" ,default is : "fast"
            // Remember, the format of json and the order of json attributes must be the same as the SDK specifications.
            // The sorting rules of Json attribute data are arranged from [a-z]
            String bodyJson = "{\"order\":{\"amount\":\"" + amount.toString() + "\",\"currencyType\":\"" + (currency.equals("") ? "MYR" : currency) + "\",\"id\":\"" + orderId + "\"},\"recipient\":{\"email\":\"" + recipientEmail + "\",\"methodRef\":\"" + refName + "\",\"methodType\":\"" + bankCode + "\",\"methodValue\":\"" + accountNumber + "\",\"name\":\"" + cardholder + "\",\"phone\":\"" + recipientPhone + "\"}}";
            //String bodyJson = "{\"callbackUrl\\\":\"https://www.google.com\",\"order\":{\"amount\":\"" + amount.toString() + "\",\"currencyType\":\"" + (currency.equals("") ? "MYR" : currency) + "\",\"id\":\"" + orderId + "\"},\"payoutspeed\\\":\"normal\",\"recipient\":{\"email\":\"" + recipientEmail + "\",\"methodRef\":\"" + refName + "\",\"methodType\":\"" + bankCode + "\",\"methodValue\":\"" + accountNumber + "\",\"name\":\"" + cardholder + "\",\"phone\":\"" + recipientPhone + "\"}}";
            String base64ReqBody = sortedAfterToBased64(bodyJson);
            String signature = createSignature(cnst, base64ReqBody);
            String encryptData = symEncrypt(base64ReqBody);
            String json = "{\"data\":\"" + encryptData + "\"}";
            String[] keys = new String[] { "code","message", "encryptedData" };
            HashMap<String, String> dict = post(requestUrl, token, signature, json, cnst.get("nonceStr"), cnst.get("timestamp"), keys);
            if (!dict.get("code").isEmpty() && dict.get("code").equals("1") && !dict.get("encryptedData").isEmpty())
            {
                String decryptedData = symDecrypt(dict.get("encryptedData"));
                keys = new String[] {  "transactionId" };
                dict = findJosnValue(keys, decryptedData);
                if (!dict.get("transactionId").isEmpty())
                {
                    result.put("code", "1");
                    result.put("message", "");
                    result.put("transactionId",dict.get("transactionId"));
                    return result;
                }
            }
            result.put("code", "0");
            result.put("message", dict.get("message"));
            return result;
        }
        catch (Exception e)
        {
            result.put("code","0");
            result.put("message",e.getMessage());
            return result;
        }
    }
    
    /**
     * User deposit and withdrawal details
     * @param orderId transaction id
     * @param type 1 deposit,2 withdrawal
     * @return code,message,transactionId,amount,fee
     */
    public static HashMap<String, String> detail(String orderId, int type)
    {
    	HashMap<String, String> result = new HashMap<String, String>();
        try
        {
            String token = getToken();
            if (token.isEmpty())return result;
            String requestUrl = "gateway/" + gatewayCfg.VERSION_NO + "/getTransactionStatusById";
            HashMap<String, String> cnst = generateConstant(requestUrl);
            // Remember, the format of json and the order of json attributes must be the same as the SDK specifications.
            // The sorting rules of Json attribute data are arranged from [a-z]
            // type : 1 deposit,2 withdrawal
            String bodyJson = "{\"transactionId\":\"" + orderId + "\",\"type\":" + type + "}";
            String base64ReqBody = sortedAfterToBased64(bodyJson);
            String signature = createSignature(cnst, base64ReqBody);
            String encryptData = symEncrypt(base64ReqBody);
            String json = "{\"data\":\"" + encryptData + "\"}";
            String[] keys = new String[] { "code", "message", "encryptedData" };
            HashMap<String, String> dict = post(requestUrl, token, signature, json, cnst.get("nonceStr"), cnst.get("timestamp"), keys);
            if (!dict.get("code").isEmpty() && dict.get("code") == "1" && !dict.get("encryptedData").isEmpty())
            {
                String decryptedData = symDecrypt(dict.get("encryptedData"));
                result = new HashMap<String, String>();
                result.put("code", "1");
                result.put("message", decryptedData);
                return result;
            }
            result = new HashMap<String, String>();
            result.put("code", dict.get("code"));
            result.put("message", dict.get("message"));
            return result;
        }
        catch (Exception e)
        {
            result = new HashMap<String, String>();
            result.put("code", "0");
            result.put("message", e.getMessage());
            return result;
        }
    }

    /**
     * get server token
     * @return token
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InterruptedException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    private static String getToken() throws InvalidKeySpecException, NoSuchAlgorithmException,  IOException, InterruptedException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {
        if (EncryptAuthInfo.equals(""))
        {
            String authString = stringToBase64(gatewayCfg.CLIENT_ID + ":" + gatewayCfg.CLIENT_SECRET);
            EncryptAuthInfo = publicEncrypt(authString);
        }
        String json = "{\"data\":\"" + EncryptAuthInfo + "\"}";
        String[] keys = new String[] { "code", "encryptedToken" };
        HashMap<String, String> dict = post("gateway/" + gatewayCfg.VERSION_NO + "/createToken",  "", "", json, "", "", keys);
        String token = "";
        if (!dict.get("code").isEmpty() && !dict.get("encryptedToken").isEmpty() && dict.get("code").equals("1"))
        {
            token = symDecrypt(dict.get("encryptedToken"));
        }
        return token;
    }

    /**
     * A simple http request method
     * @param url
     * @param token
     * @param signature
     * @param json
     * @param nonceStr
     * @param timestamp
     * @param keys
     * @return
     * @throws IOException
     * @throws InterruptedException
     */
    private static HashMap<String, String> post(String url,  String token, String signature,String json, String nonceStr, String timestamp, String[] keys) throws IOException, InterruptedException
    {
        HttpClient httpClient =  HttpClient.newHttpClient();
        if (gatewayCfg.BASE_URL.endsWith("/")) {
        	url = gatewayCfg.BASE_URL+url;
        }else {
        	url = gatewayCfg.BASE_URL+"/"+url;
        }
        URI uri = URI.create(url);
        Builder httpBuilder = HttpRequest.newBuilder(uri)
        		.version(HttpClient.Version.HTTP_1_1)
        		.POST(BodyPublishers.ofString(json));
        httpBuilder.setHeader("Content-Type","application/json");
        if (!token.isEmpty() && !signature.isEmpty() && !nonceStr.isEmpty() && !timestamp.isEmpty())
        {
        	httpBuilder.setHeader("Authorization", token);
        	httpBuilder.setHeader("X-Nonce-Str", nonceStr);
        	httpBuilder.setHeader("X-Signature", signature);
        	httpBuilder.setHeader("X-Timestamp", timestamp);
        }
        HttpRequest httpRequest = httpBuilder.build();
        HttpResponse<String> response =httpClient.send(httpRequest, BodyHandlers.ofString());
        String result = response.body();
        HashMap<String, String> dict = findJosnValue(keys, result);
        return dict;
    }
    
    /**
     * find json value
     * @param keys
     * @param josn
     * @return
     */
    private static HashMap<String, String> findJosnValue(String[] keys, String josn)
    {
    	HashMap<String, String> dict = new HashMap<String, String>();
    	for(int i=0;i<keys.length;i++) 
    	{
			String value = "";
	        String pattern = "\"" + keys[i] + "\":((\"(.*?)\")|(\\d*))";
	        Matcher matcher = Pattern.compile(pattern).matcher(josn);
	        if (matcher.find()) 
	        {
	        	value = matcher.group().replace("\""+keys[i]+"\":", "");
	        	if (value.startsWith("\"")){
	        		value=value.substring(1,value.length());
	        	}
	        	if(value.endsWith("\"")) {
	        		value=value.substring(0,value.length()-1);
	        	}
	        }
	        dict.put(keys[i], value);
    	}
        return dict;
    }

    /**
     * create a signature
     * @param cnst
     * @param base64ReqBody
     * @return signature info
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     */
    private static String createSignature(HashMap<String, String> cnst, String base64ReqBody) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, IOException
    {
        String dataString = String.format("data=%s&method=%s&nonceStr=%s&requestUrl=%s&signType=%s&timestamp=%s",
           base64ReqBody, cnst.get("method"), cnst.get("nonceStr"), cnst.get("requestUrl"), cnst.get("signType"), cnst.get("timestamp"));
        String signature = sign(dataString);
        return String.format("%s %s", cnst.get("signType"), signature);
    }

    /**
     * generate constant
     * @param requestUrl
     * @return constant
     * @throws UnsupportedEncodingException
     */
    private static HashMap<String,String> generateConstant(String requestUrl) throws UnsupportedEncodingException
    {
        HashMap<String,String> constant = new HashMap<String,String>();
        constant.put("method","post");
        constant.put("nonceStr",randomNonceStr());
        constant.put("requestUrl", requestUrl);
        constant.put("signType", "sha256");
        constant.put("timestamp",String.valueOf(new Date().getTime()));
        return constant;
    }

    /**
     * random nonceStr
     * @return nonceStr
     * @throws UnsupportedEncodingException
     */
    private static String randomNonceStr() throws UnsupportedEncodingException
    {
        StringBuilder sb = new StringBuilder();
        char[] chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        String[] stringChars = new String[8];
        Random random = new Random();
      
        for (int i = 0; i < stringChars.length; i++)
        {
            sb.append(chars[random.nextInt(chars.length)]);
        }
        byte[] bytes = stringToBytes(sb.toString());
        String hex = bytesToHex(bytes);
        return hex;
    }

    /**
     * Encrypt data based on the server's public key
     * @param data data to be encrypted
     * @return encrypted data
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    private static String publicEncrypt(String data) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException 
    {
    	byte[] bytesToEncrypt = stringToBytes(data);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    	cipher.init(Cipher.ENCRYPT_MODE, getServerPublicKey());
    	byte[] dataByte = cipher.doFinal(bytesToEncrypt);
    	String encryptText = bytesToHex(dataByte);
        return encryptText;
    }

    /**
     * Decrypt data according to the interface private key
     * @param encryptData data to be decrypted
     * @returnreturn decrypted data
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @SuppressWarnings("unused")
	private static String privateDecrypt(String encryptData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException 
    {
        byte[] bytesToDecrypt = hexToBytes(encryptData);
    	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
        byte[] decrypted = cipher.doFinal(bytesToDecrypt);
        String decryptedText = bytesToString(decrypted);
        return decryptedText;
    }

    /**
     * interface data encryption method
     * @param message data to be encrypted
     * @returnPayment The encrypted data is returned in hexadecimal
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException 
     */
    private static String symEncrypt(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {
    	Cipher cipher = Cipher.getInstance(ALGORITHM);
    	byte[] key = stringToBytes(gatewayCfg.CLIENT_SYMMETRIC_KEY);
        byte[] iv = generateIv(gatewayCfg.CLIENT_SYMMETRIC_KEY);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec,ivSpec);
        byte[] plainTextData = stringToBytes(message);
        byte[] cipherText = cipher.doFinal(plainTextData);
        String encrypted = bytesToHex(cipherText);
        return encrypted;
    }

    /**
     * Payment interface data decryption method
     * @param encryptedMessage symmetricKey Encrypted key (from Key property field in dev settings)
     * @return Return the data content of utf-8 after decryption
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException 
     */
    public static String symDecrypt(String encryptedMessage) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {
    	Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] key = stringToBytes(gatewayCfg.CLIENT_SYMMETRIC_KEY);
        byte[] iv = generateIv(gatewayCfg.CLIENT_SYMMETRIC_KEY);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec,ivSpec);
        byte[] plainTextData = hexToBytes(encryptedMessage);
        byte[] cipherText = cipher.doFinal(plainTextData);
        String decryptedText = bytesToString(cipherText);
        return decryptedText;
    }

    /**
     * private key signature
     * @param data
     * @return signature info base64
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private static String sign(String data) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException
    {
    	PrivateKey privatekey = getPrivateKey();
        Signature signer = Signature.getInstance(HASH_ALGORITHM);
        signer.initSign(privatekey);
        byte[] dataByte = stringToBytes(data);
        signer.update(dataByte, 0, dataByte.length);
        byte[] sign = signer.sign();
        String base64 = bytesToBase64(sign);
        return base64;
    }

    /**
     * Public key verification signature information
     * @param data
     * @param signature
     * @return verify result true or false
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    @SuppressWarnings("unused")
	private static Boolean verify(String data, String signature) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException 
    {
    	 PublicKey publickey = getServerPublicKey();
         Signature signer = Signature.getInstance(HASH_ALGORITHM);
         signer.initVerify(publickey);
         byte[] dataByte = stringToBytes(data);
         signer.update(dataByte, 0, dataByte.length);
         byte[] signatureByte = base64ToBytes(signature);
         return signer.verify(signatureByte);
    }
    
    /**
     * get server public key
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    private static PublicKey getServerPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException  {
    	PublicKey publicKey = null;
    	String key = gatewayCfg.SERVER_PUB_KEY.replace("-----BEGIN PUBLIC KEY-----", "");
    	key = key.replace("-----END PUBLIC KEY-----", "");
    	key = key.replaceAll("\\n", "");
    	key = key.replaceAll(" ", "");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }
    
    /**
     * get private key
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    private static PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    	PrivateKey privateKey = null;
    	String key = gatewayCfg.PRIVATE_KEY.replace("-----BEGIN RSA PRIVATE KEY-----", "");
    	key = key.replace("-----END RSA PRIVATE KEY-----", "");
    	key = key.replaceAll("\\n", "");
    	key = key.replaceAll(" ", "");
    	// begin pkcs1 to pkcs8
    	byte[] oldder = Base64.getDecoder().decode(key.getBytes());
    	byte[] prefix = {0x30,(byte)0x82,0,0, 2,1,0,0x30,0x0d, 6,9,0x2a,(byte)0x86,0x48,(byte)0x86,(byte)0xf7,0x0d,1,1,1, 5,0, 4,(byte)0x82,0,0 }; 
        byte[] newder = new byte [prefix.length + oldder.length];
        System.arraycopy (prefix,0, newder,0, prefix.length);
        System.arraycopy (oldder,0, newder,prefix.length, oldder.length);
        int len = oldder.length, loc = prefix.length-2; 
        newder[loc] = (byte)(len>>8); newder[loc+1] = (byte)len;
        len = newder.length-4; loc = 2;
        newder[loc] = (byte)(len>>8); newder[loc+1] = (byte)len;
        // end pkcs1 to pkcs8
    	PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec (newder);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }
    
    /**
     * Return base64 after sorting arguments
     * @param param
     * @return json base64
     * @throws UnsupportedEncodingException
     */
    private static String sortedAfterToBased64(String json) throws UnsupportedEncodingException
    {
        byte[] jsonBytes = stringToBytes(json);
        String jsonBase64 = bytesToBase64(jsonBytes);
        return jsonBase64;
    }

    /**
     * Generate an IV based on the data encryption key
     * @param symmetricKey
     * @return iv bytes
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException 
     */
    private static byte[] generateIv(String symmetricKey) throws  NoSuchAlgorithmException, UnsupportedEncodingException
    {
        byte[] data = stringToBytes(symmetricKey);
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] messageDigest = md.digest(data);
        return messageDigest;
    }

    /**
     * UTF8 String to bytes
     * @param data
     * @return bytes
     * @throws UnsupportedEncodingException
     */
    private static byte[] stringToBytes(String data) throws UnsupportedEncodingException
    {
        return new String(data).getBytes("UTF-8");
    }

    /**
     * String to base64
     * @param data
     * @return string
     * @throws UnsupportedEncodingException
     */
    private static String stringToBase64(String data) throws UnsupportedEncodingException
    {
        byte[] dataBytes = stringToBytes(data);
        return bytesToBase64(dataBytes);
    }

    /**
     * String to bytes
     * @param bytes
     * @return string
     */
    private static String bytesToString(byte[] bytes)
    {
        return new String(bytes,StandardCharsets.UTF_8);
    }

	/**
	 * Bytes to hex
	 * @param bytes
	 * @return string
	 */
	private static String bytesToHex(byte[] bytes)
	{
		char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
	    for (int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	/**
	 * Hex to bytes
	 * @param hex
	 * @return bytes
	 */
	private static byte[] hexToBytes(String hex)
	{
		int len = hex.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
	                             + Character.digit(hex.charAt(i+1), 16));
	    }
	    return data;
	}

    /**
     * Bytes to base64
     * @param bytes
     * @return string
     */
    private static String bytesToBase64(byte[] bytes)
    {
    	byte[] decodedString = Base64.getEncoder().encode(bytes);
        return new String(decodedString);
    }

    /**
     * Base64 to bytes
     * @param base64
     * @return bytes
     */
    private static byte[] base64ToBytes(String base64)
    {
    	byte[] bytes = Base64.getDecoder().decode(base64);
        return bytes;
    }
}