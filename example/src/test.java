import java.util.HashMap;

import gateway.gatewaySdk;
import gateway.gatewayCfg;;

public class test {
	/**
	 * Here is an example of a gateway sdk
	 * @param args
	 */
	public static void main(String[] args) {
		
		// docs : https://doc.gateway.org/docs/quickstart/setup
	    // payment-method: https://doc.gateway.org/docs/appendix/payment-method
	    // dictionary : https://doc.gateway.org/docs/appendix/dictionary
		
		// initialize this configuration
		// verNo gateway Api Version Number, default: v1
		// apiUrl gateway Api Url
		// appId in developer settings : App Id
		// key in developer settings : Key
		// secret in developer settings : secret
		// serverPubKey in developer settings : Server Public Key
		// privateKey in developer settings : Private Key
		gatewayCfg.init(verNo, apiUrl, appId, key, secret, serverPubKey, privateKey);
		
		// Here is an example of a deposit 
		// return deposit result: code=1,message=,transactionId=12817291,paymentUrl=https://www.xxxx...
		HashMap<String,String> depositResult = gatewaySdk.deposit("10001",1.06, "MYR", "TNG_MY", "gateway Test", "gateway@hotmail.com", "0123456789");
		System.out.println(depositResult);
		
		// Here is an example of a ithdraw
		// return withdraw result: code=1,message=,transactionId=12817291
		HashMap<String,String> withdrawResult = gatewaySdk.withdraw("10012", 1.06, "MYR", "CIMB", "gateway Test", "234719327401231","", "gateway@hotmail.com", "0123456789");
		System.out.println(withdrawResult);
		
		// Here is an example of a detail
		// return detail result:code=1,message=,transactionId=,amount=,fee=
		HashMap<String, String> detailResult = gatewaySdk.detail("10854", 1);
		System.out.println(detailResult);
		
		// Decrypt the encrypted information in the callback
		String jsonstr = gatewaySdk.symDecrypt("encryptedData .........");
		System.out.println(jsonstr);
	}
}