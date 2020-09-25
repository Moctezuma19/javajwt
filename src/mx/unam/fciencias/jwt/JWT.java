/**
* Implemetacion sencilla de JSON Web Token (JWT)
* @author Jorge Erick Rivera Lopez
* @version 1.0
* @since 24 de septiembre de 2020
*/
package mx.unam.fciencias.jwt;

import java.util.Base64;
import java.util.Base64.*;
import java.sql.Timestamp;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.json.*;

public class JWT{

	private String cabecera;
	private String carga;
	private String usuario;
	private String clave;
	private long iat;
	private String token;
	//private final float extra = 900000; //15 minutos

	public JWT(){
		this.usuario = null;
		this.clave = null;
	}
	/**
	* Constructor que se inicializa con un nombre de usuario y una clave.
	* @param usuario Cadena que identifica a un usuario.
	* @param clave Caedna que identifica a una clave que posiblemente haya sido preprocesada.
	*/
	public JWT(String usuario, String clave){
		JSONObject jo = new JSONObject();
		jo.put("alg","HSHA256");
		jo.put("typ","JWT");
		this.cabecera = jo.toString();
		this.usuario = usuario;
		this.clave = clave;
		this.token = "ND";

	}
	private String HMACSHA256(byte[] secretKey, byte[] message) {
    	byte[] hmacSha256 = null;
    	try {
      		Mac mac = Mac.getInstance("HmacSHA256");
      		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
      		mac.init(secretKeySpec);
      		hmacSha256 = mac.doFinal(message);
    	} catch (Exception e) {
      		System.out.println(e);
      		//throw new RuntimeException("Failed to calculate hmac-sha256", e);
    	}
    	return String.format("%h",new String(hmacSha256));
  	}
  	/**
  	* Metodo que genera un token.
  	* @return Regresa la cadena del token.
  	* @throws Exception Genera una excepcion si se trata generar un token sin usuario ni clave.
  	*/
	public String generaToken() throws Exception{
		if(this.usuario == null && this.clave == null){
			throw new Exception("Este objeto necesita usuario y clave.");
		}
		Base64.Encoder enc = Base64.getEncoder();
		this.iat = System.currentTimeMillis();
		JSONObject jo = new JSONObject();
		jo.put("sub",this.usuario);
		jo.put("iat",this.iat);
		String carga = jo.toString();
		String pre_jwt = enc.encodeToString(cabecera.getBytes()) + "." + enc.encodeToString(carga.getBytes());
		String firma = HMACSHA256(this.clave.getBytes(),pre_jwt.getBytes());
		System.out.println(firma);
		this.token = pre_jwt + "." + enc.encodeToString(firma.getBytes());
		return this.token;
	}

	/**
	* Metodo que valida un token dada una clave.
	* @param jwt Token
	* @param clave clave
	* @return Devuelve true si el token corresponde al usuario, false de lo contrario.
	*/
	public boolean validaToken(String jwt, String clave){
		Base64.Decoder dec = Base64.getDecoder();
		String[] token2 = jwt.split("\\.");	
		String pre_jwt = token2[0] + "." + token2[1];
		String firma_c = HMACSHA256(clave.getBytes(),pre_jwt.getBytes());
		System.out.println(firma_c);
		String firma_o = new String(dec.decode(token2[2]));
		if(firma_c.equals(firma_o)){
			return true;
		}
		return false;
	}
	/**
	* Metodo que valida que el token no haya expirado, el plazo es de 15 minutos.
	* @param jwt Token
	* @return Devuelve true si el token esta en tiempo, si ha expirado devuelve false.
	*/
	public boolean validaTokenTiempo(String jwt){
		Base64.Decoder dec = Base64.getDecoder();
		String[] token2 = jwt.split("\\.");	
		JSONObject cabecera = new JSONObject(new String(dec.decode(token2[0])));
		long tiempo = (long)cabecera.get("iat");
		Timestamp ts = new Timestamp(tiempo + 900000);
		Timestamp ts2 = new Timestamp(System.currentTimeMillis());
		return ts2.compareTo(ts) < 0;
	}

	@Override
	public String toString(){
		return this.token;
	}

}