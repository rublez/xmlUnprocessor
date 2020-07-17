import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

public class GenEnveloped {

	private static final String KEYSTORE_FILE = "74828799.p12";
	private static final String KEYSTORE_PWD = "nbcbank2020";
	private static final String XML_TO_SIGN = "envelope.xml";
	private static final String GENERATED_XML = "signed.xml";
	private final static XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");
	private static DocumentBuilderFactory dbf;
	private static KeyStore keystore;
	
	static {
		try {
			keystore = KeyStore.getInstance("PKCS12");
			keystore.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PWD.toCharArray());

			dbf = DocumentBuilderFactory.newInstance();
			dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
			dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
			dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
			dbf.setXIncludeAware(false);
			dbf.setExpandEntityReferences(false);
			dbf.setNamespaceAware(true);

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | ParserConfigurationException e) {
			throw new RuntimeException(e);

		}
	
	}
	
	public static void main(String[] args) {
		try {
			genEnveloped();
			
		} catch (Exception e) {
			System.err.println(e);
			System.exit(1);
			
		}
		
	}

	public static void genEnveloped() throws Exception {
		PrivateKey privateKey = (PrivateKey) keystore.getKey("1", KEYSTORE_PWD.toCharArray());

		Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(XML_TO_SIGN));

		SignatureUtils.signUsingJSR105(doc, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
				privateKey, keystore);
		
		// output the resulting document
		OutputStream os = new FileOutputStream(GENERATED_XML);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.setParameter(OutputKeys.ENCODING, "utf-8");
		trans.transform(new DOMSource(doc), new StreamResult(os));
	}
	
}
