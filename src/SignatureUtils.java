import static javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class SignatureUtils {

	public SignatureUtils() {
	}

	private static String KEY_INFO;

	public static void signUsingJSR105(
			Document document,
			String algorithm,
			PrivateKey signingKey,
			KeyStore keystore
			) throws Exception {

		Document docDoc = (Document) document.cloneNode(true);
		Document docHdr = (Document) document.cloneNode(true);
		noDocument(docHdr);
		noAppHdr(docDoc);

		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
		CanonicalizationMethod c14nMethod = signatureFactory.newCanonicalizationMethod(EXCLUSIVE, (C14NMethodParameterSpec) null);

		KEY_INFO = UUID.randomUUID().toString();
		KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
		X509Data x509Data = getX509Data(kif, keystore);
		javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(x509Data), KEY_INFO);

		XPathFactory xpf = XPathFactory.newInstance();
		XPath xpath = xpf.newXPath();
		xpath.setNamespaceContext(new DSNamespaceContext());

		List<Reference> referenceList = new ArrayList<>();
		referenceList.add(newReferenceKeyInfo(signatureFactory));

		QName qHdr = new QName("https://www.bcb.gov.br/pi/pibr.001/1.1", "AppHdr");
		QName qDoc = new QName("https://www.bcb.gov.br/pi/pibr.001/1.1", "Document");

		String expressionH = "//*[local-name()='" + qHdr.getLocalPart() + "']";
		String expressionD = "//*[local-name()='" + qDoc.getLocalPart() + "']";
		Node elementsToSignAppHdr = (Node) xpath.evaluate(expressionH, docHdr, XPathConstants.NODE);

		final List<Transform> tfList;
		DigestMethod digestMethod = signatureFactory.newDigestMethod(DigestMethod.SHA256, null);
		String id = UUID.randomUUID().toString();

		XMLSignatureFactory signatureFactory_apphdr = XMLSignatureFactory.getInstance("DOM");

		System.out.println("AppHdr: " + id);
		tfList = new ArrayList<>(2);
		tfList.add(signatureFactory_apphdr.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
		tfList.add(signatureFactory_apphdr.newCanonicalizationMethod(EXCLUSIVE, (C14NMethodParameterSpec) null));

		Reference reference =
				signatureFactory_apphdr.newReference(
						"",
						digestMethod,
						tfList,
						null,
						null
				);
		referenceList.add(reference);


		Node elementsToSignDocument = (Node) xpath.evaluate(expressionD, docDoc, XPathConstants.NODE);
		digestMethod = signatureFactory.newDigestMethod(DigestMethod.SHA256, null);
		id = UUID.randomUUID().toString();

		//used when dereferencing (is it right)
		Node toDsc = elementsToSignDocument;
		System.out.println("Document: " + id);

		Reference reference_document =
				signatureFactory.newReference(
						null,   // To use a reference 'null' we must dereference it, but HOW!!
						digestMethod,
						Collections.singletonList(signatureFactory.newCanonicalizationMethod(EXCLUSIVE, (C14NMethodParameterSpec) null)),
						null,
						null
				);
		referenceList.add(reference_document);


		//}


		SignatureMethod signatureMethod =
				signatureFactory.newSignatureMethod(algorithm, null);
		SignedInfo signedInfo =
				signatureFactory.newSignedInfo(c14nMethod, signatureMethod, referenceList);

		javax.xml.crypto.dsig.XMLSignature sig = signatureFactory.newXMLSignature(
				signedInfo,
				keyInfo,
				null,
				null,
				null);

		QName whereToPut = new QName("AppHdr", "Sgntr");
		String xpr = "//*[local-name()='" + whereToPut.getLocalPart() + "']";
		Node sgntrNode = (Node) xpath.evaluate(xpr, document, XPathConstants.NODE);

		//sgntrNode.getLength()
		//XPath xPath = XPathFactory.newInstance().newXPath();
		//String expression = "//Envelope/AppHdr/Sgntr";
		//Element sgntrNode = (Element) xPath.compile(expression).evaluate(document, XPathConstants.nODE);

		XMLSignContext signContext = new DOMSignContext(signingKey, sgntrNode);
		//URIDereferencer uriDereferencer = new URIDereferencer() {

		// Hellllllllllllllllll!!!!!!!!!!!!!!!!
		// To use a reference 'null' it must be done, but HOW!!
		// All references are being cut off when it's done

		//NoUriDereferencer dr = new NoUriDereferencer(toDsc);
		//dr.dereference(referenceList.get(2), signContext);

		//signContext.setURIDereferencer(dr);

		sig.sign(signContext);



	}

	private static  Reference newReferenceKeyInfo(XMLSignatureFactory xmlSignatureFactory) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		System.out.println("keyInfo: " + KEY_INFO);
		return xmlSignatureFactory.newReference(
				"#" + KEY_INFO,
				xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null),
				Collections.singletonList(xmlSignatureFactory.newCanonicalizationMethod(EXCLUSIVE, (C14NMethodParameterSpec) null)),
				null,
				null
				);
	}


	private static  X509Data getX509Data(KeyInfoFactory kif, KeyStore keystore) throws KeyStoreException {
		return newX509Data(kif, getCertificate(keystore));
	}

	private static  X509Certificate getCertificate(KeyStore keystore) throws KeyStoreException {
		String alias = keystore.aliases().nextElement();
		return (X509Certificate) keystore.getCertificate(alias);
	}


	private static  X509Data newX509Data(KeyInfoFactory kif, X509Certificate certificate) {
		X509IssuerSerial x509IssuerSerial = kif.newX509IssuerSerial(certificate.getIssuerDN().toString(), certificate.getSerialNumber());
		return kif.newX509Data(Collections.singletonList(x509IssuerSerial));
	}


	private static void  noDocument(Document doc) throws TransformerException {
		QName documentNode = new QName("Envelope", "Document");
		Node removed = remove(documentNode, doc);
		removed.getParentNode().removeChild(removed);

		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer t = tf.newTransformer();
		System.out.println("AppHdr: ");
		t.transform(new DOMSource(doc), new StreamResult(System.out));
		System.out.println("\n\n");
		
	}

	private static void noAppHdr(Document doc) throws TransformerException {
		QName documentNode = new QName("Envelope", "AppHdr");
		Node removed = remove(documentNode, doc);
		removed.getParentNode().removeChild(removed);

		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer t = tf.newTransformer();
		System.out.println("Document: ");
		t.transform(new DOMSource(doc), new StreamResult(System.out));
		System.out.println("\n\n");
		
	}

	private static Node remove(QName locator, Document document) {
		XPathFactory xpf = XPathFactory.newInstance();
		XPath xpath = xpf.newXPath();
		String xpr = "//*[local-name()='" + locator.getLocalPart() + "']";
		try {
			return (Node) xpath.evaluate(xpr, document, XPathConstants.NODE);

		} catch (XPathExpressionException e) {
			e.printStackTrace();

		}
		return null;

	}


}
