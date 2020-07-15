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
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class SignatureUtils {

	public SignatureUtils() {

	}

	private static String KEY_INFO;

	public static void signUsingJSR105(Document document, List<QName> namesToSign, String algorithm,
			PrivateKey signingKey, KeyStore keystore) throws Exception {
		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
		CanonicalizationMethod c14nMethod = signatureFactory.newCanonicalizationMethod(EXCLUSIVE,
				(C14NMethodParameterSpec) null);

		KEY_INFO = UUID.randomUUID().toString();
		KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
		X509Data x509Data = getX509Data(kif, keystore);
		// kif.newX509Data(Collections.singletonList(signingCert));
		javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(x509Data), KEY_INFO);

		XPathFactory xpf = XPathFactory.newInstance();
		XPath xpath = xpf.newXPath();
		xpath.setNamespaceContext(new DSNamespaceContext());

		List<javax.xml.crypto.dsig.Reference> referenceList = new ArrayList<>();
		referenceList.add(newReferenceKeyInfo(signatureFactory));
		Element toDsc = null;
		javax.xml.crypto.dsig.Reference reference_document = null;
		// XMLSignContext signContext = new DOMSignContext(signingKey,
		// document.getDocumentElement());

		for (QName nameToSign : namesToSign) {
			String expression = "//*[local-name()='" + nameToSign.getLocalPart() + "']";
			NodeList elementsToSign = (NodeList) xpath.evaluate(expression, document, XPathConstants.NODESET);
			for (int i = 0; i < elementsToSign.getLength(); i++) {
				Element elementToSign = (Element) elementsToSign.item(i);

				final List<Transform> tfList;
				DigestMethod digestMethod = signatureFactory.newDigestMethod(DigestMethod.SHA256, null);
				String id = UUID.randomUUID().toString();
				elementToSign.setAttributeNS(null, "id", id);
				elementToSign.setIdAttributeNS(null, "id", true);

				if (nameToSign.getLocalPart().equals("AppHdr")) {

					XMLSignatureFactory signatureFactory_apphdr = XMLSignatureFactory.getInstance("DOM");

					System.out.println("AppHdr: " + id);
					tfList = new ArrayList<>(2);
					tfList.add(
							signatureFactory_apphdr.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
					tfList.add(signatureFactory_apphdr.newCanonicalizationMethod(EXCLUSIVE,
							(C14NMethodParameterSpec) null));

					javax.xml.crypto.dsig.Reference reference = signatureFactory_apphdr.newReference("#" + id,
							digestMethod, tfList, null, null);
					referenceList.add(reference);

				} else if (nameToSign.getLocalPart().equals("Document")) {

					XMLSignatureFactory signatureFactory_document = XMLSignatureFactory.getInstance("DOM");

					digestMethod = signatureFactory.newDigestMethod(DigestMethod.SHA256, null);
					id = UUID.randomUUID().toString();
					elementToSign.setAttributeNS(null, "id", id);
					elementToSign.setIdAttributeNS(null, "id", true);

					System.out.println("Document: " + id);
					toDsc = elementToSign;

					// URIDereferencer uriDereferencer = new URIDereferencer() {

					// Hellllllllllllllllll!!!!!!!!!!!!!!!!
					// To use a reference 'null' it must be done, but HOW!!
					// All references are being cut off when it's done
					// signContext.setURIDereferencer(new NoUriDereferencer(toDsc));

					reference_document = signatureFactory_document.newReference("#" + id, // To use a reference 'null' we must dereference it, but HOW!!
							digestMethod, Collections.singletonList(signatureFactory_document
									.newCanonicalizationMethod(EXCLUSIVE, (C14NMethodParameterSpec) null)),
							null, null);
					referenceList.add(reference_document);

				}
			}
		}

		SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(algorithm, null);
		SignedInfo signedInfo = signatureFactory.newSignedInfo(c14nMethod, signatureMethod, referenceList);

		javax.xml.crypto.dsig.XMLSignature sig = signatureFactory.newXMLSignature(signedInfo, keyInfo, null, null,
				null);

		XMLSignContext signContext = new DOMSignContext(signingKey, document.getDocumentElement());

		// URIDereferencer uriDereferencer = new URIDereferencer() {

		// Hellllllllllllllllll!!!!!!!!!!!!!!!!
		// To use a reference 'null' it must be done, but HOW!!
		// All references are being cut off when it's done

		// NoUriDereferencer dr = new NoUriDereferencer(toDsc);
		// dr.dereference(reference_document, signContext);

		// signContext.setURIDereferencer(dr);

		sig.sign(signContext);

	}

	private static Reference newReferenceKeyInfo(XMLSignatureFactory xmlSignatureFactory)
			throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		System.out.println("keyInfo: " + KEY_INFO);
		return xmlSignatureFactory.newReference("#" + KEY_INFO,
				xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null),
				Collections.singletonList(
						xmlSignatureFactory.newCanonicalizationMethod(EXCLUSIVE, (C14NMethodParameterSpec) null)),
				null, null);
	}

	private static X509Data getX509Data(KeyInfoFactory kif, KeyStore keystore) throws KeyStoreException {
		return newX509Data(kif, getCertificate(keystore));
	}

	private static X509Certificate getCertificate(KeyStore keystore) throws KeyStoreException {
		String alias = keystore.aliases().nextElement();
		return (X509Certificate) keystore.getCertificate(alias);
	}

	private static X509Data newX509Data(KeyInfoFactory kif, X509Certificate certificate) {
		X509IssuerSerial x509IssuerSerial = kif.newX509IssuerSerial(certificate.getIssuerDN().toString(),
				certificate.getSerialNumber());
		return kif.newX509Data(Collections.singletonList(x509IssuerSerial));
	}

}
