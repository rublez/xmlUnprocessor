import java.util.Collections;
import java.util.Iterator;

import javax.xml.crypto.Data;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.XMLCryptoContext;

import org.w3c.dom.Node;

public class NoUriDereferencer implements URIDereferencer {

	private Node data = null;

	
	public NoUriDereferencer(Node node) {
	    data = node;
	}

	public Data dereference(URIReference ref, XMLCryptoContext ctxt) {
	    return new NodeSetData() {
	        public Iterator iterator() {
	            return Collections.singletonList(data).iterator();
	        }
	    };
	}
}
