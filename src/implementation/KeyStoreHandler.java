package implementation;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class KeyStoreHandler {
	private KeyStore myKeyStore;
	private FileInputStream fis;
	private FileOutputStream fos;
	private char[] password = "root".toCharArray();
	String addresa = "/home/konstantin/eclipse-workspace/ZP2018/ETFrootCA.p12";

	public KeyStoreHandler() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try {
			fis = new FileInputStream(addresa);
			myKeyStore = KeyStore.getInstance("PKCS12");
			myKeyStore.load(fis, password);
			fis.close();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public boolean store() {
		try {
			fos = new FileOutputStream(addresa);
			myKeyStore.store(fos, this.password);
			fos.close();
			return true;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	public Enumeration<String> aliases() {
		try {
			return myKeyStore.aliases();
		} catch (KeyStoreException e) {
			System.out.println("aliases nije vracen \n");
			e.printStackTrace();
		}
		return null;
	}

	public boolean deleteEntry(String keyPairName) {
		try {
			myKeyStore.deleteEntry(keyPairName);
			this.store();
			return true;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	public X509Certificate getCertificate(String keyPairName) {
		try {
			X509Certificate cert;
			if (myKeyStore.isKeyEntry(keyPairName)) {
				Certificate[] chain = myKeyStore.getCertificateChain(keyPairName);
				if (chain == null) {
					System.out.println("Chain is null");
					return null;
				}
				cert = (X509Certificate) chain[0];
			} else {
				cert = (X509Certificate) myKeyStore.getCertificate(keyPairName);
			}
			return cert;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public Key getKey(String keyPairName)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return myKeyStore.getKey(keyPairName, password);
	}

	public void setCertificateEntry(String keyPairName, X509Certificate cert) throws KeyStoreException {
		myKeyStore.setCertificateEntry(keyPairName, cert);
	}

	public void setKeyEntry(String keyPairName, Key key, char[] password, Certificate[] cert) throws KeyStoreException {
		myKeyStore.setKeyEntry(keyPairName, key, password, cert);
	}

	public void reset() {
		Enumeration<String> aliases;
		aliases = this.aliases();
		while (aliases.hasMoreElements()) {
			this.deleteEntry(aliases.nextElement());
		}
	}

	public boolean entryInstanceOf(String keyPairName) throws KeyStoreException {
		return myKeyStore.entryInstanceOf(keyPairName, KeyStore.TrustedCertificateEntry.class);
	}

	public KeyPair getRootPair() {
		try {
			Key k = myKeyStore.getKey("etfrootca", password);
			Certificate[] chain = myKeyStore.getCertificateChain("etfrootca");
			X509Certificate cert = (X509Certificate) chain[0];
			return new KeyPair(cert.getPublicKey(), (PrivateKey)k);
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
