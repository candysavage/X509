package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

import code.GuiException;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {

	private String selected;
	private KeyStore myKeyStore;
	private char[] password = "root".toCharArray();

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean importCertificate(String s, String s1) {
		FileInputStream fis;
		String address = "/home/konstantin/eclipse-workspace/ZP2018/ETFrootCA.p12";
		try {
			fis = new FileInputStream(s);
			CertificateFactory factory = CertificateFactory.getInstance("X509");
			X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);

			myKeyStore.setCertificateEntry(s1, cert);
			myKeyStore.store(new FileOutputStream(address), password);
			return true;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public boolean importKeypair(String keypair_name, String file, String password) {
		KeyStore temp;
		String address = "/home/konstantin/eclipse-workspace/ZP2018/ETFrootCA.p12";
		FileInputStream fis;
		String name;
		try {
			fis = new FileInputStream(file);
			temp = KeyStore.getInstance("PKCS12");
			temp.load(fis, password.toCharArray());
			name = temp.aliases().nextElement();
			X509Certificate[] cert = new X509Certificate[1];
			cert[0] = (X509Certificate) temp.getCertificate(name);

			myKeyStore.setKeyEntry(keypair_name, temp.getKey(name, password.toCharArray()), this.password, cert);
			myKeyStore.store(new FileOutputStream(address), this.password);
			return true;

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public boolean exportKeypair(String keypair_name, String file, String password) {
		KeyStore temp;

		try {
			temp = KeyStore.getInstance("PKCS12");
			temp.load(null, null);
			X509Certificate[] cert = new X509Certificate[1];
			cert[0] = (X509Certificate) myKeyStore.getCertificate(keypair_name);
			File f = new File(file + ".p12");

			if (f.exists()) {
				temp.load(new FileInputStream(f), password.toCharArray());
			}
			temp.setKeyEntry(keypair_name, myKeyStore.getKey(keypair_name, this.password), password.toCharArray(),
					cert);
			temp.store(new FileOutputStream(f), password.toCharArray());

			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String s) {
		try {
			X509Certificate cert = (X509Certificate) myKeyStore.getCertificate(s);
			return cert.getSigAlgName();

		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		FileInputStream fis;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		String address = "/home/konstantin/eclipse-workspace/ZP2018/ETFrootCA.p12";
		try {
			myKeyStore = KeyStore.getInstance("PKCS12");
			fis = new FileInputStream(address);
			myKeyStore.load(fis, password);
			return myKeyStore.aliases();

		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean removeKeypair(String s) {
		String address = "/home/konstantin/eclipse-workspace/ZP2018/ETFrootCA.p12";
		try {
			myKeyStore.deleteEntry(s);
			myKeyStore.store(new FileOutputStream(address), password);
			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public void resetLocalKeystore() {
		Enumeration<String> aliases;
		aliases = loadLocalKeystore();
		while (aliases.hasMoreElements()) {
			removeKeypair(aliases.nextElement());
		}
	}

	@Override
	public int loadKeypair(String keyPairName) {
		X509Certificate cert;
		String name;
		Enumeration<String> aliases;
		try {
			cert = (X509Certificate) myKeyStore.getCertificate(keyPairName);
			
			this.access.setIssuer(cert.getIssuerX500Principal().getName());
			this.access.setSubject(cert.getSubjectX500Principal().getName());
			this.access.setNotAfter(cert.getNotAfter());
			this.access.setNotBefore(cert.getNotBefore());
			this.access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
			this.access.setSerialNumber(cert.getSerialNumber().toString());
			this.access.setVersion(cert.getVersion());										// TEST ?
			
			selected = keyPairName;
			X500Principal etfPrincipal = ((X509Certificate) myKeyStore.getCertificate("etfrootca")).getIssuerX500Principal();
			X500Principal tempPrincipal;
			X509Certificate tempCert;
			
			tempCert = cert;
			tempPrincipal = cert.getIssuerX500Principal();
			aliases = myKeyStore.aliases();
			
			if
			
			
			
		}
		
		
		
		return 0;
	}

	@Override
	public boolean canSign(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportCertificate(String arg0, String arg1, int arg2, int arg3) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String getCertPublicKeyParameter(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getSubjectInfo(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean importCAReply(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String importCSR(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean saveKeypair(String arg0) {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(this.access.getPublicKeyAlgorithm());
			Date startDate = this.access.getNotBefore();
			Date expiryDate = this.access.getNotAfter();
			String serialNumber = this.access.getSerialNumber();
			KeyPair keyPair = kpg.generateKeyPair();
			PrivateKey caKey = keyPair.getPrivate();
			
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public boolean signCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

}
