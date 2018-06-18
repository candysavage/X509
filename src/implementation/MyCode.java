package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {

	private KeyStoreHandler keyStoreHandler;
	private PKCS10CertificationRequest myCSR;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
	}

	@Override
	public boolean importCertificate(String file, String keyPairName) {
		FileInputStream fis;
		try {
			fis = new FileInputStream(file);
			CertificateFactory factory = CertificateFactory.getInstance("X509");
			X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);
			fis.close();
			keyStoreHandler.setCertificateEntry(keyPairName, cert);
		} catch (KeyStoreException | CertificateException | IOException e) {
			e.printStackTrace();
		}
		return keyStoreHandler.store();

	}

	@Override
	public boolean importKeypair(String keyPairName, String file, String password) {
		KeyStore temp;
		FileInputStream fis;
		String name;

		try {
			fis = new FileInputStream(file);
			temp = KeyStore.getInstance("PKCS12");
			temp.load(fis, password.toCharArray());
			name = temp.aliases().nextElement();
			X509Certificate[] cert = new X509Certificate[1];
			cert[0] = (X509Certificate) temp.getCertificate(name);
			keyStoreHandler.setKeyEntry(keyPairName, temp.getKey(name, password.toCharArray()), cert);
			fis.close();
			return true;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
				| UnrecoverableKeyException e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public boolean exportKeypair(String keyPairName, String file, String password) {
		KeyStore temp;
		try {
			temp = KeyStore.getInstance("PKCS12");
			temp.load(null, null);
			X509Certificate[] cert = new X509Certificate[1];
			cert[0] = (X509Certificate) keyStoreHandler.getCertificate(keyPairName);
			File f = new File(file);

			if (f.exists()) {
				temp.load(new FileInputStream(f), password.toCharArray());
			}
			temp.setKeyEntry(keyPairName, keyStoreHandler.getKey(keyPairName), password.toCharArray(), cert);
			temp.store(new FileOutputStream(f), password.toCharArray());

			return true;

		} catch (NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException
				| KeyStoreException e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public boolean exportCertificate(String file, String keyPairName, int encoding, int format) {
		try {
			X509Certificate cert = (X509Certificate) keyStoreHandler.getCertificate(keyPairName);
			if (cert == null) {
				System.out.println("exportCertificate cert is null ********************\n");
			}
			switch (encoding) { // 0 = DER
								// 1 = PEM
			case 0:
				FileOutputStream fos = new FileOutputStream(file);
				if (format == 0) {
					fos.write(cert.getEncoded());
				} else {
					// ********************** chain ****************************************
				}
				fos.close();
				break;
			case 1:
				FileWriter fileWriter = new FileWriter(file);
				JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
				if (format == 0) {
					pemWriter.writeObject(cert);
				} else {
					// ********************** chain ***************************************
				}
				pemWriter.close();
				break;
			}
			return true;
		} catch (CertificateEncodingException | IOException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String keyPairName) {
		X509Certificate cert = (X509Certificate) keyStoreHandler.getCertificate(keyPairName);
		if (cert == null) {
			System.out.println("getCertPublicKeyAlgorithm cert is null **********************\n");
			return null;
		}
		return cert.getPublicKey().getAlgorithm();

	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		keyStoreHandler = new KeyStoreHandler();
		return keyStoreHandler.aliases();
	}

	@Override
	public boolean removeKeypair(String keyPairName) {
		return keyStoreHandler.deleteEntry(keyPairName);
	}

	@Override
	public void resetLocalKeystore() {
		keyStoreHandler.reset();
	}

	@Override
	public boolean canSign(String keyPairName) {
		X509Certificate cert = (X509Certificate) keyStoreHandler.getCertificate(keyPairName);
		if (cert == null) {
			System.out.println("canSign  cert is null ************************\n");
		}
		boolean[] keyUsage = cert.getKeyUsage();
		if (keyUsage == null) {
			return false;
		}
		if (keyUsage.length >= 6)
			if (keyUsage[5]) {
				return true;
			}
		return false;
	}

	@Override
	public String getSubjectInfo(String keyPairName) {
		X509Certificate cert = (X509Certificate) keyStoreHandler.getCertificate(keyPairName);
		if (cert == null) {
			System.out.println("getSubjectInfo cert is null ************************\n");
			return null;
		}
		Principal principal = cert.getSubjectDN();
		return principal.getName();

		// TEST
		// *********************************************************************************************************
	}

	@Override
	public String getCertPublicKeyParameter(String keyPairName) {
		int length;
		X509Certificate cert = (X509Certificate) keyStoreHandler.getCertificate(keyPairName);
		if (cert == null) {
			System.out.println("getCertPublicKeyParameter cert is null ************************\n");
			return null;
		}

		String algorithm = cert.getPublicKey().getAlgorithm();
		if (algorithm == "RSA") {
			PublicKey pkey = cert.getPublicKey();
			length = ((RSAPublicKey) pkey).getModulus().bitLength();
			return String.valueOf(length);
		}

		if (algorithm == "DSA") {
			length = ((DSAPublicKey) cert.getPublicKey()).getY().bitLength();
			return String.valueOf(length);
		}

		if (algorithm == "EC") {
			ECPublicKey ecKey = ((ECPublicKey) cert.getPublicKey());
			return ecKey.getAlgorithm();
		}
		return null;
	}

	@Override
	public int loadKeypair(String keyPairName) {
		X509Certificate cert = null;
		String name;
		Enumeration<String> aliases;

		cert = keyStoreHandler.getCertificate(keyPairName);
		if (cert == null) {
			System.out.println("cert == null");
			return -1;
		}
		this.access.setIssuer(cert.getIssuerX500Principal().getName());
		this.access.setSubject(cert.getSubjectX500Principal().getName());
		this.access.setNotAfter(cert.getNotAfter());
		this.access.setNotBefore(cert.getNotBefore());
		this.access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
		this.access.setSerialNumber(cert.getSerialNumber().toString());
		this.access.setVersion(Constants.V3);

		// System.out.println(cert.getPublicKey().getAlgorithm());
		// this.access.setPublicKeyAlgorithm((String)cert.getPublicKey().getAlgorithm());

		X500Principal etfPrincipal = ((X509Certificate) keyStoreHandler.getCertificate("etfrootca"))
				.getIssuerX500Principal();
		X500Principal tempPrincipal;
		X509Certificate tempCert;

		tempCert = cert;
		tempPrincipal = cert.getIssuerX500Principal();
		aliases = keyStoreHandler.aliases();

		try {
			if (keyStoreHandler.entryInstanceOf(keyPairName))
				return 2;
			else {
				while (true) {
					if (tempCert.getSubjectX500Principal().equals(tempPrincipal)) {
						if (tempCert.getIssuerX500Principal().equals(etfPrincipal))
							return 1;
						else
							return 0;
					} else {
						if (aliases.hasMoreElements()) {
							name = aliases.nextElement();
							tempCert = (X509Certificate) keyStoreHandler.getCertificate(name);
							tempPrincipal = tempCert.getIssuerX500Principal();
						} else
							aliases = this.loadLocalKeystore();
					}
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		return -1;
	}

	@Override
	public boolean saveKeypair(String keyPairName) {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
			kpg.initialize(Integer.parseInt(this.access.getPublicKeyParameter()));
			KeyPair keyPair = kpg.generateKeyPair();
			PrivateKey caKey = keyPair.getPrivate();

			Date startDate = this.access.getNotBefore();
			Date expiryDate = this.access.getNotAfter();
			String serialNumber = this.access.getSerialNumber();

			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

			X500Name subjectName = new X500Name(this.access.getSubject());
			X500Name issuerName = new X500Name(this.access.getSubject());

			X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(issuerName, new BigInteger(serialNumber),
					startDate, expiryDate, subjectName, subPubKeyInfo);

			boolean[] keyUsage = this.access.getExtendedKeyUsage();
			boolean[] isCritical = new boolean[3];
			isCritical[0] = this.access.isCritical(Constants.SKID);
			isCritical[1] = this.access.isCritical(Constants.SAN);
			isCritical[2] = this.access.isCritical(Constants.EKU);

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			v3CertGen.addExtension(Extension.subjectKeyIdentifier, isCritical[0],
					extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

			/*
			 * 1. any, 2. server uth, 3. client auth, 4. code signing, 5. email protection,
			 * 6. time stamp, 7. ocsp signing
			 */
			boolean EKU = false;
			KeyPurposeId[] kps = new KeyPurposeId[7];
			for (int i = 0, j = 0; i < 7; i++) {
				if (keyUsage[i]) {
					EKU = true;
					switch (i) {
					case 0:
						kps[j++] = KeyPurposeId.anyExtendedKeyUsage;
						break;
					case 1:
						kps[j++] = KeyPurposeId.id_kp_serverAuth;
						break;
					case 2:
						kps[j++] = KeyPurposeId.id_kp_clientAuth;
						break;
					case 3:
						kps[j++] = KeyPurposeId.id_kp_codeSigning;
						break;
					case 4:
						kps[j++] = KeyPurposeId.id_kp_emailProtection;
						break;
					case 5:
						kps[j++] = KeyPurposeId.id_kp_timeStamping;
						break;
					case 6:
						kps[j++] = KeyPurposeId.id_kp_OCSPSigning;
						break;
					}
				}

			}
			if (EKU == true)
				v3CertGen.addExtension(Extension.extendedKeyUsage, isCritical[2], new ExtendedKeyUsage(kps));

			String[] subjectAltNames = this.access.getAlternativeName(Constants.SAN);
			List<GeneralName> altNames = new ArrayList<GeneralName>();

			for (String altName : subjectAltNames) {
				if (isValidEmail(altName)) {
					altNames.add(new GeneralName(GeneralName.rfc822Name, altName));
				} else if (isValidDnsName(altName)) {
					altNames.add(new GeneralName(GeneralName.dNSName, altName));
				} else if (isValidIpAddress(altName)) {
					altNames.add(new GeneralName(GeneralName.iPAddress, altName));
				} else
					altNames.add(new GeneralName(GeneralName.otherName, altName));
			}

			GeneralNames SAN = GeneralNames
					.getInstance(new DERSequence((GeneralName[]) altNames.toArray(new GeneralName[] {})));
			v3CertGen.addExtension(Extension.subjectAlternativeName, isCritical[1], SAN);

			String sigAlg = this.access.getPublicKeyDigestAlgorithm();

			ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider(new BouncyCastleProvider())
					.build(caKey);

			X509CertificateHolder holder = v3CertGen.build(signer);
			X509Certificate[] cert = new X509Certificate[1];
			cert[0] = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);

			keyStoreHandler.setKeyEntry(keyPairName, (Key) keyPair.getPrivate(), cert);

			return true;

		} catch (NoSuchAlgorithmException | CertIOException | OperatorCreationException | CertificateException
				| KeyStoreException e) {
			e.printStackTrace();
		}

		return false;
	}

	// Auxiliary functions
	private boolean isValidEmail(String altName) {
		String rfc822Regex = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])";
		if (altName.matches(rfc822Regex)) {
			return true;
		}

		return false;
	}

	private boolean isValidDnsName(String altName) {
		String dnsName = "^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$";
		if (altName.matches(dnsName))
			return true;
		return false;
	}

	private boolean isValidIpAddress(String altName) {
		String ipAddress = "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$";
		if (altName.matches(ipAddress))
			return true;
		return false;
	}

	@Override
	public String importCSR(String file) {
		try {
			FileInputStream fis = new FileInputStream(file);
			myCSR = new PKCS10CertificationRequest(fis.readAllBytes());
			fis.close();
			X500Name x500Name = myCSR.getSubject();

			return x500Name.toString();

		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean exportCSR(String file, String keyPairName, String algorithm) {
		X509Certificate cert = keyStoreHandler.getCertificate(keyPairName);
		JcaPKCS10CertificationRequestBuilder reqBuild = new JcaPKCS10CertificationRequestBuilder(
				cert.getSubjectX500Principal(), cert.getPublicKey());

		PKCS10CertificationRequest req;
		try {
			req = reqBuild.build(
					new JcaContentSignerBuilder(algorithm).build((PrivateKey) keyStoreHandler.getKey(keyPairName)));
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(req.getEncoded());
			fos.close();
			return true;
		} catch (OperatorCreationException | IOException | UnrecoverableKeyException | KeyStoreException
				| NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public boolean signCSR(String file, String keyPairName, String algorithm) { // file - save CAreply in pkcs#7
																				// keyPairName - get PK to sign with
																				// algorithm - sign with algorithm
		try {

			ContentSigner signer = new JcaContentSignerBuilder(algorithm)
					.build((PrivateKey) keyStoreHandler.getKey(keyPairName));
			X509Certificate caCert = keyStoreHandler.getCertificate(keyPairName);
			SubjectPublicKeyInfo pkInfo = myCSR.getSubjectPublicKeyInfo();
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			PublicKey pubKey = converter.getPublicKey(pkInfo);

			JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(caCert,
					new BigInteger(this.access.getSerialNumber()), this.access.getNotBefore(),
					this.access.getNotAfter(), myCSR.getSubject(), pubKey);

			X509CertificateHolder holder = certGen.build(signer);

			byte[] certEncoded = holder.toASN1Structure().getEncoded();

			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
			generator.addSignerInfoGenerator(
					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer,
							caCert));
			generator.addCertificate(new X509CertificateHolder(certEncoded));
			generator.addCertificate(new X509CertificateHolder(caCert.getEncoded()));
			CMSTypedData content = new CMSProcessableByteArray(certEncoded);
			CMSSignedData signedData = generator.generate(content, true);

			FileWriter fileWriter = new FileWriter(file);
			JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
			pemWriter.writeObject(signedData.getEncoded());
			pemWriter.flush();
			pemWriter.close();

			return true;

		} catch (UnrecoverableKeyException | OperatorCreationException | KeyStoreException | NoSuchAlgorithmException
				| CertificateEncodingException | IOException | CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean importCAReply(String file, String keyPairName) {

		return false;
	}

}
