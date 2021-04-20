package it.unibo.check


import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.x509.X509V1CertificateGenerator

import java.math.BigInteger
import java.security._
import java.util.Date
import javax.security.auth.x500.X500Principal

//Fake, just to simulate a X509 certificate

object CertificateUtils {
  def generateSelfSignedX509Certificate  = {
    Security.addProvider(new BouncyCastleProvider)
    // yesterday
    val validityBeginDate = new Date(System.currentTimeMillis - 24 * 60 * 60 * 1000)
    // in 2 years
    val validityEndDate = new Date(System.currentTimeMillis + 2 * 365 * 24 * 60 * 60 * 1000)
    // GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
    keyPairGenerator.initialize(1024, new SecureRandom)
    val keyPair = keyPairGenerator.generateKeyPair
    // GENERATE THE X509 CERTIFICATE
    val certGen = new X509V1CertificateGenerator
    val dnName = new X500Principal("CN=John Doe")
    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis))
    certGen.setSubjectDN(dnName)
    certGen.setIssuerDN(dnName) // use the same

    certGen.setNotBefore(validityBeginDate)
    certGen.setNotAfter(validityEndDate)
    certGen.setPublicKey(keyPair.getPublic)
    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption")
    certGen.generate(keyPair.getPrivate, "BC")
  }
}
