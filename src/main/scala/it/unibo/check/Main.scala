package it.unibo.check

import org.bouncycastle.asn1.x509.{AuthorityKeyIdentifier, SubjectKeyIdentifier}

import java.security.cert.X509Certificate

object Main extends App {
  case class ExtendedX509Certificate(x509Certificate: X509Certificate) {
    object OID {
      val SUBJECT_KEY_IDENTIFIER: String = "2.5.29.14"
      val AUTHORITY_KEY_IDENTIFIER: String = "2.5.29.35"
    }

    def getSubjectKeyIdentifier : SubjectKeyIdentifier = {
      val encoding : Array[Byte] = x509Certificate.getExtensionValue(OID.SUBJECT_KEY_IDENTIFIER)
      SubjectKeyIdentifier.getInstance(encoding)
    }

    def getAuthorityKeyIdentifier : AuthorityKeyIdentifier = {
      val encoding : Array[Byte] =   x509Certificate.getExtensionValue(OID.AUTHORITY_KEY_IDENTIFIER)
      AuthorityKeyIdentifier.getInstance(encoding)
    }
  }
  val cert = CertificateUtils.generateSelfSignedX509Certificate
  ExtendedX509Certificate(cert).getSubjectKeyIdentifier
  ExtendedX509Certificate(cert).getAuthorityKeyIdentifier
}