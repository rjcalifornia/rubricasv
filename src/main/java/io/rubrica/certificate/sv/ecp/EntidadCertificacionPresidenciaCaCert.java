/*
 * Copyright 2009-2018 Rubrica
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.rubrica.certificate.sv.ecp;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

/**
 * Certificado raiz de la Entidad de Certificación de Presidencia, representado
 * como un objeto <code>X509Certificate</code>.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 * @author Misael Fernández <misael.fernandez.correa@gmail.com>
 */
public class EntidadCertificacionPresidenciaCaCert extends X509Certificate {

    private X509Certificate certificate;

    public EntidadCertificacionPresidenciaCaCert() {
        super();

        StringBuffer cer = new StringBuffer();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("\n");
        cer.append("MIIF4TCCA8mgAwIBAgIILnZ9AT4VxNwwDQYJKoZIhvcNAQELBQAwfjExMC8GA1UE\n");
        cer.append("AwwoQVVUT1JJREFEIENFUlRJRklDQURPUkEgUkFJWiBQUkVTSURFTkNJQTEPMA0G\n");
        cer.append("A1UECwwGSVRJR0VTMRQwEgYDVQQKDAtQcmVzaWRlbmNpYTEVMBMGA1UEBwwMU2Fu\n");
        cer.append("IFNhbHZhZG9yMQswCQYDVQQGEwJTVjAeFw0xODExMjYyMzEzMTlaFw0zODExMjEy\n");
        cer.append("MzEzMTlaMH4xMTAvBgNVBAMMKEFVVE9SSURBRCBDRVJUSUZJQ0FET1JBIFJBSVog\n");
        cer.append("UFJFU0lERU5DSUExDzANBgNVBAsMBklUSUdFUzEUMBIGA1UECgwLUHJlc2lkZW5j\n");
        cer.append("aWExFTATBgNVBAcMDFNhbiBTYWx2YWRvcjELMAkGA1UEBhMCU1YwggIiMA0GCSqG\n");
        cer.append("SIb3DQEBAQUAA4ICDwAwggIKAoICAQDrMpoHmW3K6VMlWHGFU/WQMrWrzdorIDXY\n");
        cer.append("qfF76ZW6dxL6ib0NcSd05SRWUlMi1dfGdDm1+U8F1rLffntQkAnVFl0fp7F7U8KO\n");
        cer.append("Rb9r3A0gwzCAtlyXick0nLu7BGIrBkpjRygZsDxOOS6Dqw9sIFjHdaTRpMHocI0z\n");
        cer.append("kMG2gXQHgcaUY9qFeH0k/8LHBtqRp1MX9QueXiN7I59e6CjMiXaNbnaTsW+iGJYt\n");
        cer.append("jy00vcs7bulvni+kn4//H+6Q4oT4+gCQPnhZSfwxQoDM2uWcvWSFDbdx3d0iuaaw\n");
        cer.append("Dhj9o16/5k96bWNchhiMtsGOIWqiFwkhLD3YPq20qmXS7mHUKZreg2/MrdhH7n6j\n");
        cer.append("Brj4f3oGOFBm8G7+94gfO+UgLOT/yCEoWEjXf8lK1PbyAVs6uBYyfOroHPztMwI+\n");
        cer.append("QdVIxT1RQFGlN/Mog6nu9fpOfTZ0q0C4RuXi9oX6VMV3fZi3Fnhvt0u3dOUShq0w\n");
        cer.append("WI5RaH+U8AJyFRJ32KIxQha+YCCz2oBHoBhe+K7o8XgG9ZAg9TJbHog4A59h9moz\n");
        cer.append("HtOtKFn3yg/lwYBoWWS+bDNTAVtAKuduJutHsEvyfxVj3NLVKIz4KFzBUizmSmu/\n");
        cer.append("3fNbwfCBvzFG9+WPLEDDyfusxpeHAgE2/KXQz76Hx5xb552a8F6cC+7NkhO+nbaM\n");
        cer.append("z1qYOohJ+wIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFA+H\n");
        cer.append("dIZLPTXoSiWejjPqbNB+puxsMB0GA1UdDgQWBBQPh3SGSz016Eolno4z6mzQfqbs\n");
        cer.append("bDAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggIBAOpmjHZ49Sdlb1B7\n");
        cer.append("ojDAd/8Z181abfsu1D19sQnsbou5EPoK0GyWtpdsBZnSc2GCcEwA7k8arV1R9N2g\n");
        cer.append("ovq5DrF/Ng8WxpL1zdWG+9LJFZhxgsZa/ChzU17S7Udk6VyANx7oqwt+K/s6DDvE\n");
        cer.append("YnCMgWLrPVSFnSwut8aef28pc3u9dYQErXhoMxkhhcu+JX6xFPr0NKbQNbgi/SHb\n");
        cer.append("j6iP02WhnbwY5YHi25TXzZf8yey9A/tqGlL2qtYmt3yBHQHntgWpWR/smM0uW2kC\n");
        cer.append("Qoe3fpYzYJ8Jid/LgoxSmF/n0Z7OtCZnyacebhz4VnYClIH02x92nFGvJ1ulirn0\n");
        cer.append("YLs8KPeqicREYB+NzBdw8KuLEMqFC0adOL4VC+6ydbq1hvd13Q/svMJfBYbQYuMA\n");
        cer.append("b3BcDNlrJluDsQh3NPL2kEQqSq8O5Myakk2KZRZvabvljbpz1WoWNnJbkYEQ8edU\n");
        cer.append("wp8lC6Yc0juVCbsmWCg17U1vimZXFpx5FYY7sS37wrRbXiPu+sEPkkZNKBcpIxHc\n");
        cer.append("uFb+mOg9G6TdSKA172GNCqLHtdsvaj9EDlicB0x5GwQpc1QPqyZo+2ba8AWUDbzm\n");
        cer.append("yqyMub8ppEzr3zSMxBwyRoIuKwhBvdhOqYLQTL/AQGltIKfJ0s9GTQ9b3Ydq7e8K\n");
        cer.append("0KKwW35OKi4SG+E5j0+GYcMzWAFx\n");
        cer.append("-----END CERTIFICATE-----");
        try {
            InputStream is = new ByteArrayInputStream(cer.toString().getBytes("UTF-8"));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            this.certificate = (X509Certificate) cf.generateCertificate(is);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        certificate.checkValidity();
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        certificate.checkValidity(date);
    }

    @Override
    public int getBasicConstraints() {
        return certificate.getBasicConstraints();
    }

    @Override
    public Principal getIssuerDN() {
        return certificate.getIssuerDN();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return certificate.getIssuerUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        return certificate.getKeyUsage();
    }

    @Override
    public Date getNotAfter() {
        return certificate.getNotAfter();
    }

    @Override
    public Date getNotBefore() {
        return certificate.getNotBefore();
    }

    @Override
    public BigInteger getSerialNumber() {
        return certificate.getSerialNumber();
    }

    @Override
    public String getSigAlgName() {
        return certificate.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return certificate.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return certificate.getSigAlgParams();
    }

    @Override
    public byte[] getSignature() {
        return certificate.getSignature();
    }

    @Override
    public Principal getSubjectDN() {
        return certificate.getSubjectDN();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return certificate.getSubjectUniqueID();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return certificate.getTBSCertificate();
    }

    @Override
    public int getVersion() {
        return certificate.getVersion();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return certificate.getEncoded();
    }

    @Override
    public PublicKey getPublicKey() {
        return certificate.getPublicKey();
    }

    @Override
    public String toString() {
        return certificate.toString();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException {
        certificate.verify(key);
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        certificate.verify(key, sigProvider);
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return certificate.getCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return certificate.getExtensionValue(oid);
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return certificate.getNonCriticalExtensionOIDs();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return certificate.hasUnsupportedCriticalExtension();
    }
}
