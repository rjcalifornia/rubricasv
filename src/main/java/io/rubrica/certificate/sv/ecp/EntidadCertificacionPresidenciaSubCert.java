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
 * Certificado intermedio de la Entidad de Certificación de Presidencia,
 * representado como un objeto <code>X509Certificate</code>.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 * @author Misael Fernández <misael.fernandez.correa@gmail.com>
 */
public class EntidadCertificacionPresidenciaSubCert extends X509Certificate {

    private X509Certificate certificate;

    public EntidadCertificacionPresidenciaSubCert() {
        super();

        StringBuffer cer = new StringBuffer();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIEkjCCAnqgAwIBAgIIZRJ/VlPDjMcwDQYJKoZIhvcNAQELBQAwfjExMC8GA1UE\n");
        cer.append("AwwoQVVUT1JJREFEIENFUlRJRklDQURPUkEgUkFJWiBQUkVTSURFTkNJQTEPMA0G\n");
        cer.append("A1UECwwGSVRJR0VTMRQwEgYDVQQKDAtQcmVzaWRlbmNpYTEVMBMGA1UEBwwMU2Fu\n");
        cer.append("IFNhbHZhZG9yMQswCQYDVQQGEwJTVjAeFw0xODExMjgyMTI4MDhaFw0zODExMjEy\n");
        cer.append("MzEzMTlaMC8xLTArBgNVBAMMJEVOVElEQUQgREUgQ0VSVElGSUNBQ0lPTiBQUkVT\n");
        cer.append("SURFTkNJQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKvfR7C6mbqj\n");
        cer.append("tohmr8cw+SkyH6sfKGnS5r23sSOGhzBRQ16dG5GVv2351XMJLPOVC7le6B/bXk8K\n");
        cer.append("YYDeQeAnp1AD1LbBW8/zJFne54fTvqYLKVef80aZao5JNik8u4I3yssgt2qEYN2L\n");
        cer.append("SeNaDTljpJJoP8HmTUaCQgSWN1wVOusme4KsuB/Z/WWuV/+o3xl70SNNz6wHSSfz\n");
        cer.append("KY0FOkzr69KK1smGQd/4bXeVPNKO2vATL8pE0qpAOkfU8po2l3mO4LUUSsAHeAfF\n");
        cer.append("AS7rMEYmQtNGE4lEMIs0pNB3TgaaehGm+xCPtzF4sbSDveF2MSBI0jjYWiZPVaIa\n");
        cer.append("wE3aqC4OzycCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBQP\n");
        cer.append("h3SGSz016Eolno4z6mzQfqbsbDAdBgNVHQ4EFgQU/bXi1ah81zCil2WWu7acywjB\n");
        cer.append("N2IwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAtCzgOP8Hxt7k7\n");
        cer.append("xuLkpdePQaobFsFlDoZvz+O1rCbyq2B7NPjOHxz1JpkMVf/PLbY2HRn/tmwvlrNC\n");
        cer.append("a4xAaWBZd15HP8JI/sxsphRJVFe30XrWOsj1UkPknVokrc38yUbzMvV6PtZO7JNp\n");
        cer.append("IvYLD6K/lpXlfxVeYYW2sPBSenfT5iV6LXMPmZlbTpY4fMZ7lbDnefpapCtNog2i\n");
        cer.append("08z5Qo6rde1GXzuf9H17c0CLIpsq4DNpUNEs8p5BVk4fa0kmkf+ysm/J3uV9nJ68\n");
        cer.append("1U1l9Li/WWQjdK1hDZQES0TpCNQTOKTigWPVpRZ3ZwIxBJhofFF98g5OR5tTJlJu\n");
        cer.append("cJruSv2RjTD58K+R3lTSsqnG9ffckOoC9aEoRWgoFqVxdmYZYwxIKyHUac3L4zsu\n");
        cer.append("yiYEMAsTSqCclDsENi4MG46Lx8Be9iq/mdEckfHMKz1dO3wUDa/VLSer2sJndOI6\n");
        cer.append("5sHCR+0QflL4EfnOI1ymsBvqHkYvLQvW0jD/wd5BNX9ihupKo/mLPjMDWqtS5Cp0\n");
        cer.append("qT3mpkyZsqsXLiiOxsnNyCZHIi2wOeaXcCal3YA7xxTLkVgY7ZSRKWYEEEOmmoVd\n");
        cer.append("rowoDW+70xRH8qdRcuIGmUGdnBHQg4992Bc5I3ViT69Hc1fl/9fM75hLIf1ReQY+\n");
        cer.append("WuEtrbPLVgrDO8Tf+1FE92bvU2L62A==\n");
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
