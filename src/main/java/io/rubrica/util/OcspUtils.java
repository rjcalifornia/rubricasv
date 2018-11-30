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
package io.rubrica.util;

import io.rubrica.certificate.sv.ecp.CertificadoEntidadCertificacionPresidenciaFactory;
import io.rubrica.certificate.sv.ecp.EntidadCertificacionPresidenciaCaCert;
import io.rubrica.certificate.sv.ecp.EntidadCertificacionPresidenciaSubCert;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.Reason;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.rubrica.core.RubricaException;

/**
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 * @author Misael Fernández <misael.fernandez.correa@gmail.com>
 * *
 */
public class OcspUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static boolean isValidCertificate(X509Certificate certificate) throws RubricaException {
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(certificate);

        if (CertificadoEntidadCertificacionPresidenciaFactory.esCertificadoEntidadCertificacionPresidencia(certificate)) {
            certs.add(new EntidadCertificacionPresidenciaSubCert());
        }

        // init certification path
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X509");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        CertPath cp;
        try {
            cp = cf.generateCertPath(certs);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        // load the root CA certificates
        X509Certificate rootECPCACert = new EntidadCertificacionPresidenciaCaCert();
        X509Certificate rootECPSubCert = new EntidadCertificacionPresidenciaSubCert();

        // init root trusted certs
        TrustAnchor taECPCaCert = new TrustAnchor(rootECPCACert, null);
        TrustAnchor taECPSubCert = new TrustAnchor(rootECPSubCert, null);

        Set<TrustAnchor> trustedCertsSet = new HashSet<TrustAnchor>();
        trustedCertsSet.add(taECPCaCert);
        trustedCertsSet.add(taECPSubCert);

        // init PKIX parameters
        PKIXParameters params;
        try {
            params = new PKIXParameters(trustedCertsSet);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        params.setRevocationEnabled(false);

        // enable OCSP
        // Security.setProperty("ocsp.enable", "true");
        // Activate CRLDP
        // System.setProperty("com.sun.security.enableCRLDP", "true");
        // perform validation
        CertPathValidator validator;
        try {
            validator = CertPathValidator.getInstance("PKIX");
        } catch (NoSuchAlgorithmException e) {
            throw new RubricaException(e);
        }

        try {
            CertPathValidatorResult result = validator.validate(cp, params);
            return true;
        } catch (InvalidAlgorithmParameterException e) {
            throw new RubricaException(e);
        } catch (CertPathValidatorException e) {
            Reason reason = e.getReason();
            int index = e.getIndex();
            System.out.println("reason=" + reason + "; index=" + index);

            Throwable t = e.getCause();

            if (t != null) {
                System.out.println("Cause=" + t.getClass());

                if (t instanceof SocketTimeoutException) {
                    System.out.println("Timeout al ir al OCSP server!");
                    return false;
                }
            }

            return false;
        }
    }
}
