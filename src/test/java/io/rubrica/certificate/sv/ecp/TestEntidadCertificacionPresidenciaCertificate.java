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

import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import io.rubrica.certificate.CrlUtils;
import io.rubrica.certificate.ValidationResult;
import io.rubrica.certificate.sv.ecp.CertificadoEntidadCertificacionPresidencia;
import io.rubrica.certificate.sv.ecp.CertificadoEntidadCertificacionPresidenciaFactory;
import io.rubrica.certificate.sv.ecp.EntidadCertificacionPresidenciaSubCert;
import io.rubrica.util.CertificateUtils;
import io.rubrica.util.OcspUtils;

public class TestEntidadCertificacionPresidenciaCertificate {

	private static final String CERT_PATH = "PRUEBA_FPUBLICO_RARGUELLO.p12";
	private static final String CERT_PASS = "12345678";
	private static final String CERT_ALIAS = "PRUEBA FPUBLICO MARCO RICARDO ARGUELLO JACOME's SECURITY DATA S.A. ID";

	// @Test
	public void testSD() throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(ClassLoader.getSystemResourceAsStream(CERT_PATH), CERT_PASS.toCharArray());
		PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS,
				new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));

		X509Certificate cert = (X509Certificate) pke.getCertificate();
		boolean esECP = CertificadoEntidadCertificacionPresidenciaFactory.esCertificadoEntidadCertificacionPresidencia(cert);
		System.out.println("Es EntidadCertificacionPresidencia? " + esECP);
		System.setProperty("jsse.enableSNIExtension", "false");

		CertificadoEntidadCertificacionPresidencia certECP = CertificadoEntidadCertificacionPresidenciaFactory.construir(cert);
//		System.out.println("nombres=" + certECP.getNombres());

		for (String url : CertificateUtils.getCrlDistributionPoints(cert)) {
			System.out.println("url=" + url);
		}

		// new SecurityDataCaCert().getPublicKey()
		ValidationResult result = CrlUtils.verifyCertificateCRLs(cert, new EntidadCertificacionPresidenciaSubCert().getPublicKey(),
				Arrays.asList(
						"https://direct.securitydata.net.ec/~crl/autoridad_de_certificacion_sub_security_data_entidad_de_certificacion_de_informacion_curity_data_s.a._c_ec_crlfile.crl"));
		System.out.println("Validation result: " + result);

		List<String> ocspUrls = CertificateUtils.getAuthorityInformationAccess(cert);
		for (String ocsp : ocspUrls) {
			System.out.println("OCSP=" + ocsp);
		}

		System.out.println("Valid? " + OcspUtils.isValidCertificate(cert));
	}
}