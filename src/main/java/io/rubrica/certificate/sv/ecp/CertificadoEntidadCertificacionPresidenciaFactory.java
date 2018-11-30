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

import static io.rubrica.certificate.sv.ecp.CertificadoEntidadCertificacionPresidencia.OID_CERTIFICADO_PERSONA_NATURAL;
import static io.rubrica.util.BouncyCastleUtils.certificateHasPolicy;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo
 * CertificadoEntidadCertificacionPresidencia a partir de certificados
 * X509Certificate.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 * @author Misael Fernández <misael.fernandez.correa@gmail.com>
 */
public class CertificadoEntidadCertificacionPresidenciaFactory {

    public static boolean esCertificadoEntidadCertificacionPresidencia(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_NATURAL));
    }

    public static CertificadoEntidadCertificacionPresidencia construir(X509Certificate certificado) {
        if (!esCertificadoEntidadCertificacionPresidencia(certificado)) {
            throw new IllegalStateException("Este no es un certificado emitido por el Entidad de Certificación Presidencia");
        }

        if (certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_NATURAL)) {
            System.out.println("OID_CERTIFICADO_PERSONA_NATURAL");
            return new CertificadoPersonaNaturalEntidadCertificacionPresidencia(certificado);
        } else {
            throw new RuntimeException("Certificado de la Entidad de Certificacion de la Presidencia de tipo desconocido!");
        }
    }
}
