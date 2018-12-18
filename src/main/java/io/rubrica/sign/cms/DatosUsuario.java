/*
 * Firma Digital: Servicio
 * Copyright 2017 Secretaría Nacional de la Administración Pública
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.rubrica.sign.cms;

/**
 * Datos del usuario para contruir la validacion CMS.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class DatosUsuario {

    private String cedula;
    private String nombresApellidos;
    private String fechaFirmaArchivo;

    public DatosUsuario(String cedula, String nombresApellidos) {
        this.cedula = cedula;
        this.nombresApellidos = nombresApellidos;
    }
    
    public DatosUsuario(String cedula, String nombresApellidos, String fechaFirmaArchivo) {
        this.cedula = cedula;
        this.nombresApellidos = nombresApellidos;
        this.fechaFirmaArchivo = fechaFirmaArchivo;
    }

    public DatosUsuario() {
    }

    public String getCedula() {
        return cedula;
    }

    public void setCedula(String cedula) {
        this.cedula = cedula;
    }

    public String getNombresApellidos() {
        return nombresApellidos;
    }

    public void setNombresApellidos(String nombre) {
        this.nombresApellidos = nombre;
    }

    public String getFechaFirmaArchivo() {
        return fechaFirmaArchivo;
    }

    public void setFechaFirmaArchivo(String fechaFirmaArchivo) {
        this.fechaFirmaArchivo = fechaFirmaArchivo;
    }

    @Override
    public String toString() {
        return "DatosUsuario [nombre=" + nombresApellidos + ", fechaFirmaArchivo=" + fechaFirmaArchivo + ", cedula=" + cedula + "]";
    }
}
