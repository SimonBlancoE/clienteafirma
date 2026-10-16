AutoFirma (AutoFirma-rs) - versión portable para Linux
======================================================

Este archivo contiene AutoFirma listo para usar, sin instalar nada en el sistema.

Contenido
---------
  autofirma              Ejecutable (interfaz gráfica, línea de comandos y manejador
                         del protocolo afirma://).
  share/                 Icono, fichero .desktop y metadatos AppStream (opcionales).
  LICENSE/               Licencias (GPL-2.0-or-later o EUPL-1.1).

Uso sin instalar
----------------
  ./autofirma                     Abre la aplicación.
  ./autofirma doctor              Diagnóstico de la integración con el sistema.

Firma en trámites web (protocolo afirma://)
-------------------------------------------
Para que el navegador pueda abrir AutoFirma desde una sede electrónica hay que
registrar el protocolo afirma:// y la CA local que protege la comunicación con el
navegador. Primero copie la carpeta a una ubicación definitiva (si la mueve después,
repita el registro), por ejemplo:

  mkdir -p ~/.local/opt && cp -r . ~/.local/opt/autofirma

y después, como usuario normal (no root):

  ~/.local/opt/autofirma/autofirma install --user

Esto, solo para el usuario actual:
  * genera la CA local y el certificado SSL de 127.0.0.1;
  * instala la CA en los almacenes NSS de Firefox y Chrome/Chromium del usuario
    (necesita la herramienta certutil: paquete libnss3-tools, nss-tools o
    mozilla-nss-tools según la distribución);
  * registra afirma:// con un fichero .desktop en ~/.local/share/applications.

Para deshacerlo:

  ~/.local/opt/autofirma/autofirma uninstall --user

Para todos los usuarios del equipo use preferentemente el paquete .deb o .rpm, que
hacen todo esto automáticamente (incluida la CA en el almacén del sistema).

Requisitos
----------
  * glibc 2.28 o posterior (Debian 10, Ubuntu 20.04, RHEL/Rocky 8, openSUSE Leap 15
    o posteriores).
  * Escritorio X11 o Wayland con OpenGL/EGL.
  * Tarjetas inteligentes (DNIe...): servicio pcscd y el controlador PKCS#11 de la
    tarjeta (OpenSC u otro).

Más información: docs/DEPLOYMENT.md en el código fuente.
