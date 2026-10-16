AutoFirma (AutoFirma-rs) - versión portable para Windows
========================================================

Este ZIP contiene AutoFirma listo para usar, sin instalador y sin permisos de
administrador.

Contenido
---------
  autofirma.exe          Aplicación (interfaz gráfica, línea de comandos y manejador
                         del protocolo afirma://).
  LICENSE\               Licencias (GPL-2.0-or-later o EUPL-1.1).

Uso sin instalar
----------------
Haga doble clic en autofirma.exe para firmar o verificar documentos.

Firma en trámites web (protocolo afirma://)
-------------------------------------------
Para que el navegador pueda abrir AutoFirma desde una sede electrónica hay que
registrar el protocolo afirma:// y la CA local que protege la comunicación con el
navegador. Primero descomprima el ZIP en una carpeta definitiva (por ejemplo
%LOCALAPPDATA%\Programs\AutoFirma; si la mueve después, repita el registro) y
después abra una consola (cmd o PowerShell) en esa carpeta y ejecute:

  autofirma.exe install --user

(Si el ZIP incluye autofirma-cli.exe, puede usarlo en lugar de autofirma.exe en
todas las órdenes de consola: es la variante de consola del mismo programa.)

Esto, solo para el usuario actual y sin permisos de administrador:
  * genera la CA local y el certificado SSL de 127.0.0.1;
  * instala la CA en el almacén de certificados raíz del USUARIO. Windows mostrará
    un aviso de seguridad pidiendo confirmación: compruebe que el certificado se
    llama «Autofirma ROOT» y acepte;
  * instala la CA en los perfiles de Firefox del usuario;
  * registra el protocolo afirma:// y los menús contextuales en HKEY_CURRENT_USER.

Para deshacerlo:

  autofirma.exe uninstall --user

Para comprobar que todo está bien configurado:

  autofirma.exe doctor

Instalación para todos los usuarios
-----------------------------------
En equipos gestionados o compartidos use el instalador MSI, que hace todo lo
anterior para todo el equipo de forma silenciosa (sin el aviso de Windows) y admite
despliegue por GPO, Intune o SCCM. Ver docs/DEPLOYMENT.md en el código fuente.

Aviso de SmartScreen
--------------------
Si el ejecutable no está firmado digitalmente (compilaciones de prueba), Windows
SmartScreen puede mostrar «Windows protegió su PC». Las versiones publicadas se
distribuyen firmadas.
