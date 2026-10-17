"""Genera crates/autofirma-android/locales/*.txt a partir de cats.json (xml2cat.py) con las
correcciones de 09 §10 n.º 59 y los textos propios de AutoFirma para Android."""
import json, re, sys

cats = json.load(open(sys.argv[1]))
OUT = sys.argv[2]
LANGS = ["es", "ca", "ca-valencia", "gl", "eu", "en"]
NAMES = {"es": "español", "ca": "catalán", "ca-valencia": "valenciano", "gl": "gallego", "eu": "euskera",
         "en": "inglés"}

# ----------------------------------------------------------------------------------------
# Correcciones de los textos originales. (idioma o "*", clave) -> (texto, motivo)
FIX = {}

def fix(lang, key, value, why):
    FIX[(lang, key)] = (value, why)

for l in LANGS:
    was = "«Aplikazio automatikoa», traducción automática del nombre" if l == "eu" else "«Autofirma App»"
    fix(l, "app_name", "AutoFirma", f"nombre de esta aplicación (era {was})")
    fix(l, "main_logo_content_desc", "AutoFirma", f"nombre de esta aplicación (era {was})")
    fix(l, "catala", "Català", "nombre del idioma en catalán (era «Catalá»)")
    fix(l, "euskera", "Euskara", "nombre del idioma en euskera (era «Euskera»)")

fix("ca", "intro_title", "Signatura fàcil i segura", "errata «segura/segura»")
fix("ca", "intro_text",
    "Signa documents de forma segura i legal identificant-te amb el teu certificat digital o DNI electrònic.",
    "errata «segura/segura»")
fix("ca", "cancel_nfc", "No utilitzar el DNIe", "seguía en español")
fix("ca", "save_changes", "Desa", "seguía en español")
fix("ca", "countersign", "Contrasignatura", "seguía en español")
fix("ca", "dialog_alias_cert_text", "{0}\nVàlid: {1}\nFins a: {2}\nEmissor: {3}", "seguía en español")
fix("ca", "sign_record", "Històric de signatures", "accento («Históric»)")
fix("ca-valencia", "cancel_nfc", "No utilitzar el DNIe", "seguía en español")
fix("ca-valencia", "dialog_alias_cert_text", "{0}\nVàlid: {1}\nFins a: {2}\nEmissor: {3}", "seguía en español")
fix("ca-valencia", "small_area_warning",
    "L'àrea seleccionada per a mostrar la firma té una grandària massa xicoteta.",
    "erratas («El àrea», «tè», «un grandària»)")
fix("gl", "enable_nfc_question",
    "Detectouse que o seu dispositivo dispón de NFC. Desexa habilitalo para a firma co DNIe por NFC?",
    "escape roto («ou00BF») y «Desea» en español")
fix("gl", "error_signing", "Erro durante a operación de firma", "acento («operacion»)")
fix("gl", "dialog_alias_cert_text", "{0}\nVálido: {1}\nAta: {2}\nEmisor: {3}", "«Hasta» en español")
fix("gl", "dialog_msg_loading_keystore", "Cargando almacén de chaves", "«claves» en español")
fix("gl", "operation_cancelled", "Operación cancelada", "acento («Operacion»)")
fix("en", "disclaimer", "2025 Gobierno de España", "escape sin interpretar («Espa\\u00F1a»)")
fix("en", "intro_text",
    "Sign documents securely and legally by identifying yourself with your digital certificate or electronic ID.",
    "traducción errónea («enclosed», «electonic»)")
fix("en", "accesibility_select_option", "Select an option", "«a option»")
fix("en", "eliminate_history_desc", "If you delete the history, you won't be able to recover it.",
    "traducción errónea («remove the historical»)")
for l, v in [("es", "Localiza el archivo .p12 o .pfx en tu teléfono"),
             ("en", "Locate the .p12 or .pfx file on your phone"),
             ("ca", "Localitza l'arxiu .p12 o .pfx al teu telèfon"),
             ("ca-valencia", "Localitza l'arxiu .p12 o .pfx en el teu telèfon"),
             ("gl", "Localiza o arquivo .p12 ou .pfx no teu teléfono"),
             ("eu", "Aurkitu .p12 edo .pfx fitxategia zure telefonoan")]:
    fix(l, "locate_file_message", v, "punto de más («.pfx. en»)" + (" y verbo en indicativo («aurkitzen du»)" if l == "eu" else ""))

# Sustituciones dentro de un texto: (idioma, clave, de, a, motivo)
SUBS = [
    ("ca", "is_my_dnie_suitable_desc", "DNI 3.0 y 4.0", "DNI 3.0 i 4.0", "«y» en español"),
    ("ca", "error_signing", "l'operacion", "l'operació", "errata («operacion»)"),
    ("ca-valencia", "error_signing", "l'operacion", "l'operació", "errata («operacion»)"),
    ("gl", "visible_sign_help_text_3", "Durante o sinatura", "Durante a sinatura", "concordancia («o sinatura»)"),
    ("en", "load_cert", "Impair it", "Import it", "traducción errónea («Impair»)"),
]

# Nombre de la aplicación: «Autofirma App» y «Autofirma» pasan a «AutoFirma» (con las
# declinaciones del euskera).
EU_NAME = [("Autofirma App-ekin", "AutoFirmarekin"), ("Autofirma App-etik", "AutoFirmatik"),
           ("Autofirma App-ek", "AutoFirmak"), ("Autofirma App-en", "AutoFirmaren"),
           ("Autofirma Appen", "AutoFirmaren")]

def rename(lang, text):
    if lang == "eu":
        for a, b in EU_NAME:
            text = text.replace(a, b)
    text = re.sub(r"Autofirma [Aa]pp", "AutoFirma", text)
    return text.replace("Autofirma", "AutoFirma")

# ----------------------------------------------------------------------------------------
# Textos propios. Clave -> {idioma: texto}
NEW = {}

def new(key, es, ca, va, gl, eu, en):
    assert key not in cats["es"], key
    NEW[key] = {"es": es, "ca": ca, "ca-valencia": va, "gl": gl, "eu": eu, "en": en}

new("back", "Atrás", "Enrere", "Arrere", "Atrás", "Atzera", "Back")
new("menu_information", "Información", "Informació", "Informació", "Información", "Informazioa", "Information")
new("menu_delete", "Eliminar", "Elimina", "Elimina", "Eliminar", "Ezabatu", "Delete")
new("not_available_title", "Próximamente", "Properament", "Pròximament", "Proximamente", "Laster", "Coming soon")
new("not_available_desc",
    "Esta función todavía no está disponible en AutoFirma para Android. Llegará en una próxima versión.",
    "Aquesta funció encara no està disponible a l'AutoFirma per a Android. Arribarà en una versió futura.",
    "Esta funció encara no està disponible en AutoFirma per a Android. Arribarà en una pròxima versió.",
    "Esta función aínda non está dispoñible en AutoFirma para Android. Chegará nunha próxima versión.",
    "Funtzio hau ez dago oraindik erabilgarri Androiderako AutoFirman. Hurrengo bertsio batean iritsiko da.",
    "This feature is not available in AutoFirma for Android yet. It will arrive in a future version.")
new("sign_file_desc",
    "Elige un documento del dispositivo y fírmalo con tu certificado o tu DNIe.",
    "Tria un document del dispositiu i signa'l amb el teu certificat o el DNIe.",
    "Tria un document del dispositiu i firma'l amb el teu certificat o el DNIe.",
    "Escolle un documento do dispositivo e asínao co teu certificado ou co DNIe.",
    "Aukeratu gailuko dokumentu bat eta sinatu zure ziurtagiriarekin edo NAN elektronikoarekin.",
    "Choose a document on your device and sign it with your certificate or your DNIe.")
new("web_signing", "Firma en trámites web", "Signatura en tràmits web", "Firma en tràmits web",
    "Sinatura en trámites web", "Web-izapideetako sinadura", "Signing on websites")
new("certificates", "Certificados", "Certificats", "Certificats", "Certificados", "Ziurtagiriak", "Certificates")
new("device_certificates_desc",
    "AutoFirma firma con los certificados instalados en el almacén de claves de Android. Puedes consultar los datos de cualquiera de ellos.",
    "L'AutoFirma signa amb els certificats instal·lats al magatzem de claus d'Android. Pots consultar les dades de qualsevol d'ells.",
    "AutoFirma firma amb els certificats instal·lats en el magatzem de claus d'Android. Pots consultar les dades de qualsevol d'ells.",
    "AutoFirma asina cos certificados instalados no almacén de chaves de Android. Podes consultar os datos de calquera deles.",
    "AutoFirmak Androiden gako-biltegian instalatutako ziurtagiriekin sinatzen du. Horietako edozeinen datuak kontsulta ditzakezu.",
    "AutoFirma signs with the certificates installed in the Android key store. You can view the details of any of them.")
new("view_certificate", "Ver un certificado", "Mostra un certificat", "Mostra un certificat", "Ver un certificado",
    "Ikusi ziurtagiri bat", "View a certificate")
new("cert_chain_len", "Cadena de {0} certificados", "Cadena de {0} certificats", "Cadena de {0} certificats",
    "Cadea de {0} certificados", "{0} ziurtagiriko katea", "Chain of {0} certificates")
new("system_language", "Idioma del sistema", "Idioma del sistema", "Idioma del sistema", "Idioma do sistema",
    "Sistemaren hizkuntza", "System language")
new("minutes_short", "{0} min", "{0} min", "{0} min", "{0} min", "{0} min", "{0} min")
new("nfc_not_available", "Este dispositivo no tiene NFC.", "Aquest dispositiu no té NFC.",
    "Este dispositiu no té NFC.", "Este dispositivo non ten NFC.", "Gailu honek ez du NFCrik.",
    "This device has no NFC.")
new("analyzing_document", "Analizando el documento…", "S'està analitzant el document…",
    "S'està analitzant el document…", "Analizando o documento…", "Dokumentua aztertzen…",
    "Analysing the document…")
new("proposed_format", "Formato de firma: {0}", "Format de signatura: {0}", "Format de firma: {0}",
    "Formato de sinatura: {0}", "Sinadura-formatua: {0}", "Signature format: {0}")
new("web_request_received", "Una página web ha pedido la operación «{0}».",
    "Una pàgina web ha demanat l'operació «{0}».", "Una pàgina web ha demanat l'operació «{0}».",
    "Unha páxina web pediu a operación «{0}».", "Web orri batek «{0}» eragiketa eskatu du.",
    "A website has requested the “{0}” operation.")
new("web_request_unsupported", "AutoFirma para Android no admite esta petición.",
    "L'AutoFirma per a Android no admet aquesta petició.", "AutoFirma per a Android no admet esta petició.",
    "AutoFirma para Android non admite esta petición.", "Androiderako AutoFirmak ez du eskaera hau onartzen.",
    "AutoFirma for Android does not support this request.")
new("operation_failed", "No se ha podido completar la operación: {0}",
    "No s'ha pogut completar l'operació: {0}", "No s'ha pogut completar l'operació: {0}",
    "Non se puido completar a operación: {0}", "Ezin izan da eragiketa osatu: {0}",
    "The operation could not be completed: {0}")
new("about_body",
    "AutoFirma para Android es una reimplementación libre en Rust de «Cliente @firma móvil» (Autofirma App), la aplicación de firma electrónica del Gobierno de España. Es compatible con sus formatos de firma y con el protocolo afirma:// de las sedes electrónicas, pero no es la aplicación oficial.",
    "L'AutoFirma per a Android és una reimplementació lliure en Rust del «Cliente @firma móvil» (Autofirma App), l'aplicació de signatura electrònica del Govern d'Espanya. És compatible amb els seus formats de signatura i amb el protocol afirma:// de les seus electròniques, però no és l'aplicació oficial.",
    "AutoFirma per a Android és una reimplementació lliure en Rust de «Cliente @firma móvil» (Autofirma App), l'aplicació de firma electrònica del Govern d'Espanya. És compatible amb els seus formats de firma i amb el protocol afirma:// de les seus electròniques, però no és l'aplicació oficial.",
    "AutoFirma para Android é unha reimplementación libre en Rust de «Cliente @firma móvil» (Autofirma App), a aplicación de sinatura electrónica do Goberno de España. É compatible cos seus formatos de sinatura e co protocolo afirma:// das sedes electrónicas, pero non é a aplicación oficial.",
    "Androiderako AutoFirma «Cliente @firma móvil» (Autofirma App) aplikazioaren Rust-eko berrinplementazio librea da; Espainiako Gobernuaren sinadura elektronikoko aplikazioa da hori. Haren sinadura-formatuekin eta egoitza elektronikoetako afirma:// protokoloarekin bateragarria da, baina ez da aplikazio ofiziala.",
    "AutoFirma for Android is a free reimplementation in Rust of “Cliente @firma móvil” (Autofirma App), the electronic signature app of the Government of Spain. It is compatible with its signature formats and with the afirma:// protocol used by e-government websites, but it is not the official app.")
new("about_license",
    "Es software libre: puedes redistribuirlo y modificarlo según los términos de la licencia GPL 2.0 o posterior o de la licencia EUPL 1.1, cuyo texto puede consultarse en:",
    "És programari lliure: el pots redistribuir i modificar d'acord amb els termes de la llicència GPL 2.0 o posterior o de la llicència EUPL 1.1, el text de la qual es pot consultar a:",
    "És programari lliure: el pots redistribuir i modificar d'acord amb els termes de la llicència GPL 2.0 o posterior o de la llicència EUPL 1.1, el text de la qual es pot consultar en:",
    "É software libre: podes redistribuílo e modificalo segundo os termos da licenza GPL 2.0 ou posterior ou da licenza EUPL 1.1, cuxo texto se pode consultar en:",
    "Software librea da: GPL 2.0 lizentziaren (edo ondorengo bertsioren baten) edo EUPL 1.1 lizentziaren baldintzen arabera birbanatu eta alda dezakezu. Lizentziaren testua hemen kontsulta daiteke:",
    "It is free software: you can redistribute and modify it under the terms of the GPL 2.0 or later or the EUPL 1.1, whose text is available at:")
new("eupl_url", "https://eupl.eu/1.1/es", "https://eupl.eu/1.1/es", "https://eupl.eu/1.1/es", "https://eupl.eu/1.1/es",
    "https://eupl.eu/1.1/es", "https://eupl.eu/1.1/en")
new("third_party_licenses",
    "Tipografía Inter (licencia OFL) e iconos Phosphor (licencia MIT).",
    "Tipografia Inter (llicència OFL) i icones Phosphor (llicència MIT).",
    "Tipografia Inter (llicència OFL) i icones Phosphor (llicència MIT).",
    "Tipografía Inter (licenza OFL) e iconas Phosphor (licenza MIT).",
    "Inter tipografia (OFL lizentzia) eta Phosphor ikonoak (MIT lizentzia).",
    "Inter typeface (OFL licence) and Phosphor icons (MIT licence).")
new("privacy_policy_body",
    "AutoFirma para Android es software libre e independiente: no lo opera ninguna administración pública ni ninguna empresa.\n\n"
    "## Qué datos trata\n\n"
    "- No recoge datos personales ni los envía a sus desarrolladores ni a terceros.\n"
    "- No incluye publicidad, analíticas ni telemetría.\n"
    "- Los documentos que firmas, tus certificados y el PIN y el CAN del DNIe se usan solo en tu dispositivo y solo mientras dura cada operación. Las claves privadas nunca salen del almacén de Android ni de la tarjeta.\n\n"
    "## Conexiones\n\n"
    "La aplicación solo se conecta a los servidores que indica la página web en la que firmas y, si hace falta, a los de las autoridades de certificación para comprobar certificados.\n\n"
    "## Datos guardados en el dispositivo\n\n"
    "Las preferencias y el histórico de firmas se guardan en el almacenamiento privado de la aplicación y se borran al desinstalarla. Puedes eliminar el histórico en Ajustes > Histórico de firmas.",
    "L'AutoFirma per a Android és programari lliure i independent: no l'opera cap administració pública ni cap empresa.\n\n"
    "## Quines dades tracta\n\n"
    "- No recull dades personals ni les envia als seus desenvolupadors ni a tercers.\n"
    "- No inclou publicitat, analítiques ni telemetria.\n"
    "- Els documents que signes, els teus certificats i el PIN i el CAN del DNIe només s'utilitzen al teu dispositiu i només mentre dura cada operació. Les claus privades no surten mai del magatzem d'Android ni de la targeta.\n\n"
    "## Connexions\n\n"
    "L'aplicació només es connecta als servidors que indica la pàgina web on signes i, si cal, als de les autoritats de certificació per comprovar certificats.\n\n"
    "## Dades desades al dispositiu\n\n"
    "Les preferències i l'historial de signatures es desen a l'emmagatzematge privat de l'aplicació i s'esborren en desinstal·lar-la. Pots eliminar l'historial a Ajustos > Històric de signatures.",
    "AutoFirma per a Android és programari lliure i independent: no l'opera cap administració pública ni cap empresa.\n\n"
    "## Quines dades tracta\n\n"
    "- No arreplega dades personals ni les envia als seus desenvolupadors ni a tercers.\n"
    "- No inclou publicitat, analítiques ni telemetria.\n"
    "- Els documents que firmes, els teus certificats i el PIN i el CAN del DNIe només s'utilitzen en el teu dispositiu i només mentres dura cada operació. Les claus privades no ixen mai del magatzem d'Android ni de la targeta.\n\n"
    "## Connexions\n\n"
    "L'aplicació només es connecta als servidors que indica la pàgina web en què firmes i, si cal, als de les autoritats de certificació per a comprovar certificats.\n\n"
    "## Dades guardades en el dispositiu\n\n"
    "Les preferències i l'històric de signatures es guarden en l'emmagatzematge privat de l'aplicació i s'esborren en desinstal·lar-la. Pots eliminar l'històric en Ajustos > Històric de signatures.",
    "AutoFirma para Android é software libre e independente: non o opera ningunha administración pública nin ningunha empresa.\n\n"
    "## Que datos trata\n\n"
    "- Non recolle datos persoais nin os envía aos seus desenvolvedores nin a terceiros.\n"
    "- Non inclúe publicidade, analíticas nin telemetría.\n"
    "- Os documentos que asinas, os teus certificados e o PIN e o CAN do DNIe úsanse só no teu dispositivo e só mentres dura cada operación. As chaves privadas nunca saen do almacén de Android nin da tarxeta.\n\n"
    "## Conexións\n\n"
    "A aplicación só se conecta aos servidores que indica a páxina web na que asinas e, se cómpre, aos das autoridades de certificación para comprobar certificados.\n\n"
    "## Datos gardados no dispositivo\n\n"
    "As preferencias e o histórico de firmas gárdanse no almacenamento privado da aplicación e bórranse ao desinstalala. Podes eliminar o histórico en Axustes > Histórico de firmas.",
    "Androiderako AutoFirma software libre eta independentea da: ez du inongo administrazio publikok ez enpresak kudeatzen.\n\n"
    "## Zer datu tratatzen ditu\n\n"
    "- Ez du datu pertsonalik biltzen, eta ez die garatzaileei ez hirugarrenei bidaltzen.\n"
    "- Ez du publizitaterik, analitikarik ez telemetriarik.\n"
    "- Sinatzen dituzun dokumentuak, zure ziurtagiriak eta NAN elektronikoaren PINa eta CANa zure gailuan bakarrik erabiltzen dira, eta eragiketa bakoitzak irauten duen bitartean soilik. Gako pribatuak ez dira inoiz Androiden biltegitik edo txarteletik ateratzen.\n\n"
    "## Konexioak\n\n"
    "Aplikazioa sinatzen ari zaren web orriak adierazten dituen zerbitzarietara bakarrik konektatzen da eta, behar izanez gero, ziurtapen-agintarienetara, ziurtagiriak egiaztatzeko.\n\n"
    "## Gailuan gordetako datuak\n\n"
    "Hobespenak eta sinaduren historia aplikazioaren biltegiratze pribatuan gordetzen dira, eta aplikazioa desinstalatzean ezabatzen dira. Historia Doikuntzak > Sinaduren historia atalean ezaba dezakezu.",
    "AutoFirma for Android is free and independent software: it is not operated by any public administration or company.\n\n"
    "## What data it processes\n\n"
    "- It does not collect personal data or send it to its developers or to third parties.\n"
    "- It contains no advertising, analytics or telemetry.\n"
    "- The documents you sign, your certificates and your DNIe PIN and CAN are used only on your device and only for the duration of each operation. Private keys never leave the Android key store or the card.\n\n"
    "## Connections\n\n"
    "The app only connects to the servers indicated by the website where you sign and, when needed, to those of the certification authorities to check certificates.\n\n"
    "## Data stored on the device\n\n"
    "Settings and the signature history are stored in the app's private storage and are deleted when you uninstall it. You can delete the history in Configuration > History of signatures.")
new("legal_notice_body",
    "AutoFirma para Android es software libre: puedes usarlo, estudiarlo, copiarlo y modificarlo según la licencia GPL 2.0 o posterior o la EUPL 1.1. Se distribuye sin ninguna garantía, en los términos de esas licencias.\n\n"
    "## No es la aplicación oficial\n\n"
    "Es una reimplementación compatible con «Cliente @firma móvil» (Autofirma App) del Gobierno de España, con sus formatos de firma y con el protocolo afirma:// de las sedes electrónicas, pero no es la aplicación oficial ni está avalada por ninguna administración.\n\n"
    "## Uso\n\n"
    "- Eres responsable de los documentos que firmas y del uso de tus certificados.\n"
    "- Comprueba siempre qué vas a firmar y en qué página web.\n"
    "- No uses la aplicación en dispositivos rooteados o con sistemas no oficiales, y mantén Android actualizado.",
    "L'AutoFirma per a Android és programari lliure: el pots utilitzar, estudiar, copiar i modificar d'acord amb la llicència GPL 2.0 o posterior o l'EUPL 1.1. Es distribueix sense cap garantia, en els termes d'aquestes llicències.\n\n"
    "## No és l'aplicació oficial\n\n"
    "És una reimplementació compatible amb el «Cliente @firma móvil» (Autofirma App) del Govern d'Espanya, amb els seus formats de signatura i amb el protocol afirma:// de les seus electròniques, però no és l'aplicació oficial ni està avalada per cap administració.\n\n"
    "## Ús\n\n"
    "- Ets responsable dels documents que signes i de l'ús dels teus certificats.\n"
    "- Comprova sempre què signaràs i en quina pàgina web.\n"
    "- No utilitzis l'aplicació en dispositius amb accés root o amb sistemes no oficials, i mantén l'Android actualitzat.",
    "AutoFirma per a Android és programari lliure: el pots utilitzar, estudiar, copiar i modificar d'acord amb la llicència GPL 2.0 o posterior o l'EUPL 1.1. Es distribuïx sense cap garantia, en els termes d'estes llicències.\n\n"
    "## No és l'aplicació oficial\n\n"
    "És una reimplementació compatible amb «Cliente @firma móvil» (Autofirma App) del Govern d'Espanya, amb els seus formats de firma i amb el protocol afirma:// de les seus electròniques, però no és l'aplicació oficial ni està avalada per cap administració.\n\n"
    "## Ús\n\n"
    "- Eres responsable dels documents que firmes i de l'ús dels teus certificats.\n"
    "- Comprova sempre què firmaràs i en quina pàgina web.\n"
    "- No utilitzes l'aplicació en dispositius amb accés root o amb sistemes no oficials, i mantín Android actualitzat.",
    "AutoFirma para Android é software libre: podes usalo, estudalo, copialo e modificalo segundo a licenza GPL 2.0 ou posterior ou a EUPL 1.1. Distribúese sen ningunha garantía, nos termos desas licenzas.\n\n"
    "## Non é a aplicación oficial\n\n"
    "É unha reimplementación compatible con «Cliente @firma móvil» (Autofirma App) do Goberno de España, cos seus formatos de sinatura e co protocolo afirma:// das sedes electrónicas, pero non é a aplicación oficial nin está avalada por ningunha administración.\n\n"
    "## Uso\n\n"
    "- Es responsable dos documentos que asinas e do uso dos teus certificados.\n"
    "- Comproba sempre que vas asinar e en que páxina web.\n"
    "- Non uses a aplicación en dispositivos con acceso root ou con sistemas non oficiais, e mantén Android actualizado.",
    "Androiderako AutoFirma software librea da: GPL 2.0 lizentziaren (edo ondorengo bertsioren baten) edo EUPL 1.1 lizentziaren arabera erabil, azter, kopia eta alda dezakezu. Inolako bermerik gabe banatzen da, lizentzia horien baldintzetan.\n\n"
    "## Ez da aplikazio ofiziala\n\n"
    "Espainiako Gobernuaren «Cliente @firma móvil» (Autofirma App) aplikazioarekin, haren sinadura-formatuekin eta egoitza elektronikoetako afirma:// protokoloarekin bateragarria den berrinplementazio bat da, baina ez da aplikazio ofiziala, eta ez du inongo administraziok babesten.\n\n"
    "## Erabilera\n\n"
    "- Zu zara sinatzen dituzun dokumentuen eta zure ziurtagirien erabileraren arduraduna.\n"
    "- Egiaztatu beti zer sinatuko duzun eta zer web orritan.\n"
    "- Ez erabili aplikazioa root sarbidea duten gailuetan edo sistema ez-ofizialetan, eta eguneratuta eduki Android.",
    "AutoFirma for Android is free software: you can use, study, copy and modify it under the GPL 2.0 or later or the EUPL 1.1. It is distributed without any warranty, under the terms of those licences.\n\n"
    "## It is not the official app\n\n"
    "It is a reimplementation compatible with “Cliente @firma móvil” (Autofirma App) of the Government of Spain, with its signature formats and with the afirma:// protocol used by e-government websites, but it is not the official app and it is not endorsed by any public administration.\n\n"
    "## Use\n\n"
    "- You are responsible for the documents you sign and for the use of your certificates.\n"
    "- Always check what you are about to sign and on which website.\n"
    "- Do not use the app on rooted devices or with unofficial systems, and keep Android up to date.")
new("accessibility_statement_body",
    "AutoFirma para Android quiere ser accesible para todas las personas, conforme al Real Decreto 1112/2018 y a la norma EN 301 549.\n\n"
    "- Funciona con TalkBack y con otros lectores de pantalla.\n"
    "- Respeta el tamaño de letra y el tema claro u oscuro del sistema.\n"
    "- Se puede usar en vertical y en horizontal.\n"
    "- Los botones y las opciones tienen un tamaño cómodo para tocarlos.\n\n"
    "Si encuentras alguna barrera de accesibilidad, comunícala en el repositorio del proyecto:",
    "L'AutoFirma per a Android vol ser accessible per a totes les persones, d'acord amb el Reial decret 1112/2018 i la norma EN 301 549.\n\n"
    "- Funciona amb el TalkBack i amb altres lectors de pantalla.\n"
    "- Respecta la mida de la lletra i el tema clar o fosc del sistema.\n"
    "- Es pot utilitzar en vertical i en horitzontal.\n"
    "- Els botons i les opcions tenen una mida còmoda per tocar-los.\n\n"
    "Si trobes alguna barrera d'accessibilitat, comunica-la al repositori del projecte:",
    "AutoFirma per a Android vol ser accessible per a totes les persones, d'acord amb el Reial Decret 1112/2018 i la norma EN 301 549.\n\n"
    "- Funciona amb TalkBack i amb altres lectors de pantalla.\n"
    "- Respecta la grandària de la lletra i el tema clar o fosc del sistema.\n"
    "- Es pot utilitzar en vertical i en horitzontal.\n"
    "- Els botons i les opcions tenen una grandària còmoda per a tocar-los.\n\n"
    "Si trobes alguna barrera d'accessibilitat, comunica-la en el repositori del projecte:",
    "AutoFirma para Android quere ser accesible para todas as persoas, conforme ao Real decreto 1112/2018 e á norma EN 301 549.\n\n"
    "- Funciona con TalkBack e con outros lectores de pantalla.\n"
    "- Respecta o tamaño de letra e o tema claro ou escuro do sistema.\n"
    "- Pódese usar en vertical e en horizontal.\n"
    "- Os botóns e as opcións teñen un tamaño cómodo para tocalos.\n\n"
    "Se atopas algunha barreira de accesibilidade, comunícaa no repositorio do proxecto:",
    "Androiderako AutoFirmak pertsona guztientzat irisgarria izan nahi du, 1112/2018 Errege Dekretuaren eta EN 301 549 arauaren arabera.\n\n"
    "- TalkBackekin eta beste pantaila-irakurgailu batzuekin funtzionatzen du.\n"
    "- Sistemaren letra-tamaina eta gai argia edo iluna errespetatzen ditu.\n"
    "- Bertikalean eta horizontalean erabil daiteke.\n"
    "- Botoiek eta aukerek ukitzeko tamaina erosoa dute.\n\n"
    "Irisgarritasun-oztoporen bat aurkitzen baduzu, jakinarazi proiektuaren biltegian:",
    "AutoFirma for Android aims to be accessible to everyone, in accordance with Royal Decree 1112/2018 and the EN 301 549 standard.\n\n"
    "- It works with TalkBack and other screen readers.\n"
    "- It follows the system font size and light or dark theme.\n"
    "- It can be used in portrait and landscape.\n"
    "- Buttons and options have a comfortable size for touch.\n\n"
    "If you find an accessibility barrier, please report it in the project repository:")

EXTRA = sys.argv[3] if len(sys.argv) > 3 else None
if EXTRA:
    exec(open(EXTRA).read())

# ----------------------------------------------------------------------------------------

def esc(v):
    assert "\\" not in v, v
    return v.replace("\n", "\\n")

HEADER = """# Textos de AutoFirma para Android ({name}).
#
# Formato: «clave = texto», una entrada por línea; «\\n» es un salto de línea y {{0}}, {{1}}…
# son los datos que se insertan. En los textos largos, una línea que empieza por «## » es un
# título, una que empieza por «- », un elemento de lista, y **así** se marca la negrita.
#
# Primera parte: los textos de Autofirma App 1.9 (res/values{res}/strings.xml), con las
# mismas 272 claves; las marcas HTML se han pasado a este formato (<b> → **, <p> → párrafos,
# <u> se quita) y los %s/%1$s a {{0}}. Como esta aplicación se llama AutoFirma, «Autofirma
# App» y «Autofirma» se escriben «AutoFirma». Las correcciones de las erratas del original
# (docs/spec/09-android.md §10, n.º 59) llevan delante un comentario «Corregido: …».
#
# Segunda parte (desde «# [autofirma-rs]»): textos propios de AutoFirma para Android.
"""
RES = {"es": "", "ca": "-ca", "ca-valencia": "-b+ca+ES+valencia", "gl": "-gl", "eu": "-eu", "en": "-en"}

count = 0
for lang in LANGS:
    lines = [HEADER.format(name=NAMES[lang], res=RES[lang])]
    cat = cats[lang]
    for key in cats["es"]:
        value = rename(lang, cat[key])
        notes = []
        if (lang, key) in FIX:
            value, why = FIX[(lang, key)]
            notes.append(why)
        for (l, k, a, b, why) in SUBS:
            if l == lang and k == key:
                assert a in value, (lang, key, a)
                value = value.replace(a, b)
                notes.append(why)
        for n in notes:
            lines.append(f"# Corregido: {n}.")
            count += 1
        lines.append(f"{key} = {esc(value)}")
    lines.append("")
    lines.append("# [autofirma-rs]")
    for key, texts in NEW.items():
        lines.append(f"{key} = {esc(texts[lang])}")
    open(f"{OUT}/{lang}.txt", "w").write("\n".join(lines) + "\n")
print("correcciones:", count, "textos propios:", len(NEW))
