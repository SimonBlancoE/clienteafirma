# 10 — DNIe por NFC: detección, PACE (CAN), mensajería segura, canal CWA-14890, PIN y firma

> **Propósito.** Especificación de implementación, a nivel de byte, de todo lo necesario para firmar con un
> **DNIe 3.0 / 4.0 por NFC** tal como lo hace JMulticard (la biblioteca que usa la app oficial «Autofirma» para
> Android, `firma-android`), para portarlo a Rust puro dentro de AutoFirma-rs **sin leer el código Java**.
> Cubre: detección de la tarjeta, PACE con CAN, mensajería segura AES (PACE) y 3DES (CWA-14890), sistema de
> ficheros del DNIe, lectura de certificados (PKCS#15, certificados comprimidos), PIN, firma, interacción con la
> interfaz (CAN/PIN), secuencias completas de APDU, vectores de prueba, simulador y licencias.
>
> **Fuentes analizadas (solo lectura).**
> - JMulticard **2.1** (`es.gob.afirma.jmulticard:jmulticard-base:2.1`), commit `4ec9494f` (2026-04-29),
>   módulos `jmulticard` (núcleo), `jmulticard-jse` (proveedor JCA + `BcCryptoHelper`), `jmulticard-crypto`
>   (copia de `BcCryptoHelper`/`BcPaceChannelHelper` + subconjunto de Bouncy Castle), `jmulticard-android`
>   (`AndroidNfcConnection`), `jmulticard-jsr268` (PC/SC de escritorio). Rutas abreviadas en este documento:
>   `core/…` = `jmulticard/src/main/java/es/gob/jmulticard/…`, `jse/…` = `jmulticard-jse/src/main/java/es/gob/jmulticard/…`,
>   `android/…` = `jmulticard-android/src/main/java/es/gob/jmulticard/android/nfc/…`.
> - `firma-android` (`afirma-ui-android`), commit `6f6554bd` (2025-07-18), `versionName 1.9`, que **declara
>   JMulticard 2.0** en `app/build.gradle` (`jmulticard-android:2.0`, `jmulticard-jse:2.0`). Este documento describe
>   el código 2.1; las diferencias 2.0→2.1 no se han podido comprobar sin conexión (**VERIFICAR** en la
>   paridad final con tarjeta real).
>
> **Relación con otras especificaciones.** El DNIe por lector de contacto, los diálogos de escritorio de PIN/CAN y la
> caché de PIN de AutoFirma de escritorio están en [05 §3.7](05-keystores.md). Las pantallas, textos y navegación de
> la app Android (pasos del CAN/PIN, detector, errores) están en [09 §4.9](09-android.md). Este documento se centra en
> el **protocolo** de la ruta sin contacto (NFC) y reutiliza la parte común (canal CWA-14890, ficheros, firma).

Convenciones:
- «**Java:**» describe el comportamiento exacto de JMulticard / firma-android (objetivo de paridad).
  «**Rust:**» es la implementación recomendada.
- «**Quirk:**» marca comportamiento sorprendente o erróneo del Java; se indica si hay que reproducirlo.
- «**VERIFICAR**» marca un dato que no se ha podido confirmar al 100 % (ni en el código ni por cálculo) y que hay
  que comprobar con una tarjeta real o con la norma original antes de darlo por bueno.
- Hex en mayúsculas, sin separadores salvo para legibilidad. `‖` = concatenación. `[a..b]` = rango de octetos
  semiabierto. Las longitudes son en octetos salvo que se diga lo contrario.
- Todos los valores criptográficos citados como «verificado» se han recomputado de forma independiente con un
  script Python (`cryptography`) y, cuando procede, con las clases Java de JMulticard compiladas (ver §14).

---

## 0. Visión general

### 0.1 Qué hace la app oficial

1. El usuario introduce el **CAN** (6 dígitos impresos en el anverso del DNI) y el **PIN** *antes* de acercar la
   tarjeta (pantallas de 3 pasos). Ambos se guardan en memoria.
2. Se detecta un `Tag` NFC (`IsoDep`) y se crea `AndroidNfcConnection` → `DnieProvider` → `KeyStore "DNI"`.
3. `KeyStore.load()` → `DnieFactory.getDnie()` identifica la tarjeta por los *bytes históricos* y crea un
   `DnieNfc`, cuyo constructor **abre PACE con el CAN** y, ya bajo mensajería segura AES, lee el CDF, los
   certificados, el PrKDF y el IDESP (sin PIN).
4. La app elige **automáticamente** el alias `CertFirmaDigital` (no muestra selector).
5. Al firmar: dentro del canal PACE se establece el **canal CWA-14890 «de PIN»** (autenticación mutua con
   certificados CV y RSA-1024), se verifica el PIN, se establece el **canal CWA-14890 «de usuario»**, y se envían
   `MSE:SET DST` + `PSO:COMPUTE DIGITAL SIGNATURE` con un `DigestInfo` calculado en el host (RSA-2048, PKCS#1 v1.5
   aplicado por la tarjeta).
6. Tras **cada** firma JMulticard rompe deliberadamente la mensajería segura (envía un `SELECT` en claro) y la
   siguiente firma repite PACE + canal de PIN + VERIFY + canal de usuario.

### 0.2 Capas de mensajería segura (lo más importante del documento)

La tarjeta tiene **un único contexto de mensajería segura activo**. Cada canal nuevo se negocia *dentro* del
contexto actual y, al terminar, **sustituye** sus claves. JMulticard lo modela con objetos `ApduConnection`
anidados, pero lo que viaja por el aire es esto:

```
 fase                          APDU en el aire                       quién la protege
 ───────────────────────────── ───────────────────────────────────── ─────────────────────────────
 detección                     (sin APDU; bytes históricos/HLR)      —
 PACE (MSE:SET AT, GA×4)       en claro                              —
 lectura IDESP/CDF/PrKDF/certs SM-PACE (AES-128, CMAC)               claves PACE
 handshake canal de PIN        SM-PACE                               claves PACE
 GET RETRIES + VERIFY PIN      SM-CWA-PIN (3DES, MAC retail 8 oct.)  claves CWA «PIN»   ← ya NO hay capa PACE
 handshake canal de usuario    SM-CWA-PIN                            claves CWA «PIN»
 MSE:SET DST + PSO:CDS         SM-CWA-USR (3DES, MAC retail 8 oct.)  claves CWA «usuario»
 «reset» tras la firma         SELECT MF en claro → error SM         la tarjeta descarta el contexto
 siguiente firma               PACE de nuevo, etc.
```

Fundamento en el código: `Cwa14890OneV1Connection(card, connection, …)` toma como subconexión
`connection.getSubConnection()` cuando `connection` es un `Cwa14890Connection` (y `PaceConnection` lo es, porque
hereda de `Cwa14890OneV2Connection`); por tanto el canal CWA transmite directamente sobre la conexión NFC cruda.
En cambio, durante `open()` del canal nuevo, las APDU del *handshake* salen por `card.getConnection()`, que sigue
siendo la conexión anterior hasta que `AbstractSmartCard.setConnection()` asigna la nueva **después** de `open()`.
(`core/connection/cwa14890/Cwa14890OneV1Connection.<init>`, `.open`; `core/card/AbstractSmartCard.setConnection`;
`core/card/dnie/Dnie3.openPinChannel`, `.openUserChannel`).

**Rust:** modelar explícitamente un `enum SmContext { Plain, Pace(PaceSm), CwaPin(CwaSm), CwaUser(CwaSm), Broken }` (§13.2) en la sesión, con
`send()` que envuelve con el contexto actual; establecer un canal = ejecutar su handshake con `send()` y después
sustituir el contexto. No reproducir el anidamiento de objetos de Java.

### 0.3 Algoritmos y parámetros (resumen)

| Elemento | Valor |
|---|---|
| Tecnología NFC | ISO/IEC 14443-4 (`IsoDep`); el DNIe es **tipo B** (ver §3.2) |
| PACE | ICAO 9303-11 / BSI TR-03110, `id-PACE-ECDH-GM-AES-CBC-CMAC-128` = OID `0.4.0.127.0.7.2.2.4.2.2`, *Generic Mapping* ECDH |
| Curva PACE | **brainpoolP256r1** (parámetro estandarizado **13** = `0x0D`) |
| Contraseña PACE | CAN (referencia `0x02`); MRZ (`0x01`) soportada por JMulticard pero no usada por la app |
| KDF PACE | SHA-1(K ‖ c)[0..16], c = `00000001` (enc), `00000002` (mac), `00000003` (π) |
| SM tras PACE | AES-128-CBC (IV = AES-ECB(K_enc, SSC)), AES-CMAC truncado a 8, SSC de 16 octetos empezando en 0 |
| Canal CWA-14890 | autenticación mutua con certificados CV, RSA-1024 «raw», ISO 9796-2 DS1, SIGMIN, SHA-1 |
| SM CWA | 3DES-CBC (IV 0, K1‖K2‖K1), MAC retail ISO 9797-1 alg. 3 con SSC, **8 octetos** (CWA v2), SSC de 8 octetos |
| Claves de usuario | RSA-2048 (`KprivAutenticacion` FID 0101, `KprivFirmaDigital` FID 0102) |
| Firma | `PSO:CDS` sobre `DigestInfo` DER (SHA-1/256/384/512); relleno PKCS#1 v1.5 en la tarjeta |
| Certificados en tarjeta | X.509 comprimidos con zlib tras una cabecera de 8 octetos |

---

## 1. Alcance: qué tarjetas usa firma-android por NFC

**Java (firma-android):** la única ruta NFC es `KeyStoreManagerFactory.initNfcKeyStoreManager()`, que crea
`new AndroidNfcConnection(tag)` y `new es.gob.jmulticard.jse.provider.DnieProvider(conn)` y pide
`KeyStore.getInstance("DNI", p)`. No hay rutas NFC para CERES, TIF, TUI ni tarjetas genéricas:

- **CERES (FNMT)** solo se usa por **lector USB CCID** (`AndroidCCIDConnection` + `CeresProvider`, luego
  `DnieProvider` por contacto). Nunca por NFC.
- `DnieKeyStoreImpl.isAnotherCardsAllowed()` devuelve `false`, así que `DnieFactory.getDnie(…, includeCloneCards=false)`
  ni siquiera intenta TIF / CERES 4.30 (que además solo se reconocerían por ATR de contacto).
- La pantalla «¿Es mi DNI compatible?» dice literalmente: «Los DNIe compatibles con este proceso son los
  **DNI 3.0 y 4.0**» (`strings.xml` `is_my_dnie_suitable_desc`).
- **Quirk (JMulticard):** la **TIE** (tarjeta de identidad de extranjero, «permiso de residencia») presenta los
  mismos datos de aplicación tipo B y se detecta erróneamente como DNIe (`TODO` en `DnieFactory.getDnie`, con ATR de
  ejemplo `3B8C800150D71A03F3E1F35E117781A16A`). No está soportada; el fallo aparecerá más tarde (lectura de CDF,
  canal CWA…). **Rust:** reproducir la detección pero tratar cualquier fallo posterior como «tarjeta no soportada».

Conclusión: el port NFC solo necesita **DNIe 3.0 y 4.0**, ambos con exactamente el mismo flujo (`DnieNfc`). La única
diferencia funcional es el juego de constantes CWA (r1/r2) elegido por el IDESP (§6.2).

### 1.1 Flujo de la app (firma-android) relevante para el port

Resumen orientado al protocolo; el detalle de la interfaz está en 09 §4.9.

| Paso | Clase / recurso | Comportamiento |
|---|---|---|
| Activar NFC | `NfcHelper`, `LoadKeyStoreFragmentActivity.requestNFCKeystore` | si NFC está apagado: toast «Por favor, active el NFC para usar DNIe y pulsa atrás para volver» y abre `Settings.ACTION_WIRELESS_SETTINGS`; si sigue apagado: toast «No se ha habilitado NFC.» y almacén del sistema |
| Elegir DNIe vs. certificado | `ChooseCertTypeDialog` | solo si la preferencia «usar NFC» (`AppConfig.isUseNfcConnection`) está activa |
| Introducción | `IntroUseDnieActivity` | botón «¿Es mi DNI compatible?»; muestra errores previos (tarjeta no soportada, CAN incorrecto, PIN incorrecto) |
| Paso 1: CAN | `InsertDataDnieStep1Fragment` | campo `inputType=number`, `maxLength=6`; válido si **longitud == 6**; error «Introduzca un CAN válido» |
| Paso 2: PIN | `InsertDataDnieStep2Fragment` | campo `textPassword`; válido si **longitud ≥ 4** (sin máximo); error «Introduzca un pin válido» |
| Paso 3 | `InsertDataDnieStep3Fragment` | «Leer DNIe con el móvil» → devuelve CAN y PIN |
| Detección | `NFCDetectorActivity` | *foreground dispatch* con filtros `TAG/NDEF/TECH_DISCOVERED` y tech-list `{NfcV,NfcF,NfcA,NfcB}`; manifiesto: `TECH_DISCOVERED` con `{IsoDep, NfcA, NfcB}`; guarda el `Tag` en `DnieConnectionManager` |
| Carga | `LoadNfcKeyStoreManagerTask` → `KeyStoreManagerFactory.initNfcKeyStoreManager` → `LoadCertificatesTask` | `ks.load(CallbackHandlerProtection(AndroidDnieNFCCallbackHandler(can, pin)))`; lista alias; `SelectAliasDialog.signWithSignCertificate()` toma `CertFirmaDigital` |
| Firma | `AndroidJcaKeyStoreManager` (`ks.getEntry(alias, null)`) → `SignTask` → `AOSigner.sign(…)` | el firmante usa `Signature` `SHAxxxwithRSA` del proveedor `DNIeJCAProvider` |

Detalles de `AndroidDnieNFCCallbackHandler.handle()` (`firma-android …/crypto/AndroidDnieNFCCallbackHandler.java`):
- `PasswordCallback` (incluye `CardWithRetriesPasswordCallback`) → PIN guardado; **ignora** el número de intentos.
- `es.gob.jmulticard.callback.CustomTextInputCallback` → CAN guardado.
- `CustomAuthorizeCallback` → no hace nada (JMulticard 2.1 nunca la emite; ver §10).
- Cualquier otro → solo registra un error en el log.

Gestión de errores de la app (códigos de `ThirdPartyErrors`, textos `es` de `strings.xml`):

| Situación | Excepción Java que llega a la app | Reacción | Código / texto al usuario |
|---|---|---|---|
| Tarjeta NFC no reconocida | `KeyStoreException` en `initNfcKeyStoreManager` → `UnsupportedNfcCardException` | vuelve a `IntroUseDnieActivity` con `errorUnsupportedNFC` | 300100 «La tarjeta que has proporcionado no parece ser un DNIe. Por favor inténtalo de nuevo» |
| No se puede conectar | otra `Exception` en `initNfcKeyStoreManager` → `InitializingNfcCardException` | vuelve al paso 3 con diálogo «Error en la lectura de tu DNIe» + «Reintentar» | 300102 solo en el log; el diálogo muestra el texto de 300103 |
| CAN incorrecto | `InvalidAccessCodeException` en `ks.load` | borra CAN y PIN guardados; `IntroUseDnieActivity` con `errorCANValidation` | 300108 «Error al iniciar la conexión con la tarjeta. Es posible que el CAN sea incorrecto. Inténtelo de nuevo.» |
| Cualquier error de lectura (tag perdido, SM…) | cualquier otra `Exception` en `ks.load`/`aliases`/`getCertificate` → `InitializingNfcCardException` | paso 3 con diálogo y botón «Reintentar» | 300103 «Se ha producido un error al intentar leer tu DNIe. Por favor, vuelve a intentarlo. Recuerda mantenerlo en una superficie lisa…» |
| PIN incorrecto (al firmar) | `AOException → … → SignatureAuthException → BadPinException` (tres niveles de causa) → `MSCBadPinException` | reinicia todo el flujo NFC con `errorPINValidation` | 300105, título «PIN incorrecto», texto «El PIN del dispositivo criptográfico es incorrecto. Tenga en cuenta que varios intentos fallidos consecutivos podrían bloquearlo.» (no se muestran los intentos restantes) |
| PIN bloqueado | `AuthenticationModeLockedException` (comprobada por **nombre de clase** solo en `LoadCertificatesTask.getCertificate`) | diálogo «El DNIe tiene el PIN bloqueado…» | 300106; **Quirk:** en NFC el bloqueo solo aparece al firmar y entonces cae en el error genérico de firma |
| Sin certificado de firma | (no hay alias `CertFirmaDigital`) | `signWithSignCertificate()` no hace nada | 300110 existe pero no se ve emitido en este flujo |

**Rust:** el núcleo (crate) debe exponer errores tipados equivalentes:
`CardNotSupported`, `ConnectionFailed`, `WrongCan`, `ReadError`, `WrongPin { retries_left: Option<u8> }`,
`PinBlocked`, `Cancelled`, `NoSigningCertificate`, `SecureMessaging(…)`, `TagLost`.

---

## 2. Transporte NFC

### 2.1 Android (`AndroidNfcConnection`, `android/AndroidNfcConnection.java`)

| Aspecto | Valor |
|---|---|
| Tecnología | `IsoDep.get(tag)`; `connect()` en el constructor |
| Timeout | `setTimeout(3000)` ms (`ISODEP_TIMEOUT`) |
| `reset()` | **no** reinicia nada: devuelve `getHistoricalBytes()` (NfcA) o, si es `null`, `getHiLayerResponse()` (NfcB) |
| `getTerminals()` | siempre `{0}`; `setTerminal()` no hace nada |
| `getMaxApduSize()` | `0xFF` (ver §2.3) |
| Longitud extendida | **no se usa** nunca (todas las APDU llevan Lc/Le cortos) |
| `close()` | `IsoDep.close()` |
| Logs | si es `VERIFY` (INS `0x20`), en vez de la APDU se registra «Verificacion de PIN» |
| Watchdog | solo en Android 2.3.3 ≤ API < 28: `NFCWatchdogRefresher` llama por reflexión a `TagService.connect(handle, 3)` cada 100 ms (máx. 30 s) entre transmisiones para evitar *keep-alives* que rompen el reto-respuesta |

`DnieProvider(conn)` hace `Dnie.connect(conn)` (abre si está cerrada) e inmediatamente `conn.close()`; luego
`BcPaceChannelHelper.openPaceChannel` vuelve a abrir con `conn.open()` → `IsoDep.connect()`.

**Rust (Android):** el puente del port Android en curso (`crates/autofirma-android/src/bridge.rs`,
`PlatformBridge::nfc_transceive`; `android/…/MainActivity.java`) usa `NfcAdapter.enableReaderMode` con
`FLAG_READER_NFC_A | NFC_B | SKIP_NDEF_CHECK`, `EXTRA_READER_PRESENCE_CHECK_DELAY = 1000` y `IsoDep.setTimeout(5000)`
(JMulticard: 3000 ms; 5000 es una desviación razonable porque `PSO:CDS` puede tardar más de un segundo). Para la
detección de §3 el evento `NfcTag` debe aportar además `getHistoricalBytes()`/`getHiLayerResponse()` y, si es NfcB,
`NfcB.getApplicationData()`/`getProtocolInfo()` (hoy solo lleva el identificador de la etiqueta). El watchdog de
JMulticard solo actúa en API < 28; como la app admite API ≥ 23, en API 23–27 hay que comprobar que las sondas de
presencia del modo lector no interrumpen el handshake CWA (**VERIFICAR**).

### 2.2 Escritorio con lector sin contacto (PC/SC)

JMulticard usa `SmartcardIoConnection` (`jmulticard-jsr268`): `connect("*")`, sin GET RESPONSE automático del JRE
(`sun.security.smartcardio.t0GetResponse=false`, `t1GetResponse=false`), `getMaxApduSize() = 0xFF`, y `reset()` =
`card.disconnect(true)` + reconexión (**reinicia la tarjeta**) devolviendo el ATR (para tarjetas sin contacto, el
*pseudo-ATR* PC/SC).

**Quirk (riesgo):** el constructor de `Dnie` llama a `conn.reset()` **después** de que `DnieNfc` haya abierto
PACE (`PaceConnection.reset()` → `subConnection.reset()`). En Android es inocuo; en PC/SC destruiría la sesión PACE
recién negociada (**VERIFICAR** con un lector real si el lector ignora el reset en T=CL). **Rust:** la operación
«identificar» del transporte no debe tener efectos secundarios; jamás reiniciar la tarjeta tras PACE.

**Rust (PC/SC):** crate `pcsc`; `SCardConnect(SHARE_EXCLUSIVE o SHARED, PROTOCOL_T1|T0)`; tomar el ATR de
`SCardStatus`; búfer de recepción ≥ 300 octetos (mejor `MAX_BUFFER_SIZE_EXTENDED`) porque la respuesta de
`PSO:CDS` bajo SM-CWA mide 285 octetos (§11).

### 2.3 Lógica común de transmisión (`core/connection/AbstractApduConnectionIso7816.transmit`)

1. Si `apdu.len() > getMaxApduSize()` (0xFF = 255): se trocea **la APDU completa** (cabecera incluida) en bloques
   de `255 − 5 = 250` octetos y cada bloque se envía como `90 C2 00 00 Lc ‖ bloque` (comando propietario
   «ENVELOPE» del DNIe). Si un bloque intermedio no devuelve `9000`, se devuelve esa respuesta. El último bloque
   también va en `90 C2 00 00 Lc …` y su respuesta es la respuesta del comando.
   En el flujo NFC del DNIe ninguna APDU supera 255 octetos (la mayor mide 244, §11), así que este camino **no se
   ejecuta**; implementarlo solo por paridad.
2. Si la respuesta es `61 xx`: se envía `00 C0 00 00 xx` (GET RESPONSE, **en claro**) y se concatena:
   `datos_parciales ‖ (respuesta completa del GET RESPONSE incluida su SW)`. Si no había datos parciales, se
   devuelve directamente la respuesta del GET RESPONSE. Recursivo.
3. Si la respuesta es `6C xx` **y** `CLA == 0x00` (solo comandos en claro): se reenvía el mismo comando con
   `Le = xx`.

**Quirk:** `CommandApdu.setLe()` reconstruye los octetos **sin Lc** (`CLA INS P1 P2 datos Le`). Solo afecta a
reintentos 6Cxx de comandos con datos, que no ocurren en este flujo. **Rust:** codificar correctamente (no
reproducir).

### 2.4 Codificación de `CommandApdu` (`core/apdu/CommandApdu.<init>`)

- Sin datos y sin Le: `CLA INS P1 P2` (4 octetos, caso 1).
- Con datos ≤ 255: `… Lc datos`; con datos > 255: `… 00 Lc1 Lc2 datos` (no ocurre aquí).
- Le presente (`Integer`): 1 octeto si ≤ 0xFF (Le=0 se escribe `00`); si > 0xFF, dos octetos sin el `00` previo
  (incorrecto según ISO, no ocurre aquí).
- **Muchos comandos de JMulticard no llevan Le aunque esperan respuesta** (SELECT, INTERNAL AUTHENTICATE,
  GENERAL AUTHENTICATE, PSO:CDS…). La tarjeta responde igualmente. **Rust:** reproducir exactamente (paridad de
  transcripción) y no añadir Le.

---

## 3. Detección e identificación de la tarjeta

### 3.1 Algoritmo (`core/card/dnie/DnieFactory.getDnie` y `getDnieNfc`)

```
terminals = conn.getTerminals(false)          // Android: {0}
si vacío → NoReadersFoundException
para cada terminal:
    conn.setTerminal(t)
    atrBytes = conn.reset()                   // CardNotPresentException → recordar y seguir
    actual = Atr(atrBytes, ATR_MASK)          // la máscara de 'actual' no se usa en equals
    si ATR_NFC.equals(actual) o ATR_NFC2.equals(actual):
        return new DnieNfc(conn, pwc, cryptoHelper, ch)
            · InvalidCanOrMrzException → InvalidAccessCodeException("El CAN indicado del DNIe no es correcto")
            · otra IcaoException      → ApduConnectionException("No se ha podido abrir el canal PACE")
    (solo getDnie) si ATR.equals(actual): byte[15]==0x04 → Dnie3 (contacto) ; si no → Dnie (2.0)
    (solo getDnie, includeCloneCards) TIF / CERES 4.30 por ATR de contacto
    si los dos últimos octetos son 65 81 → BurnedDnieCardException (DNIe «quemado»: memoria volátil borrada)
    invalid = InvalidCardException("DNIe" | "DNIe por NFC", ATR, atrBytes)
lanzar invalid; si no, la CardNotPresentException; si no, ApduConnectionException
```

Constantes (máscara `FF` = octeto significativo):

| Nombre | Patrón | Máscara |
|---|---|---|
| `ATR_NFC` | `3B 88 80 01 E1 F3 5E 11 77 81 A1 00 03` | `FF FF FF FF FF FF FF FF FF FF 00 FF 00` |
| `ATR_NFC2` | `3B 8C 80 01 50 42 8E 93 2A E1 F3 5E 11 77 81 81 02` | `FF FF FF FF FF 00 00 00 00 FF FF FF FF FF FF 00 00` |
| `ATR` (contacto) | `3B 7F 00 00 00 00 6A 44 4E 49 65 00 … 00 90 00` (20) | `FF FF 00 FF FF FF FF FF FF FF FF 00×7 FF FF` |

### 3.2 Semántica exacta de `Atr.equals` (crítica para Android)

`patrón.equals(actual)` (`core/card/Atr.equals`):
```
si patrón.len < actual.len → false
off = patrón.len − actual.len
para i en (actual.len−1) … 0:  si (patrón[i+off] & máscara[i+off]) != (actual[i] & máscara[i+off]) → false
true
```
Es decir, compara **`actual` contra el sufijo del patrón** usando la máscara del patrón. Consecuencias:

- **PC/SC (escritorio):** el lector entrega el pseudo-ATR completo de PC/SC. Interpretación de `ATR_NFC` según
  PC/SC parte 3 para tipo B: `3B 88 80 01` + 8 históricos = *Application Data* del ATQB (`E1 F3 5E 11`) +
  *Protocol Info* (`77 81 A1`; el último octeto, FWI/ADC/FO, va enmascarado) + MBLI (`00`) + TCK (enmascarado).
  `ATR_NFC2` es el formato de otros lectores: `3B 8C 80 01` + `50` + PUPI (4, aleatorio, enmascarado) +
  *Application Data* `E1 F3 5E 11` + *Protocol Info* `77 81 xx` + TCK.
- **Android:** el DNIe es tipo **B** (deducido de los patrones anteriores), así que `getHistoricalBytes()` devuelve
  `null` y JMulticard usa `getHiLayerResponse()` (HLR del ATTRIB). Si el HLR está **vacío** (lo esperable), el
  bucle de comparación no se ejecuta y `equals` devuelve **true**: cualquier tarjeta tipo B con HLR vacío pasa
  como DNIe (además del falso positivo de la TIE, que comparte con el DNIe los datos de aplicación del ATQB). **VERIFICAR** con una tarjeta real qué devuelve
  `getHiLayerResponse()` en DNIe 3.0 y 4.0.
- Comprobado ejecutando `DnieFactory` real contra un simulador (§14.3), entradas de `reset()` que se detectan como
  DNIe: vacía; el pseudo-ATR completo `3B888001E1F35E117781A10003`; `ATR_NFC2`; los 8 «históricos»
  `E1F35E117781A100` (no casan con el sufijo de `ATR_NFC`, cuyo último octeto es el TCK, pero **sí con el de
  `ATR_NFC2`**, cuyos dos últimos octetos van enmascarados); el pseudo-ATR de la TIE; y **cualquier entrada de 1 o 2
  octetos** (por esas mismas dos posiciones enmascaradas). No se detectan: `AABBCC`, otros pseudo-ATR sin contacto
  (`3B8F8001804F0CA0…`, `3B8180018080`) → `InvalidCardException`.

**Rust (paridad + robustez):**
1. Implementar `Atr::matches_suffix(pattern, mask, actual)` idéntico al Java para la ruta de paridad.
2. En Android, construir además el pseudo-ATR PC/SC desde `NfcB.getApplicationData()` (4) y
   `NfcB.getProtocolInfo()` (3): `3B 88 80 01 ‖ appData ‖ protInfo ‖ 00 ‖ TCK` (TCK = XOR de `88 80 01 …`), y
   compararlo con `ATR_NFC`; así se evita el falso positivo trivial del HLR vacío. Registrar el valor.
3. En PC/SC usar el ATR del lector tal cual.

### 3.3 Distinguir DNIe 3.0 / 4.0

**Java:** no se distinguen. `DnieNfc.getCardName()` = «DNIe 3.0/4.0 accedido de forma inalambrica». Lo único que
cambia según la tarjeta es el juego de constantes CWA, elegido por el **IDESP** (§6.2). Por contacto, el ATR con
`byte[15] == 0x04` (versión de SO 4.x) identifica DNIe 3.0/4.0 frente a DNIe 2.0 (`DnieAtr.toString` describe el
resto de campos: fabricante MoC `byte[11]` 0x10 Sagem/0x20 Siemens, chip `byte[12]` 0x01 Infineon/0x02 ST,
`byte[13..15]` `01 55` SLE78CLX408AP / `4C 34` 19WL34, ciclo de vida `byte[17]`, estado `byte[18..20]`).

**Rust:** exponer `CardKind::DnieNfc { idesp: Option<String>, cwa_set: R1 | R2 }` para diagnóstico.

### 3.4 Otras identificaciones disponibles (no usadas por la app)

- `EF.CardAccess` (FID `011C` bajo el MF) contiene los `PACEInfo`. JMulticard **no lo lee**: los parámetros PACE
  están fijados en código (§4.1). **Rust (opcional, no paridad):** leerlo en claro antes de PACE para validar que
  anuncia `id-PACE-ECDH-GM-AES-CBC-CMAC-128` y parámetro 13; si no, abortar con `CardNotSupported`.
  Que el DNIe permita leerlo sin SM: **VERIFICAR**.
- `EF.ATR/INFO` (`2F01`), `EF.DIR` (`2F00`) y los DG ICAO (`3F01/01xx`) existen en la interfaz `MrtdLds1`; no
  se usan para firmar.

---

## 4. PACE con CAN

### 4.1 Parámetros (fijados en código, no se lee `EF.CardAccess`)

`DnieNfc.getPaceConnection` construye siempre
`new CardAccess(PACE_ECDH_GM_AES_CBC_CMAC_128, BRAINPOOL_256_R1, DigestAlgorithm.SHA1)` y
`cryptoHelper.getPaceChannelHelper(cardAccess, null /* sin CHAT */)` (`core/asn1/icao/CardAccess`,
`jse/crypto/BcPaceChannelHelper`).

| Parámetro | Valor | Codificación |
|---|---|---|
| Protocolo | `id-PACE-ECDH-GM-AES-CBC-CMAC-128` (0.4.0.127.0.7.2.2.4.2.2) | `80 0A 04 00 7F 00 07 02 02 04 02 02` |
| Contraseña | CAN | `83 01 02` (MRZ = `83 01 01`, PIN = `83 01 03`) |
| CHAT | ninguno | — (si hubiera: `7F 4C 0E 06 09 04007F000703010203 53 01 02`, terminal ST; no usado) |
| Dominio | brainpoolP256r1, ID estandarizado 13 | `84 01 0D` |
| Longitud de clave de sesión | 128 bits | — |
| Hash de la KDF | SHA-1 | — |
| CLA de los comandos PACE | `00` (MSE), `10`/`10`/`10`/`00` (GA1..GA4) | encadenamiento de comandos ISO |

Parámetros de brainpoolP256r1 (RFC 5639; **verificado**: G está en la curva y `n·G = O`):

```
p = A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
a = 7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
b = 26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
Gx= 8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
Gy= 547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997
n = A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7   h = 1
```

### 4.2 Obtención del CAN (`DnieNfc.getPaceConnection`, estático)

1. Prompt `CardMessages "DnieNFC.0"` = «Por favor, introduzca el CAN o la MRZ del documento de identidad».
2. Intenta crear por reflexión `javax.security.auth.callback.TextInputCallback(prompt)`; en Android esa clase no
   existe y usa `es.gob.jmulticard.callback.CustomTextInputCallback(prompt)` (con `getText()/setText()`).
3. `ch.handle(new Callback[]{ cb })`; cualquier excepción → `PaceException("Error obteniendo el CAN")`.
4. Tipo: `CAN` si es numérico (`Character.isDigit` en todos los caracteres) **y** longitud ≤ 6; si no, `MRZ`
   (derivada con `Mrz.getMrzPswd`, SHA-1 de número de documento+fecha nacimiento+caducidad con dígitos de control,
   como en BAC). Nulo/vacío → `InvalidCanOrMrzException`.
5. El valor y el tipo se guardan en **campos estáticos** (`paceInitValue`, `paceInitType`) para reabrir PACE en
   cada firma (§9.4). Si PACE falla con `InvalidCanOrMrzException` se borran.

`WirelessInitializerCan.getBytes()` = `can.getBytes()` (codificación por defecto de la plataforma; con dígitos
equivale a ASCII). **Rust:** `π = CAN` en ASCII, solo dígitos `0-9`, longitud 6 (la app); aceptar 1–6 dígitos por
paridad con JMulticard. Guardar en `Zeroizing<String>`.

### 4.3 Secuencia de APDU (`BcPaceChannelHelper.openPaceChannel`)

Antes: si `!conn.isOpen()` → `conn.open()`.

**Paso 1 — MSE:SET AT** (`MseSetPaceAlgorithmApduCommand`, CLA `00`, sin Le):
```
00 22 C1 A4 12  80 0A 04 00 7F 00 07 02 02 04 02 02  83 01 02  84 01 0D
```
Respuesta esperada `90 00`. Otra → `PaceException(sw, "Error estableciendo el algoritmo del protocolo PACE (fallo en el MSE Set)")`.
(Las tarjetas ICAO pueden devolver `63 Cx` con contador de intentos para PIN; para CAN no aplica.)

**Paso 2 — GA1 «Encrypted Nonce»** (`DataEncryptedNonce`, CLA `10`, **sin Le**):
```
10 86 00 00 02  7C 00
```
Respuesta: `7C 12 80 10 ‖ z(16) ‖ 90 00`. JMulticard extrae `z = Tlv(Tlv(data).value).value` (no comprueba las
etiquetas). Fallo → `PaceException(sw, "Error solicitando el aleatorio de calculo PACE (nonce)")`.

Descifrado del nonce (`getSecretNonce`):
```
K_π = SHA-1(π ‖ 00 00 00 03)[0..16]
s   = AES-128-CBC-Decrypt(K_π, IV = 00×16, z)        // sin relleno; z mide 16
```

**Paso 3 — GA2 «Map Nonce»** (`DataMapNonce`, CLA `10`, sin Le):
```
SK_map_IFD = entero de 32 octetos aleatorios (SecureRandom)        // no se reduce mod n
PK_map_IFD = SK_map_IFD · G      (codificado no comprimido 04‖X(32)‖Y(32), 65 octetos)
10 86 00 00 45  7C 43 81 41 ‖ PK_map_IFD(65)
```
Respuesta: `7C 43 82 41 ‖ PK_map_ICC(65) ‖ 90 00`; JMulticard usa `unwrapEcKey` (= valor del TLV interno, sin
comprobar etiquetas) y `byteArrayToECPoint` (exige `04` inicial; **no** valida que el punto esté en la curva).
```
H  = SK_map_IFD · PK_map_ICC
G' = s·G + H                       (s interpretado como entero sin signo big-endian)
```
Fallo de SW → `PaceException(sw, "Error mapeando el aleatorio de calculo PACE (nonce)")`.

**Paso 4 — GA3 «Perform Key Agreement»** (`DataPerformKeyAgreement`, CLA `10`, sin Le):
```
SK_IFD = 32 octetos aleatorios (SecureRandom, reseeded)
PK_IFD = SK_IFD · G'
10 86 00 00 45  7C 43 83 41 ‖ PK_IFD(65)
```
Respuesta: `7C 43 84 41 ‖ PK_ICC(65) ‖ 90 00`.
```
K      = x( SK_IFD · PK_ICC )          // coordenada X afín
K_enc  = SHA-1(K ‖ 00 00 00 01)[0..16]
K_mac  = SHA-1(K ‖ 00 00 00 02)[0..16]
```
Fallo → `PaceException(sw, "Error en el tercer comando General Authenticate")`.

**Paso 5 — GA4 «Mutual Authentication»** (`DataMutualAuthentication`, **CLA `00`**, sin Le):
```
T_IFD = AES-CMAC(K_mac, 7F 49 4F 06 0A 04 00 7F 00 07 02 02 04 02 02 86 41 ‖ PK_ICC(65))[0..8]
00 86 00 00 0C  7C 0A 85 08 ‖ T_IFD(8)
```
Respuesta esperada: `7C 0A 86 08 ‖ T_ICC(8) ‖ 90 00`. Si la SW no es `9000` →
`InvalidCanOrMrzException(sw, "Error estableciendo el algoritmo del protocolo PACE (fallo en el General Authenticate)")`
→ en `DnieFactory`: `InvalidAccessCodeException("El CAN indicado del DNIe no es correcto")`.
Con un CAN erróneo la tarjeta solo puede detectarlo aquí (los pasos 1–4 no dependen del CAN desde su punto de
vista); la SW concreta (previsiblemente `63 00`) es **VERIFICAR**. El CAN no tiene contador de intentos.

Fin: `SecureMessaging(K_enc, K_mac, SSC = 00×16)`; se envuelve en `PaceConnection(conn, helper, sm)`.

### 4.4 Defectos de la implementación Java (no reproducir salvo donde se indica)

| # | Java | Efecto | Rust |
|---|---|---|---|
| P1 | `bigIntToByteArray(x)` solo quita el `00` de signo: si X tiene octetos iniciales a cero, **K mide < 32 octetos** | probabilidad teórica 2²⁴⁸/p ≈ **1/170** por sesión (medido contra el simulador: 20 fallos en 3000 PACE, todos con X = `00…`): la tarjeta rechaza GA4 con `6300` → en la carga el usuario ve «CAN incorrecto» (`InvalidAccessCodeException`); en el re-PACE de una firma, `CryptoCardException` (15/3000 firmas) | codificar K con longitud fija de 32 octetos (FE2OS, BSI TR-03111) — es lo que hace la tarjeta |
| P2 | no verifica `T_ICC` de la respuesta de GA4 | no autentica a la tarjeta | verificar `T_ICC = AES-CMAC(K_mac, 7F494F 06 0A OID 86 41 ‖ PK_IFD)[0..8]`; si no coincide → error `SecureMessaging` (mejora; no cambia el tráfico) |
| P3 | no valida puntos de la tarjeta (en curva, ≠ O) ni que `PK_ICC ≠ PK_IFD` | ataques de curva inválida | validar (SEC1, rechazar identidad); exigir `PK_ICC ≠ PK_IFD` (ICAO 9303-11) |
| P4 | claves privadas = 32 octetos aleatorios sin reducir mod n | inocuo | muestrear uniformemente en `[1, n−1]` |
| P5 | ignora las etiquetas `80/82/84/86` | tolerante | comprobar etiquetas; error claro si no cuadran |

### 4.5 Vector de prueba PACE verificado (ICAO Doc 9303-11, ejemplo «PACE – Generic Mapping, ECDH»)

Valores **verificados por cálculo** (recomputados de extremo a extremo con un script independiente; todos
coinciden entre sí, incluidos los tokens CMAC). Su procedencia es el ejemplo trabajado de PACE ECDH-GM de ICAO
Doc 9303 parte 11 (apéndice de ejemplos; número exacto de apéndice/edición: **VERIFICAR**). La contraseña es una
MRZ, no un CAN:

```
MRZ_info  = "T22000129364081251010318"
K         = SHA-1(MRZ_info)                      = 7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD
K_π       = SHA-1(K ‖ 00000003)[0..16]           = 89DED1B26624EC1E634C1989302849DD
z         = 95A3A016522EE98D01E76CB6B98B42C3
s         = AES-Dec(K_π, z)                      = 3F00C4D39D153F2B2A214A078D899B22
SK_map_IFD= 7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99
PK_map_IFD= X 7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E
            Y 544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D
SK_map_ICC= 498FF49756F2DC1587840041839A85982BE7761D14715FB091EFA7BCE9058560
PK_map_ICC= X 824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57
            Y 30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54
H         = X 60332EF2450B5D247EF6D3868397D398852ED6E8CAF6FFEEF6BF85CA57057FD5
            Y 0840CA7415BAF3E43BD414D35AA4608B93A2CAF3A4E3EA4E82C9C13D03EB7181
G'        = X 8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2
            Y 8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522
SK_IFD    = A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595
PK_IFD    = X 2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C
            Y 3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462
SK_ICC    = 107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A
PK_ICC    = X 9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB
            Y 7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094
K         = 28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925
K_enc     = F5F0E35C0D7161EE6724EE513A0D9A7F
K_mac     = FE251C7858B356B24514B3BD5F4297D1
T_IFD     = C2B0BD78D94BA866      (CMAC sobre 7F494F060A04007F00070202040202864104‖PK_ICC)
T_ICC     = 3ABB9674BCE93C08      (CMAC sobre 7F494F060A04007F00070202040202864104‖PK_IFD)
```

### 4.6 Vector sintético con CAN en formato JMulticard (determinista)

Mismas claves efímeras y mismo `s` que §4.5, pero contraseña **CAN = "123456"** (de ahí `z` distinto) y las APDU
**exactamente como las construye JMulticard** (CLA, ausencia de Le, parámetro `84 01 0D`). Generado con el script
de referencia validado en §4.5. Nótese que `K_π("123456") = 591468CDA83D65219CCCB8560233600F` coincide con el `sk`
que aparece comentado en `jse/test/.../TestPaceDnie.testAesDec`, lo que confirma la KDF del CAN.

```
K_π           = 591468CDA83D65219CCCB8560233600F
→ MSE:SET AT  = 0022C1A412800A04007F0007020204020283010284010D            ← 9000
→ GA1         = 10860000027C00
← GA1 resp    = 7C12801084EBAB7F2DE981C6FA6922A691AE0911 9000           (z = 84EB…0911)
→ GA2         = 10860000457C438141047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E
                544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D
← GA2 resp    = 7C43824104824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57
                30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54 9000
→ GA3         = 10860000457C438341042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C
                3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462
← GA3 resp    = 7C438441049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB
                7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094 9000
→ GA4         = 008600000C7C0A8508C2B0BD78D94BA866
← GA4 resp    = 7C0A86083ABB9674BCE93C08 9000
K_enc = F5F0E35C0D7161EE6724EE513A0D9A7F   K_mac = FE251C7858B356B24514B3BD5F4297D1   SSC = 00×16
```
(Como `s` y las claves efímeras son las del ejemplo ICAO, `H`, `G'`, `K`, las claves y los tokens coinciden con
§4.5; lo único que cambia con el CAN es `K_π` y `z`.)

**Rust:** la implementación debe permitir inyectar el RNG (trait `PaceRng`) para reproducir este vector en un test.

---

## 5. Mensajería segura PACE (AES) — `core/connection/pace/SecureMessaging`, `PaceConnection`

### 5.1 Estado

`K_enc` (16), `K_mac` (16), `SSC` (16 octetos, big-endian, inicial `00…00`). Incremento: `SSC += 1` módulo 2¹²⁸
(si desborda, todo a cero) **antes** de proteger cada comando y **antes** de desproteger cada respuesta
(`incrementAtIndex`). Primer comando protegido → SSC = 1; su respuesta → SSC = 2.

### 5.2 Protección de un comando (`SecureMessaging.wrap`)

1. `SSC += 1`.
2. `hdr = CLA|0x0C ‖ INS ‖ P1 ‖ P2` (de los 4 primeros octetos del comando en claro; p. ej. `00→0C`, `90→9C`).
3. Caso ISO del comando en claro (`getAPDUStructure`, mirando `capdu.getBytes()`):
   - 4 octetos → caso 1; 5 → caso 2 (solo Le); `5+Lc` con Lc≠0 → caso 3; `6+Lc` con Lc≠0 → caso 4; otros
     (extendidos) → 5/6/7 sin DO (no ocurren).
4. Si caso 3 o 4: `DO87 = 87 L 01 ‖ AES-128-CBC(K_enc, IV, pad(datos))` con `IV = AES-128-ECB(K_enc, SSC)` y
   `pad` = ISO/IEC 9797-1 método 2 (`80 00…` hasta múltiplo de 16, **siempre** se añade al menos `80`).
   Longitud codificada con `Tlv` (`L` corto < 128, `81 L` < 256, `82 LL LL`).
5. Si caso 2 o 4: `DO97 = 97 01 Le` (Le de 1 octeto; Le = 256 se codifica `00`).
6. MAC (`buildDO8E` + `getMac`):
   - si hay DO87 o DO97: `M = pad(hdr) ‖ DO87 ‖ DO97`;
   - si no (caso 1): `M = hdr` **sin rellenar** (**Quirk P6**, ver abajo);
   - `N = pad(SSC ‖ M)`; `MAC = AES-CMAC(K_mac, N)[0..8]` (CMAC de 64 bits de Bouncy Castle = CMAC truncado).
7. `DO8E = 8E 08 ‖ MAC`.
8. APDU protegida: `hdr ‖ Lc ‖ DO87 ‖ DO97 ‖ DO8E ‖ 00` — **siempre** con `Le = 00` final y `Lc` de un octeto
   (si el cuerpo superase 255 octetos el `Lc` se desbordaría; no ocurre porque los datos en claro bajo PACE nunca
   pasan de 210 octetos).

**Quirk P6 (caso 1):** ICAO 9303-11 calcula `N = pad(SSC ‖ pad(hdr))`; JMulticard usa `N = pad(SSC ‖ hdr)`.
Comprobado con las clases Java compiladas: con las claves de §4.6 y SSC = 8, el comando `00 44 00 00` se protege
como `0C4400000A8E08AAAD79CE7FBB6E5200` (MAC JMulticard `AAAD79CE7FBB6E52`; el MAC ICAO sería `7BC479A4BC349468`).
En el flujo de firma del DNIe **no se envía ningún comando de caso 1 bajo PACE**, así que el quirk no tiene efecto
observable. **Rust:** implementar la variante ICAO; dejar un test que documente la diferencia.

### 5.3 Desprotección de una respuesta (`PaceConnection.transmit` + `SecureMessaging.unwrap`)

1. Se envía la APDU protegida por la conexión cruda.
2. **Si la SW externa no es `9000` ni `6282` → `ApduConnectionException("Error transmitiendo la APDU cifrada…")`**
   (no se desprotege; el SSC queda incrementado solo una vez → contexto inutilizable; ver §5.5).
3. `SSC += 1`.
4. Recorre los datos como secuencia de TLV (`Tlv`, etiqueta de 1 octeto): `87` → DO87, `99` → DO99, `8E` → DO8E,
   otras → aviso y se ignoran. Si falta DO99 o DO8E → `SecureMessagingException`.
5. `CC = AES-CMAC(K_mac, pad(SSC ‖ DO87_codificado ‖ DO99_codificado))[0..8]` y se compara con el valor de DO8E
   (`Arrays.equals`, no constante en tiempo). Distinto → `SecureMessagingException("Checksum incorrecto…")`.
6. Si hay DO87: `datos = unpad(AES-128-CBC-Decrypt(K_enc, IV = AES-ECB(K_enc, SSC), valor_DO87[1..]))`
   (relleno ISO 7816-4 retirado por `ISO7816d4Padding` de BC; si está mal → excepción). Respuesta en claro =
   `datos ‖ valor_DO99` (la SW interna); si no hay DO87, solo `valor_DO99`.
7. Si la SW interna es `6688` → `InvalidCryptographicChecksumException` (`SecurityException`, no comprobada).
8. Si la SW interna es `6C xx` → se repite el **comando en claro** con `Le = xx` (nuevo wrap, SSC sigue avanzando).
9. Se devuelve la respuesta en claro.

### 5.4 Vectores de mensajería segura AES (verificados)

a) **Del propio JMulticard** (`jse/test/.../TestApduEncrypter`, test activo `testPartialEncryptionAes` y test
desactivado `testCMacGeneration`, que usan exactamente el cifrado/MAC de PACE):
```
K_enc = F1B0D6449CEC48864C1EFABB4957D64B   K_mac = 1665A3ADCB579053CC5D908720CE4DC1
SSC (ya incrementado) = 3DE0C9658F836888BD352DBF46462F60
comando en claro: 00 A4 04 00 0B 4D61737465722E46696C65   ("Master.File")
pad(datos)       = 4D61737465722E46696C658000000000
AES-CBC(IV=E(SSC)) = F5124EE2F53962E86E66A6D234827F0F
MAC              = 70E6DE5F679AEE64
APDU PACE (formato JMulticard, con Le=00 final):
  0CA404001D 871101F5124EE2F53962E86E66A6D234827F0F 8E0870E6DE5F679AEE64 00
```
(El test imprime la misma cadena sin el `00` final porque usa el formato CWA de JMulticard.)

b) **Continuación del vector §4.6** (K_enc/K_mac de PACE, SSC inicial 0). Generado con el script de referencia y
**comprobado byte a byte** contra `SecureMessaging.wrap/unwrap` de JMulticard compilado:
```
SELECT MF  (SSC=1) → 0CA404001D8711011D75C8363A14ACA516C1DE24B08357668E0847E2D5CE090F139600
           (SSC=2) ← 990290008E08BEA7B381C494A079 9000                        → en claro: 9000
SELECT 0006(SSC=3) → 0CA400001D871101EDF0D12A625FDCC8BAAFFF47F06BFFB58E085423DE9AFCFE57A400
           (SSC=4) ← 871101DC00E0BE4FD2B2585F464E60FE835AB1 99029000 8E08457F9F7BD3C1BA11 9000
                                                                              → en claro: 6F048102000A 9000
READ BINARY Le=0A (SSC=5) → 0CB000000D97010A8E082BBCA7B0F1532FDB00
           (SSC=6) ← 871101D76C448EFA497EEAE097326CB7DF137E 99029000 8E084D849DFCF0B2CCB5 9000
                                                                              → en claro: "BMP100002\0" 9000
READ BINARY Le=DE (SSC=7) → 0CB000000D9701DE8E08764D4C914F41831000   (19 octetos; respuesta de 222 datos = 244 octetos)
```

### 5.5 Errores, desincronización y recuperación

- JMulticard **no resincroniza** nunca el SSC. Cualquier error de transporte o de SM deja el canal inservible y
  la operación falla hacia arriba como `ApduConnectionException` / `SecureMessagingException` envuelta.
- La tarjeta, ante un error de SM (`6987` objetos SM ausentes, `6988` objetos SM incorrectos), aborta la sesión
  (ICAO 9303-11); JMulticard **aprovecha** esto para «resetear» tras cada firma (§9.4).
- `LostChannelException` se captura en `Dnie.signOperation`/`changePIN` para reintentar, pero **nunca se lanza**
  en el código actual (código muerto).
- **Rust:** ante cualquier error de SM, marcar la sesión como `Broken` y reabrir desde PACE (el CAN está en
  memoria) **una sola vez**; si vuelve a fallar, propagar. Nunca reintentar `VERIFY` automáticamente (gastaría
  intentos de PIN).

---

## 6. Canal seguro CWA-14890 del DNIe (dentro de PACE)

Sí: además de PACE, el DNIe 3.0/4.0 exige el **canal seguro CWA-14890** («canal de PIN» y «canal de usuario») para
verificar el PIN y para firmar. Es una autenticación mutua de dispositivos (CWA 14890-1, *device authentication
with key transport*) con certificados *Card Verifiable* (CV), RSA-1024 «crudo» con formato ISO 9796-2 y SIGMIN.
Implementación: `core/connection/cwa14890/Cwa14890OneV1Connection` (lógica), `Cwa14890OneV2Connection` (MAC de 8
octetos), `core/card/dnie/Dnie` (comandos), `Dnie3` (canales PIN/usuario), constantes en `core/card/dnie/Dnie3*Cwa14890Constants`.

### 6.1 Roles y constantes

| Constante | Significado | Valor |
|---|---|---|
| `REF_C_CV_CA_PUBLIC_KEY` | referencia de la clave pública raíz de la jerarquía CV (pk-RCA-AUT) en la tarjeta | `02 0F` |
| `REF_ICC_PRIVATE_KEY` | referencia de la clave privada de componente (sk-ICC-AUT) | `02 1F` |
| `C_CV_CA` | certificado CV de la CA intermedia de terminal (c-CV-CA-CS-AUT), 210 octetos | `7F21 81CE {5F37 81 80 firma(128), 5F38 3D resto(61), 42 08 CAR}` |
| `CHR_C_CV_CA` | CHR de esa CA (8 octetos) | r1 `6573534449600006`, r2 `6573534449620018` |
| `C_CV_IFD` | certificado CV del terminal (c-CV-IFD-AUT), 209 octetos | `7F21 81CD {5F37 81 80 firma(128), 5F38 3C resto(60), 42 08 CAR=CHR_C_CV_CA}` |
| `CHR_C_CV_IFD` | CHR / número de serie del terminal (sn-IFD), 8 octetos | ver tabla 6.2 |
| `IFD_PRIVATE_KEY` | clave privada RSA-1024 del terminal (n, d; e = 65537 embebido al final de `5F38`) | ver apéndice A |
| `getIfdKeyLength()` | longitud de la clave del terminal en octetos | `128` |
| `CA_COMPONENT_PUBLIC_KEY` | clave pública de la CA de componentes (RSA-1024, 162 octetos SPKI) | **no se usa** (ver Quirk C1) |

Las claves privadas del terminal y los certificados CV son **públicos**: están en el código fuente de JMulticard
(publicado por la Administración bajo LGPL/EUPL, §15). Hay cuatro terminales: {PIN, usuario} × {r1, r2}.

### 6.2 Elección del juego de constantes por IDESP (`DnieFactory.getDnie3PinCwa14890Constants/…Usr…`)

`Dnie3.<init>` lee el IDESP (`Dnie.getIdesp()` = `new String(contenido de 3F00/0006)`, codificación por defecto ⇒
ASCII; **sin recortar**, puede incluir NUL o espacios finales: **VERIFICAR** el contenido real). Si falla, `idesp = null`.

```
si idesp nulo o vacío           → r2 (con aviso)
si "BMP100001".compareTo(idesp) > 0  (idesp < "BMP100001" lexicográfico UTF-16) → r1
si no                            → r2
```

| Juego | Canal | Clase | `CHR_C_CV_IFD` | `C_CV_CA` usada |
|---|---|---|---|---|
| r1 | PIN | `Dnie3PinCwa14890Constants` | `4000000000000001` | `Dnie3r1Cwa14890Constants.C_CV_CA` (CHR `6573534449600006`) |
| r1 | usuario | `Dnie3UsrCwa14890Constants` | `2000000000000001` | idem r1 |
| r2 | PIN | `Dnie3r2PinCwa14890Constants` | `D002E00000000004` | `Dnie3r2Cwa14890Constants.C_CV_CA` (CHR `6573534449620018`) |
| r2 | usuario | `Dnie3r2UsrCwa14890Constants` | `D002E00000000002` | idem r2 |

(Las clases `DnieCwa14890Constants`, del DNIe 2.0 por contacto, no intervienen en NFC.)

**Rust:** `fn cwa_set(idesp: Option<&str>) -> CwaSet` con la misma comparación (sobre la cadena tal cual; comparar
como bytes ASCII equivale a `String.compareTo` para ASCII). Las constantes se generan como `const` desde los
ficheros Java con un script (apéndice A da longitudes y SHA-256 para validarlas).

### 6.3 Handshake (`Cwa14890OneV1Connection.open`)

Todas estas APDU se envían por la conexión **actual de la tarjeta** (SM-PACE para el canal de PIN; SM-CWA-PIN para
el canal de usuario). `Dnie3.openPinChannel` / `openUserChannel` hacen además un `SELECT MF` por esa conexión
**antes** de `open()` (en el canal de usuario, si falla, `CryptoCardException`; en el de PIN solo se registra).

| # | Operación (método) | APDU en claro (antes de SM) | Respuesta esperada |
|---|---|---|---|
| 0 | `subConnection.open()` | — | — |
| 1 | número de serie (`Dnie.getSerialNumber`) | `90 B8 00 00 07` (GET CHIP INFO, CLA propietaria `90`) | 7 octetos `SN` + `9000`; si no `9000` → `ApduConnectionException` |
| 2 | `card.verifyIcc()` | — (**no hace nada**, Quirk C1) | — |
| 3 | clave pública de componente (`Dnie.getIccCertPublicKey`) | `SELECT MF` (por nombre) ; `00 A4 00 00 02 60 1F` ; `READ BINARY` hasta la longitud del FCI | X.509 DER del certificado de componente; se extrae la clave RSA (exige módulo ≥ 128 octetos y exponente ≥ 3 octetos, `BcCryptoHelper.CustomRsaPublicKey`) |
| 4 | cadena del terminal (`Dnie.verifyIfdCertificateChain`) | a) `00 22 81 B6 04 83 02 02 0F` (MSE:SET DST-verificación, clave raíz) b) `00 2A 00 AE D2 ‖ C_CV_CA(210)` (PSO:VERIFY CERTIFICATE) c) `00 22 81 B6 0A 83 08 ‖ CHR_C_CV_CA` d) `00 2A 00 AE D1 ‖ C_CV_IFD(209)` | `9000` en cada una; si no → `SecureChannelException` |
| 5 | autenticación interna (`internalAuthentication`) | a) `00 22 C1 A4 12 83 0C 00000000 ‖ CHR_C_CV_IFD(8) 84 02 02 1F` (MSE:SET AT; la referencia pública se rellena con ceros a la izquierda hasta 12) b) `00 88 00 00 10 ‖ RND.IFD(8) ‖ CHR_C_CV_IFD(8)` (INTERNAL AUTHENTICATE, **sin Le**) | a) `9000` b) 128 octetos + `9000` |
| 6 | reto (`getChallenge`) | `00 84 00 00 08` (GET CHALLENGE) | `RND.ICC`(8) + `9000` |
| 7 | autenticación externa (`externalAuthentication`) | `00 82 00 00 80 ‖ datos(128)` (EXTERNAL AUTHENTICATE, sin Le) | `9000` (si no → `SecureChannelException`) |
| 8 | derivación de claves | — | — |

`RND.IFD`, `PRND2` y `K.IFD` salen de `BcCryptoHelper.generateRandomBytes`, que usa
`new DigestRandomGenerator(new SHA1Digest())` **sin semilla** (Quirk C2).

**Paso 5 — validación de la respuesta de INTERNAL AUTHENTICATE** (`internalAuthValidateInternalAuthenticateMessage`):
```
sigmin = (resp ^ d_IFD) mod n_IFD                  // "descifrar" con la privada del terminal
m      = (sigmin ^ e_ICC) mod n_ICC                // como 128 octetos big-endian
si m[0] != 6A o m[127] != BC:
    m = ((n_ICC − sigmin) ^ e_ICC) mod n_ICC       // SIG era N.ICC − SIGMIN
    si sigue sin ser 6A…BC → SecureChannelException
m = 6A ‖ PRND1(74) ‖ K.ICC(32) ‖ h(20) ‖ BC
comprobar h == SHA-1(PRND1 ‖ K.ICC ‖ RND.IFD ‖ CHR_C_CV_IFD(8))   si no → SecureChannelException
```
(74 = 128 − 32 − 20 − 2.) **Quirk C3:** al copiar `N.ICC − SIGMIN` a un búfer de 128 octetos, un valor de menos de 128
octetos se alinearía a la **izquierda** (error); en la práctica no ocurre porque SIGMIN ≤ N/2 implica
N.ICC − SIGMIN > N/2 ≥ 2¹⁰²², que siempre ocupa 128 octetos. **Rust:** operar con enteros.

**Paso 7 — construcción de EXTERNAL AUTHENTICATE:**
```
PRND2 = aleatorio(74) ; K.IFD = aleatorio(32)
h     = SHA-1(PRND2 ‖ K.IFD ‖ RND.ICC ‖ SN.ICC)        // SN.ICC = serie de 7 octetos con un 00 a la izquierda → 8
msg   = 6A ‖ PRND2 ‖ K.IFD ‖ h ‖ BC                    // 128 octetos
sig   = (msg ^ d_IFD) mod n_IFD
sigmin= min(sig, n_IFD − sig)
datos = (sigmin ^ e_ICC) mod n_ICC                     // 128 octetos big-endian
```

**Paso 8 — claves de sesión** (`generateKenc`, `generateKmac`, `generateSsc`):
```
K_IFD/ICC = K.ICC XOR K.IFD                           (32 octetos)
K_enc = SHA-1(K_IFD/ICC ‖ 00 00 00 01)[0..16]
K_mac = SHA-1(K_IFD/ICC ‖ 00 00 00 02)[0..16]
SSC   = RND.ICC[4..8] ‖ RND.IFD[4..8]                (8 octetos)
```
Vector de la propia batería de JMulticard (`TestKeyGeneration`): `K.IFD = D8E25F213F58A31F38316AA922C48A93BAA93C8B1F7A1851D0EB746059B613FD`,
`K.ICC = 5AEF062AFD9F0DBAC9113A9E6D7AB288CC4E455DAA098DB8D18C8237E7726788` → XOR =
`820D590BC2C7AEA5F12050374FBE381B76E779D6B57395E90167F657BEC47475` (el test calcula después las claves con SHA-256;
el código de producción usa **SHA-1**).

### 6.4 Mensajería segura CWA (3DES) — `AbstractApduEncrypter`, `ApduEncrypterDes`, `ApduEncrypterDesMac8`

Estado: `K_enc`, `K_mac` (16 octetos, clave 3DES de dos claves K1‖K2 → K1‖K2‖K1), `SSC` (8 octetos).
`Cwa14890OneV1Connection.transmit`: `SSC += 1` antes de proteger y `SSC += 1` antes de desproteger
(`increment`: módulo 2⁶⁴ manteniendo 8 octetos).

**Protección (`protectAPDU`):**
```
cla' = CLA | 0x0C
DO87 = 87 L 01 ‖ 3DES-CBC(K_enc, IV = 00×8, pad8(datos))     si hay datos (getData() no vacío)
DO97 = 97 01 Le                                              si Le != null (Le de 1 octeto)
MAC  = retail-MAC(K_mac, SSC, pad8( pad8(cla' INS P1 P2) ‖ DO87 ‖ DO97 ))[0..8]
APDU = cla' INS P1 P2 Lc ‖ DO87 ‖ DO97 ‖ 8E 08 ‖ MAC          ← SIN Le final
```
`retail-MAC` (ISO/IEC 9797-1 algoritmo 3, DES, IV 0) aplicado sobre `SSC ‖ datos_rellenos`:
`t = DES_K1(SSC)`; para cada bloque excepto el último `t = DES_K1(t ⊕ Bi)`; final
`3DES_{K1K2K1}(t ⊕ B_last)`. `pad8` = ISO 9797-1 método 2. El MAC es de **8 octetos** en CWA v2
(`ApduEncrypterDesMac8`, usado por `Cwa14890OneV2Connection`); la v1 (DNIe 2.0) usa 4.
Los datos en claro se sobrescriben con ceros tras cifrar (`wipeByteArray`).

**Desprotección (`ApduEncrypterDes.decryptResponseApdu`):**
1. Si la SW externa no es `9000` → se devuelve **solo esa SW** sin verificar nada (el SSC ya se incrementó).
2. Leer en orden: DO87 opcional (`87`), DO99 (`99`), DO8E (`8E`) con `BerTlv` (longitudes 81/82 soportadas;
   **Quirk C4:** una longitud exactamente 128 se trata como indefinida; no ocurre porque DO87 siempre es impar).
   Falta DO8E o DO99 → `SecureChannelException`.
3. MAC esperado = retail-MAC(K_mac, SSC, pad8(DO87_codificado ‖ DO99_codificado)); distinto →
   `InvalidCryptographicChecksumException`.
4. Datos = `unpad(3DES-CBC-Decrypt(K_enc, IV 0, valor_DO87[1..]))`; respuesta = datos ‖ valor_DO99.
   (`removePadding7816`: si el último octeto no nulo no es `80`, considera que no había relleno.)

`Cwa14890OneV1Connection.transmit`, tras desproteger:
- SW externa `6688` (antes de desproteger) → `InvalidCryptographicChecksumException`.
- SW interna `6C xx` → reenviar el comando en claro con `Le = xx` (recursivo).
- SW interna `62 xx` → reenviar con `Le = Le − 1` (`MSB_INCORRECT_LE_PACE`; recursivo; **Quirk C5:** si el
  comando no tenía Le → `NullPointerException`). Pensado para lecturas que sobrepasan el fin de fichero.
- Cualquier excepción al desproteger → `ApduConnectionException("Error en la desencriptacion…")`.

**Vectores verificados** (de `jse/test/.../TestApduEncrypter`, recomputados en Python y con las clases Java):
```
K_enc = 598F26E36E11A8EC14B81E19BDA223CA   K_mac = 5DE2939A1EA03A930B88206D8F73E8A7
VERIFY "CRYPTOKI", SSC=D31AC8EC7BA0FE6F, MAC 4 (v1):
  0C20000019 871101CE1AB937C332F3FAEE43336D4311EF33 8E046908DF4E          (test testPinEncryptionDes)
idem con MAC 8 (v2, el del DNIe 3/4):
  0C2000001D 871101CE1AB937C332F3FAEE43336D4311EF33 8E086908DF4E6EB3CEAE
SELECT "Master.File", SSC=D31AC8EC7BA0FE75, MAC 4:
  0CA4040019 8711013E9AC315A8E855DD3722F291078AC2BD 8E04B6F56963          (test testEncryptionDes)
GET RETRIES (00 20 00 00, Le=00), SSC=D31AC8EC7BA0FE70, MAC 8:
  0C2000000D 970100 8E08BE9DF8CB9EC57B9D
MSE:SET DST (00 22 41 B6 04 84020102), SSC=D31AC8EC7BA0FE72, MAC 8:
  0C2241B615 870901E09FC9BCFA520CF8 8E08FF5D2104F58149D1
```
Y el ejemplo de SM 3DES de ICAO 9303-11 (BAC, `SELECT EF.COM`), que usa el mismo cifrado y MAC (**verificado**):
```
KS_enc = 979EC13B1CBFE9DCD01AB0FED307EAE5  KS_mac = F1CB1F1FB5ADF208806B89DC579DC1F8
SSC = 887022120C06C227, comando 00 A4 02 0C 02 011E
  → 0CA4020C15 8709016375432908C044F6 8E08BF8B92D635FF24F8   (ICAO añade un 00 final; JMulticard no)
respuesta 99029000 8E08FA855A5D4C50A8ED con SSC = 887022120C06C228 (MAC verificado)
```

### 6.5 Los dos canales del DNIe 3/4 (`Dnie3`)

| Canal | Constantes | Se establece por | Tráfico posterior | Para qué |
|---|---|---|---|---|
| PIN (`ChannelType.CWA_PIN`) | `Dnie3[r2]PinCwa14890Constants` | SM-PACE | SM-CWA-PIN sobre NFC crudo | consultar intentos y `VERIFY` |
| usuario (`ChannelType.CWA_USER`) | `Dnie3[r2]UsrCwa14890Constants` | SM-CWA-PIN | SM-CWA-USR sobre NFC crudo | `MSE:SET DST` + `PSO:CDS` (y descifrado RSA) |

`Dnie3.openSecureChannelIfNotAlreadyOpened(doChv=true)`:
1. Si ya hay canal CWA abierto (`isSecurityChannelOpen`: conexión actual es `Cwa14890Connection`, abierta y **no**
   `PaceConnection`) → nada.
2. Si la conexión actual está cerrada → `setConnection(rawConnection)` (= la `PaceConnection`).
3. `openPinChannel()`; `verifyPin(getInternalPasswordCallback())` (§8); si no hay forma de pedir el PIN
   (`PasswordCallbackNotFoundException`) se continúa sin verificar.
4. `openUserChannel()`.

### 6.6 Quirks del canal CWA

| # | Java | Rust |
|---|---|---|
| C1 | `Dnie.verifyIcc()` vacío: **no se valida** el certificado de componente (601F) contra `CA_COMPONENT_PUBLIC_KEY` | paridad: no rechazar; opcional (mejora): verificar la firma del certificado con esa clave y registrar el resultado como aviso (**VERIFICAR** que esa CA firma los certificados de componente de DNIe 3/4) |
| C2 | `generateRandomBytes` crea en **cada llamada** un `DigestRandomGenerator` SHA-1 **sin semilla**, así que siempre devuelve el mismo prefijo de la misma secuencia (comprobado en dos JVM distintas): 8 octetos → `6C5544797A91115D`; 32 octetos → `6C5544797A91115DC3330EBD003851D239A706FF2AA2AB70039C5510DDF06420`. Por tanto RND.IFD, K.IFD (que empieza por RND.IFD) y PRND2 son **constantes** en ambos canales y en todas las sesiones; la única entropía de las claves CWA es K.ICC/RND.ICC de la tarjeta | usar un CSPRNG (`OsRng`). Ventaja para pruebas: el oráculo Java es determinista en esta parte (§14) |
| C3 | alineación a la izquierda de `N.ICC − SIGMIN` (inalcanzable) | enteros |
| C4 | `BerTlv` longitud 128 = indefinida | parser correcto |
| C5 | reintento `62xx` con NPE si no hay Le | reintentar solo si hay Le |
| C6 | `Cwa14890OneV1Connection.open()` cierra la subconexión (`conn.close()`) ante cualquier fallo de las etapas 1–7 → en NFC cierra `IsoDep` | cerrar la sesión y devolver error tipado |

---

## 7. Sistema de ficheros y lectura de certificados

### 7.1 Ficheros usados

| Ruta | Contenido | Lectura | Fuente |
|---|---|---|---|
| MF | seleccionado **por nombre** `"Master.File"` (`00 A4 04 00 0B 4D61737465722E46696C65`, sin Le) | — | `Dnie.selectMasterFile` |
| `3F00/0006` | IDESP (texto) | bajo PACE | `Dnie.IDESP_LOCATION` |
| `3F00/601F` | certificado X.509 de componente (sin comprimir) | bajo el SM activo, en cada handshake CWA | `Dnie.CERT_ICC_FILE_ID` |
| `3F00/5015/6004` | CDF PKCS#15 | bajo PACE | `Dnie.CDF_LOCATION` |
| `3F00/5015/6001` | PrKDF PKCS#15 | bajo PACE | `Dnie.PRKDF_LOCATION` |
| rutas del CDF | certificados comprimidos (espécimen: `6061/7001` autenticación, `6061/7002` firma, `6061/7003` CA intermedia) | bajo PACE | CDF |
| rutas del PrKDF | claves privadas (espécimen: `3F11/0101` autenticación, `3F11/0102` firma) | no se leen; el último FID se usa en `MSE:SET DST` | PrKDF |
| `3F00/0000` | fichero de PIN (solo `changePIN`, no usado) | — | `Dnie.changePIN` |
| `011C`, `2F01`, `2F00`, `3F01/01xx` | EF.CardAccess, ATR/INFO, DIR, DG ICAO | no usados para firmar | `MrtdLds1` |

Los valores del espécimen proceden de `core/test/resources/CDF_ESPECIMEN.ber` y `PRKDF_ESPECIMEN.ber` (DNIe 3.0
de pruebas «ESPECIMEN», emisor «AC DNIE 001»). **No** hay que fijar rutas en código: se leen del CDF/PrKDF.

### 7.2 Selección y lectura (`AbstractIso7816FourCard`)

- `Location("50156004")` → lista de FID de 2 octetos, **eliminando `3F00`** si aparece; `selectFileByLocation`
  hace `SELECT MF` (por nombre) y luego `00 A4 00 00 02 FID` por cada elemento.
- `selectFileById`: `6A82` → `FileNotFoundException`; `6982` → `RequiredSecurityStateNotSatisfiedException`;
  otra SW ≠ `9000` → `Iso7816FourCardException`.
- Longitud del fichero desde el FCI (`SelectFileApduResponse.decode`): requiere `datos[0] = 6F` y
  `datos[1] == len(datos) − 2`; si `datos[2] == 81` → longitud = `datos[3]` octetos siguientes (2 en la práctica);
  luego busca `81` (identificador, **Quirk:** debería ser `83`), `84` (nombre DF) y el propietario FNMT `85 0A`
  (FID en `+3`, tamaño en `+5`). Sin FCI o sin `81` → longitud 0 (y la lectura devuelve vacío).
  **Quirk:** tras el TLV `81` debe haber al menos un octeto más dentro del FCI; si el FCI termina justo ahí
  `decode()` lanza `ArrayIndexOutOfBoundsException` (comprobado en el simulador).
  **Rust:** parsear el FCI como TLV y aceptar `80` o `81` para el tamaño; **VERIFICAR** el FCI real del DNIe.
- `readBinaryComplete(len)`: bloques de **`0xDE` = 222** octetos (`MAX_READ_CHUNK`; garantiza que la respuesta
  bajo PACE quepa en 256: `87 81 E1 01 ‖ 224 ‖ 99 02 SW ‖ 8E 08 MAC ‖ SW` = 244 octetos), comando
  `00 B0 offHi offLo Le` con `Le = min(222, len−off)`; `6B00` → devuelve lo leído; `6982` → `IOException`;
  `6282` → aviso, añade los datos y termina; otra SW → `IOException`.

### 7.3 CDF (`core/asn1/der/pkcs15/Cdf`)

`Record` de hasta 10 `CertificateObject` **concatenados** (no hay SEQUENCE exterior; el fichero puede tener
relleno `00` al final: el parser se detiene en el primer elemento que no decodifica y los opcionales se saltan).
Estructura de cada objeto (PKCS#15 `CertificateObject{X509CertificateAttributes}`):
```
30 {                                   -- PKCS15Object
  30 { 0C label(UTF8)  [03 flags]  [04 authId] }      -- CommonObjectAttributes  → alias = label
  30 { 04 iD }                                         -- CommonCertificateAttributes → ID (se enlaza con el PrKDF)
  A1 { 30 {                                            -- [1] X509CertificateAttributes
         30 { 04 path  [02 index]  [80 length] }       -- Path → ruta del fichero (hex)
         [30 subject Name]  [A0 issuer Name]  [02 serialNumber] } }
}
```
Espécimen (verificado parseando el fichero):

| label (alias) | iD (ASCII) | path | longitud |
|---|---|---|---|
| `CertAutenticacion` | `A02034674163C2020160830144606` (29 oct.) | `60617001` | `0548` |
| `CertFirmaDigital` | `F02034674163C2020160830144606` | `60617002` | `0542` |
| `CertCAIntermediaDGP` | `S02034674163C2020160830144606` | `60617003` | `0550` |

(iD en hex, p. ej. `4130323033343637343136334332303230313630383330313434363036`; el primer carácter A/F/S
distingue autenticación, firma y CA. El enlace certificado↔clave se hace comparando el iD en hex en mayúsculas.)

### 7.4 PrKDF (`PrKdf`, con alternativa `CeresScPrKdf`)

`Record` de hasta 10 `PrivateKeyObject{PrivateRSAKeyAttributes}`:
```
30 {
  30 { 0C label  03 flags }                                -- CommonObjectAttributes
  30 { 04 iD  03 usage  [01 native]  03 accessFlags  02 keyReference }   -- CommonKeyAttributes
  [A0 CommonPrivateKeyAttributes]                          -- opcional (ausente en DNIe)
  A1 { 30 { 30 { 04 path  02 index  80 length }  02 modulusLength } }   -- [1] PrivateRSAKeyAttributes
}
```
Espécimen: `KprivAutenticacion` (iD `A0…06`, usage `063000`, keyReference `01`, path `3F110101`, 2048 bits) y
`KprivFirmaDigital` (iD `F0…06`, usage `063040` = sign + signRecover + **nonRepudiation**, keyReference `02`,
path `3F110102`, 2048 bits). En autenticación, usage `063000` = sign + signRecover. Si `PrKdf` falla al decodificar se reintenta con `CeresScPrKdf` (`CommonPrivateKeyAttributes` vacío).
`getKeyReference()` = último octeto del INTEGER.

### 7.5 Certificados comprimidos (`core/card/CompressionUtils.getCertificateFromCompressedOrNotData`)

```
si len(datos) < 1 → IOException
intentar: Inflater (zlib, con cabecera) sobre datos[8..]   // los 8 primeros octetos se ignoran
          bucle inflate; si devuelve 0 octetos sin terminar → DataFormatException
si falla: usar los datos tal cual (certificado sin comprimir)
X.509 = CertificateFactory("X.509").generateCertificate(resultado)
```
La cabecera de 8 octetos se interpreta habitualmente como longitud descomprimida + longitud comprimida
(2 × uint32 LE): **VERIFICAR**; JMulticard no la usa. **Rust:** `flate2::read::ZlibDecoder` sobre `[8..]`;
si falla, intentar DER directo; validar que el resultado es un único `Certificate` DER sin octetos sobrantes.

### 7.6 Carga y alias (`Dnie.loadCertificates`, ejecutado en el constructor)

1. `needsPinForLoadingCerts()` es `false` en `Dnie3` (true solo en DNIe 1.0) → no se abre CWA ni se pide PIN.
2. `SELECT MF`; leer CDF; para cada entrada `i`: leer `path_i`, descomprimir, `certs[label_i] = cert`,
   `aliasById[hex(iD_i)] = label_i`.
3. Leer PrKDF; para cada clave `j`: `alias = aliasById[hex(iD_j)]`; si existe →
   `keyRefs[alias] = DniePrivateKeyReference(card, iD_j, Location(path_j), label_j, keyReference_j, bitLength(módulo del certificado))`.
4. `aliases = keys(certs)` (`HashSet`) y `hideCertsWithoutKey()` quita los alias sin clave (la CA intermedia).
   **Quirk:** se borra de un `HashSet` mientras se itera; no lanza `ConcurrentModificationException` solo porque
   `CertCAIntermediaDGP` cae en el último cubo (cubos 4, 5 y 6 de 16). Orden resultante de `aliases()`:
   `CertAutenticacion`, `CertFirmaDigital`.
5. Cualquier excepción → `ApduConnectionException("Error cargando las estructuras iniciales de la tarjeta")`.

Después (`Dnie3.<init>`) se lee el IDESP (§6.2).

### 7.7 Cadena de certificados (`jse/provider/DnieKeyStoreImpl.engineGetCertificateChain`)

`[cert(alias), CertCAIntermediaDGP (si existe)]` y, si hay intermedia, una raíz embebida que la verifique:
primero `ACRAIZ-SHA2-2.crt` (CN=AC RAIZ DNIE 2, SHA-256
`C5C380EB9240FB36A16E15F5D6BAD0BF611F6D03F0EF24229919E7D2D8126C11`), si no `ACRAIZ-SHA2.crt` (CN=AC RAIZ DNIE,
SHA-256 `F5792110817A86D4FE244AC2A8B10B5B0BF4CE8626661AB984470A87879830F5`); si ninguna verifica, sin raíz.
**Rust:** incluir ambas raíces como recursos (`include_bytes!`) y replicar la lógica.

`DniePrivateKey` (JCA): algoritmo `RSA`, `getModulus()` del certificado, sin codificación; el proveedor ofrece
`SHA1withRSA`, `SHA256withRSA`, `SHA384withRSA`, `SHA512withRSA` (y alias OID) y, fuera de JVM Oracle,
`Cipher RSA/ECB/PKCS1Padding` (descifrado con la clave de la tarjeta, no usado al firmar).

---

## 8. PIN

### 8.1 Intentos restantes (`Dnie.getPinRetriesLeft`, sobre el canal de PIN)

`RetriesLeftApduCommand` = `00 20 00 00` con `Le = 00` y sin datos (en claro: `0020000000`). Protegido por CWA:
`0C 20 00 00 0D 97 01 00 8E 08 MAC` (18 octetos).
```
si SW == 6982 → ApduConnectionException
intentos = (byte)SW2 − (byte)0xC0       // con 63 C3 → 3; con 90 00 → 64 (!)
```
`Dnie3.getPinRetriesLeft` exige que la conexión actual sea `Cwa14890OneV2Connection` con tipo `CWA_PIN` (si es
`CWA_USER` abre antes el canal de PIN; si es PACE → error).

**Quirk:** cualquier SW se interpreta como `63Cx`; `9000` daría 64. Si la SW interna llega como SW externa sin SM
(rama 1 de §6.4), también se interpreta. **Rust:** aceptar `63Cx` → `x`; `9000` → «desconocido/ya verificado»;
otras → error. **VERIFICAR** con tarjeta real cómo responde el DNIe (SW interna `63Cx` con SW externa `9000`, o
SW externa `63Cx` sin objetos SM).

### 8.2 Petición del PIN (`Dnie.getInternalPasswordCallback`)

1. `intentos = getPinRetriesLeft()`; error → `PinException("No se ha podido obtener el numero de intentos restantes de PIN")`.
2. `intentos == 0` → `AuthenticationModeLockedException` (sin VERIFY).
3. Si la tarjeta tiene un `PasswordCallback` fijo (`setPasswordCallback`/`KeyStore.PasswordProtection`) → ese.
4. Si tiene `CallbackHandler` → `CardWithRetriesPasswordCallback(prompt, echo=false)` con
   `prompt = "Por favor, introduzca el PIN del DNIe.\nIntentos restantes: <n>"` (`CardMessages "Dnie.0"`) y
   `setRetriesLeft(n)`; `handle()`; `IOException`/`UnsupportedCallbackException` →
   `PasswordCallbackNotFoundException`; PIN nulo o vacío → `BadPinException("El PIN no puede ser nulo ni vacio")`.
5. Si no hay ninguno → `PasswordCallbackNotFoundException` (el canal de usuario se abre igualmente sin PIN y la
   firma fallará en la tarjeta).

### 8.3 VERIFY (`Dnie.verifyPin`, `core/apdu/dnie/VerifyApduCommand`)

En claro: `00 20 00 00 Lc ‖ PIN` donde **PIN = cada `char` convertido a `(byte)`** (ASCII/Latin-1 truncado, sin
relleno ni formato), y el `char[]` del callback se sobrescribe con `\0` tras leerlo. (Los octetos de
`getBytes()` del objeto llevan un marcador `01 00`; el PIN real solo existe al cifrar, vía `getData()`.)
Bajo CWA: `0C 20 00 00 Lc 87 L 01 ‖ 3DES(pad8(PIN)) 8E 08 MAC`.

| SW (en claro, tras CWA) | Excepción |
|---|---|
| `9000` | — |
| `63 Cx` | `BadPinException(x)` («PIN incorrecto, intentos restantes: x»; `(byte)SW2 − (byte)0xC0`) |
| `69 83` | `AuthenticationModeLockedException` |
| `00 00` | `ApduConnectionException("Se ha perdido el canal NFC")` |
| otra | `ApduConnectionException(Iso7816FourCardException("Error en la verificacion de PIN (…)"))` |

Reglas de longitud: JMulticard no impone ninguna; la app Android exige ≥ 4; el diálogo de escritorio 4–16 (05 §3.7.4).
Longitud real admitida por el DNIe: 8–16 caracteres (**VERIFICAR**; el modo consola de escritorio exige 8–16).
Un PIN de 4–7 caracteres, que la app Android acepta, llegaría a la tarjeta y previsiblemente gastaría un intento
(**VERIFICAR**); **Rust:** validar 8–16 antes de enviar si se confirma.
**Rust:** PIN como `Zeroizing<Vec<u8>>`; rechazar caracteres no ASCII imprimibles antes de enviar (evita gastar un
intento por un carácter que se truncaría distinto).

**Nunca** se reintenta VERIFY automáticamente: un PIN incorrecto termina la operación (`BadPinException` →
`SignatureAuthException` en `DnieSignatureImpl.engineSign`). **Quirk:** tras un `BadPinException` el canal de PIN
queda abierto; si se vuelve a firmar con el **mismo** objeto `Dnie`, `isSecurityChannelOpen()` es `true`, no se pide
PIN y se envían `MSE:SET DST` + `PSO:CDS` por el canal de PIN → `6982` → `DnieCardException` (comprobado en el
simulador). La app nunca lo hace (reinicia todo el flujo NFC). **Rust:** tras `WrongPin`, cerrar la sesión.

---

## 9. Firma

### 9.1 Claves «firma» y «autenticación»

| Alias (label CDF) | Clave (label PrKDF) | FID clave (espécimen) | keyReference | Uso | Uso en firma-android |
|---|---|---|---|---|---|
| `CertAutenticacion` | `KprivAutenticacion` | `0101` | `01` | autenticación de cliente (TLS), CN «… (AUTENTICACIÓN)», usage sign+signRecover | no |
| `CertFirmaDigital` | `KprivFirmaDigital` | `0102` | `02` | firma electrónica (no repudio), CN «… (FIRMA)», usage + nonRepudiation | **sí, siempre** (`SelectAliasDialog.signWithSignCertificate`) |

Ambas son RSA-2048 (longitud tomada del módulo del certificado, `DniePrivateKeyReference.keySize`) y ambas se usan
con el mismo PIN y el mismo procedimiento. JMulticard 2.1 **no** pide confirmación adicional para la clave de firma.

### 9.2 Flujo JCA (`jse/provider/DnieSignatureImpl`)

- `engineInitSign(DniePrivateKey)`; `engineUpdate` acumula los datos **sin resumir**.
- `engineSign()`: comprueba que la tarjeta es `Dni` (si no, `ProviderException`); crea un
  `DniePrivateKeyReference` y llama a `card.sign(datos, "SHA256withRSA"…, ref)`.
  `CryptoCardException` → `SignatureException`; `PinException` → `SignatureAuthException(e)` (de ahí la cadena
  `AOException → AOException → SignatureAuthException → BadPinException` que inspecciona la app).
- `engineInitVerify` delega en otro proveedor que no sea `DNIeJCAProvider`/`SunMSCAPI`/`Ceres430JCAProvider`/PKCS#11.

### 9.3 Operación en la tarjeta (`Dnie.signOperation`)

1. `openSecureChannelIfNotAlreadyOpened()` (en `DnieNfc`: PACE si hace falta, §9.4; luego canal de PIN + VERIFY +
   canal de usuario, §6.5).
2. **MSE:SET DST** (`MseSetComputationApduCommand`, sin referencia de algoritmo):
   ```
   00 22 41 B6 04  84 02 ‖ FID   // FID = último elemento de la ruta de la clave del PrKDF (01 02 para firma)
   ```
   SW ≠ `9000` → `DnieCardException("Error en el establecimiento de las clave de firma con respuesta: <SW>")`.
3. `DigestInfo.encode(alg, datos)`: normaliza el nombre (`SHA1`/`SHA-1`/`SHA`/`SHAwithRSA`/`SHA-1withRSA`/
   `SHA1withRSAEncryption`/… → `SHA1withRSA`, ídem 256/384/512; otro → `IllegalStateException`), resume en el host y
   antepone la cabecera DER fija:

   | Hash | Cabecera `DigestInfo` | Total |
   |---|---|---|
   | SHA-1 | `3021300906052B0E03021A05000414` | 35 |
   | SHA-256 | `3031300D060960864801650304020105000420` | 51 |
   | SHA-384 | `3041300D060960864801650304020205000430` | 67 |
   | SHA-512 | `3051300D060960864801650304020305000440` | 83 |
4. **PSO:COMPUTE DIGITAL SIGNATURE** (`PsoSignHashApduCommand`, **sin Le**):
   ```
   00 2A 9E 9A Lc ‖ DigestInfo
   ```
   La tarjeta aplica PKCS#1 v1.5 (tipo 01) y devuelve la firma RSA de 256 octetos. SW ≠ `9000` → se registra la
   respuesta completa y `DnieCardException("Error durante la operacion de firma con respuesta: <SW>")`.
5. `LostChannelException` → cerrar, bajar a la subconexión y reintentar recursivamente (código muerto, §5.5).
6. Devuelve `res.getData()` (la firma, sin verificar en la tarjeta; el firmante de AutoFirma la verifica después
   con la clave pública del certificado).

**Rust:** `SigningKey::sign(data, alg)` → `digest` → `DigestInfo` → APDU; verificar la firma con la clave pública del
certificado antes de devolverla (AutoFirma ya lo hace en `AOPkcs1Signer`, 05 §5.2).

### 9.4 Después de cada firma: «reset» y nueva sesión (`DnieNfc.sign`, `resetCard`)

```
firma = signInternal(...)
setConnection(getConnection().getSubConnection())   // canal de usuario → conexión NFC cruda (sin SM)
selectMasterFile()  en claro: 00 A4 04 00 0B 4D61737465722E46696C65
    → la tarjeta responde con error de SM (el comentario del código dice «69 87») y descarta su contexto SM
    → la excepción se registra («Paso de canal seguro a no seguro al reiniciar») y se ignora
return firma
```
Consecuencia: en la **siguiente** firma `DnieNfc.openSecureChannelIfNotAlreadyOpened` ve que la conexión actual no
es `Cwa14890Connection` y **reabre PACE** con el CAN guardado en estático (`getPaceConnection(con, pch)`), sin volver
a leer certificados, y después canal de PIN, petición de PIN (el `CallbackHandler` vuelve a ser invocado), VERIFY,
canal de usuario y firma. Esto es lo que ocurre en la firma por lotes (`SignBatchTask`): N firmas = N × (PACE + CWA
PIN + VERIFY + CWA usuario + firma). Cada firma cuesta ≈ 40 APDU (§11.3).

**Rust:** reproducir la semántica («una sesión SM por firma»). Mejora opcional (no paridad, **VERIFICAR** con
tarjeta): mantener el canal de usuario abierto entre firmas de un mismo lote. El DNIe puede exigir PIN por firma
para la clave de firma; no asumirlo sin probar.

### 9.5 Otras operaciones disponibles (no usadas al firmar)

- `Dnie.cipherData` (descifrado RSA con la clave privada, `jse/provider/rsacipher/DnieCipherImpl`): `LoadDataApduCommand` +
  `SignDataApduCommand(keyReference, keyBitSize)` bajo el canal de usuario.
- `Dnie.changePIN`: `SELECT MF`, `SELECT 0000`, `ChangePinApduCommand` (requiere canal administrativo; no usado).
- `Dnie3.checkSecurityObjects`, `getDg1…getDg14`, `getSod` (lectura ICAO bajo PACE; DG3/DG4 requieren canal
  administrativo).

---

## 10. Interacción con la interfaz (CAN, PIN, confirmación)

### 10.1 Lo que pide JMulticard 2.1

| Momento | Callback | Prompt | Respuesta esperada |
|---|---|---|---|
| construcción de `DnieNfc` (una vez por sesión de tarjeta) | `TextInputCallback` (JRE) o `CustomTextInputCallback` (Android) | «Por favor, introduzca el CAN o la MRZ del documento de identidad» | texto CAN; vacío → `InvalidCanOrMrzException` |
| cada apertura de canal con PIN (es decir, **cada firma**) | `CardWithRetriesPasswordCallback` (subclase de `PasswordCallback`, `echoOn=false`, `getRetriesLeft()`) | «Por favor, introduzca el PIN del DNIe.\nIntentos restantes: n» | `char[]` del PIN; vacío → `BadPinException` |
| — | `CustomAuthorizeCallback` (confirmación de firma) | **nunca se emite** en JMulticard 2.1 (el manejador Android lo acepta y lo ignora; el de escritorio de AutoFirma lo muestra, ver 05 §3.7.4) | — |

`KeyStore.PasswordProtection` / `CachePasswordCallback` fijan un PIN que se usará sin preguntar
(`Dnie.setPasswordCallback`). `AbstractJMultiCardKeyStore.engineGetEntry(alias, CallbackHandlerProtection)` cambia el
`CallbackHandler` de la tarjeta; con `null` (lo que hace la app) mantiene el del `load()`.

### 10.2 Lo que hace la app Android (pantallas y textos completos en 09 §4.9)

- CAN y PIN se piden **antes** de leer la tarjeta y se responden desde memoria (`CachePasswordCallback`), sin
  diálogos durante la operación NFC. El PIN se reutiliza en cada firma del lote.
- `DnieConnectionManager` (singleton) guarda CAN, PIN, `Tag`, conexión y manejador; `reset()` cierra la conexión
  pero conserva el CAN («se interpreta que se desea seguir usando el mismo DNIe»); `clearCan()`/`clearPin()` los
  borran (tras CAN incorrecto o cancelación del detector).
- Mensajes (es): título paso 1 «Introduzca el CAN del DNI», ayuda «El CAN es un número situado en la parte inferior
  derecha del DNI. Es necesario para la lectura del DNI con NFC.»; accesibilidad «…El código CAN contiene seis
  dígitos y se puede encontrar en la esquina inferior derecha del anverso de su DNI.»; detector «Acerque su
  dispositivo al DNIe» / «Coloque el dispositivo sobre el DNIe y no lo mueva durante la operación de firma»;
  progreso `dialog_msg_loading_keystore`, `loading_certs`, `signing`.

### 10.3 Rust

```rust
pub trait DnieInteraction: Send + Sync {
    /// Una vez por sesión de tarjeta. Devuelve el CAN (solo dígitos). Err(Cancelled) si el usuario cancela.
    fn request_can(&self) -> Result<Zeroizing<String>, Cancelled>;
    /// Antes de cada VERIFY. `retries_left` = valor leído de la tarjeta.
    fn request_pin(&self, retries_left: u8) -> Result<Zeroizing<String>, Cancelled>;
    /// Opcional (paridad escritorio): confirmar uso de la clave de firma.
    fn confirm_signature(&self) -> Result<bool, Cancelled> { Ok(true) }
}
```
El CAN se guarda en la sesión (zeroize al soltarla) para reabrir PACE entre firmas. La caché de PIN de una hora y la
confirmación son responsabilidad de la capa de interfaz (05 §3.7.5), no del controlador. En escritorio (lector sin
contacto) la petición de CAN debe reutilizar el diálogo de AutoFirma descrito en 05 §3.7.4 («DNI Electrónico:
Introducción de CAN», «Por favor, introduzca el CAN del DNIe», imagen `can_example.png`; cerrar la ventana devuelve
un CAN vacío, que aquí produce `InvalidCanOrMrzException` → «CAN incorrecto»), y la de PIN el diálogo de PIN de DNIe
con «Intentos restantes».

---

## 11. Secuencia completa de APDU de una sesión

Notación: «claro» = APDU antes de proteger; «aire» = longitud total enviada por NFC; capa = contexto SM activo
(§0.2). Las longitudes «aire» son exactas (calculadas y observadas en el simulador, §14.3). `n` = número de lecturas
de 222 octetos según el tamaño de cada fichero.

### 11.1 Fase A — detección y PACE (5 APDU, en claro)

| # | Claro = aire | Aire | Respuesta |
|---|---|---|---|
| — | `reset()`: históricos/HLR (Android) o pseudo-ATR (PC/SC) → `DnieNfc`; petición del CAN | — | — |
| A1 | `00 22 C1 A4 12 80 0A 04007F00070202040202 83 01 02 84 01 0D` | 23 | `9000` |
| A2 | `10 86 00 00 02 7C 00` | 7 | `7C 12 80 10 z(16) 9000` (22) |
| A3 | `10 86 00 00 45 7C 43 81 41 04 X Y` | 74 | `7C 43 82 41 04 X Y 9000` (71) |
| A4 | `10 86 00 00 45 7C 43 83 41 04 X Y` | 74 | `7C 43 84 41 04 X Y 9000` (71) |
| A5 | `00 86 00 00 0C 7C 0A 85 08 T_IFD` | 17 | `7C 0A 86 08 T_ICC 9000` (14) |

Ejemplo completo con bytes: §4.6.

### 11.2 Fase B — carga de certificados (bajo SM-PACE; constructor `Dnie` + `Dnie3`)

| Paso | Claro | Aire | Respuesta en aire |
|---|---|---|---|
| B1 | `00 A4 04 00 0B 4D61737465722E46696C65` (SELECT MF; `loadCertificates`) | 35 | 16 (`99 02 9000 8E 08 … 9000`) |
| B2 | SELECT MF (inicio de `selectFileByLocation`) | 35 | 16 |
| B3 | `00 A4 00 00 02 50 15` | 35 | 35 con FCI de ≤ 15 octetos (`87 11 01 ‖16 ‖ 99 02 ‖ 8E 08 ‖ 9000`) |
| B4 | `00 A4 00 00 02 60 04` | 35 | idem |
| B5 | `00 B0 hi lo Le` × n (CDF; Le = 0xDE salvo el último) | 19 | 244 por bloque completo |
| B6 | por cada certificado del CDF: SELECT MF, `00 A4 00 00 02 60 61`, `00 A4 00 00 02 70 0x`, READ × n | 35/35/35/19 | — |
| B7 | SELECT MF, SELECT `5015`, SELECT `6001`, READ × n (PrKDF) | — | — |
| B8 | SELECT MF, SELECT `0006`, READ (IDESP, `Dnie3.<init>`) | — | — |

Con los ficheros del espécimen (CDF y PrKDF de 2100 octetos, certificados de ~740 octetos comprimidos en el
simulador) la carga son **56 APDU** (5 PACE + 51 bajo PACE). Con tamaños reales (certificados de ~1350 octetos
comprimidos) serán unas 65.

### 11.3 Fase C — primera firma (`DnieNfc.sign`)

Canal de PIN, handshake bajo **SM-PACE** (`Dnie3.openPinChannel` + `Cwa14890OneV1Connection.open`):

| # | Claro | Aire | Resp. aire |
|---|---|---|---|
| C1 | SELECT MF (antes de `open`) | 35 | 16 |
| C2 | `90 B8 00 00 07` (GET CHIP INFO; en aire CLA `9C`) | 19 | 35 |
| C3 | SELECT MF; `00 A4 00 00 02 60 1F`; READ × n (certificado de componente) | 35/35/19 | 16/35/244 |
| C4 | `00 22 81 B6 04 83 02 02 0F` | 35 | 16 |
| C5 | `00 2A 00 AE D2 ‖ C_CV_CA` | **244** | 16 |
| C6 | `00 22 81 B6 0A 83 08 ‖ CHR_C_CV_CA` | 35 | 16 |
| C7 | `00 2A 00 AE D1 ‖ C_CV_IFD` | **244** | 16 |
| C8 | `00 22 C1 A4 12 83 0C 00000000 ‖ CHR_C_CV_IFD 84 02 02 1F` | 51 | 16 |
| C9 | `00 88 00 00 10 ‖ RND.IFD ‖ CHR_C_CV_IFD` | 51 | 164 |
| C10 | `00 84 00 00 08` | 19 | 35 |
| C11 | `00 82 00 00 80 ‖ datos(128)` | 164 | 16 |

PIN, bajo **SM-CWA-PIN** (sin PACE):

| # | Claro | Aire | Resp. aire |
|---|---|---|---|
| C12 | `00 20 00 00 00` (intentos) → `0C 20 00 00 0D 97 01 00 8E 08 MAC` | 18 | 16 (`99 02 63 Cx 8E 08 … 9000`) |
| — | callback de PIN («Intentos restantes: x») | — | — |
| C13 | `00 20 00 00 Lc PIN` → `0C 20 00 00 Lc 87 L 01 ‖ 3DES ‖ 8E 08 MAC` | 34 (PIN ≤ 7 caracteres: 26; 8–15: 34; 16: 42) | 16 |

Canal de usuario, handshake bajo **SM-CWA-PIN**: C1–C11 de nuevo con las constantes de usuario
(longitudes en aire: SELECT MF 34, GET CHIP INFO 18 → resp. 27, SELECT FID 26, READ 18 → 244, MSE 26/34,
PSO VERIFY **235**, MSE:SET AT 42, INTERNAL AUTH 42 → resp. 156, GET CHALLENGE 18 → 35, EXTERNAL AUTH 155).

Firma, bajo **SM-CWA-USR**:

| # | Claro | Aire | Resp. aire |
|---|---|---|---|
| C14 | `00 22 41 B6 04 84 02 01 02` | 26 | 16 |
| C15 | `00 2A 9E 9A 33 ‖ DigestInfo-SHA256(51)` (SHA-512: Lc `53`, aire 106) | 74 | **285** (`87 82 01 09 01 ‖ 264 ‖ 99 02 9000 ‖ 8E 08 ‖ 9000`) |
| C16 | `00 A4 04 00 0B 4D61737465722E46696C65` **en claro** | 16 | `6987` (esperado) |

Total observado: **35 APDU** en la primera firma (con un certificado de componente de 3 bloques).

### 11.4 Fase D — firmas siguientes

PACE (A1–A5) + C1–C16 sin la fase B: **40 APDU** por firma. La petición de CAN no se repite; la de PIN sí.

### 11.5 Tamaños límite

- Mayor C-APDU: 244 octetos (PSO:VERIFY CERTIFICATE bajo PACE). El camino `90 C2` (troceado > 255) no se usa.
- Mayor R-APDU: 285 octetos (firma bajo CWA). El transporte debe aceptar respuestas > 258 octetos (o `61xx` + GET
  RESPONSE en claro, que JMulticard también soporta).
- Ninguna APDU usa longitud extendida.

---

## 12. DNIe 3.0 frente a 4.0, y contacto frente a NFC

| Aspecto | DNIe 3.0 | DNIe 4.0 | Fuente |
|---|---|---|---|
| Detección NFC | `ATR_NFC` / `ATR_NFC2` / HLR vacío | igual | §3 |
| Clase JMulticard | `DnieNfc` | `DnieNfc` | `DnieFactory` |
| PACE | ECDH-GM, brainpoolP256r1, AES-128 | igual (fijado en código) | §4 |
| Constantes CWA | r1 si IDESP < `BMP100001`, si no r2 | previsiblemente r2 (**VERIFICAR**) | §6.2 |
| Ficheros y rutas | según CDF/PrKDF | según CDF/PrKDF (**VERIFICAR** rutas reales) | §7 |
| Claves | RSA-2048 | RSA-2048 (**VERIFICAR**) | longitud tomada del certificado |
| Raíz | AC RAIZ DNIE / AC RAIZ DNIE 2 | AC RAIZ DNIE 2 (**VERIFICAR**) | §7.7 |

Por **contacto** (`Dnie3` creado por `DnieFactory` con el ATR `3B7F…6A444E4965…9000` y `byte[15] = 04`) el flujo es
el mismo **sin PACE**: la carga de certificados va en claro, el canal de PIN se negocia en claro y el resto es
idéntico; tras la firma `Dnie.sign` simplemente cierra el canal (`getConnection().close()`), sin el `SELECT` de
reinicio. El DNIe 2.0 (`Dnie`, CWA v1 con `DnieCwa14890Constants` y MAC de 4 octetos, PIN obligatorio para leer
certificados solo en DNIe 1.0) queda fuera de este documento.

---

## 13. Diseño propuesto para Rust

### 13.1 Ubicación

Nuevo crate `crates/afirma-dnie` (sin E/S propia salvo los transportes opcionales) consumido por
`afirma-keystores` como un *backend* más («DNIe por NFC / lector sin contacto»). Hoy `docs/PARITY.md` marca el
controlador JMulticard como sustituido por los módulos PKCS#11 del DNIe/OpenSC; este crate añade la vía sin
contacto y, opcionalmente, la de contacto (misma lógica sin PACE).

```
afirma-dnie/
  src/apdu.rs        CommandApdu/ResponseApdu (codificación exacta §2.4), StatusWord
  src/transport.rs   trait ApduTransport + lógica común (61xx, 6Cxx en claro, troceado 90 C2)
  src/transport/pcsc.rs     (feature "pcsc")   lector sin contacto de escritorio
  src/transport/sim.rs      (cfg(test) / feature "sim")  simulador de tarjeta (§14.3)
  src/atr.rs         patrones y máscaras, comparación por sufijo, pseudo-ATR desde NfcB
  src/ec.rs          brainpoolP256r1 (crate bp256 con aritmética, o primeorder con parámetros RFC 5639)
  src/pace.rs        protocolo PACE (§4), RNG inyectable
  src/sm/pace.rs     SM AES (§5)        src/sm/cwa.rs   SM 3DES (§6.4)
  src/cwa.rs         handshake CWA-14890 (§6.3), RSA «crudo» con BigUint
  src/consts.rs      constantes CWA r1/r2 generadas (apéndice A), raíces DNIe (include_bytes!)
  src/fs.rs          SELECT/READ, FCI, Location
  src/pkcs15.rs      CDF/PrKDF (crate der o parser propio tolerante al relleno 00)
  src/certs.rs       descompresión zlib + X.509
  src/session.rs     DnieNfcSession: máquina de estados
  src/error.rs       errores tipados (§1.1)
```

### 13.2 Interfaces

```rust
pub trait ApduTransport {
    /// Envía una APDU completa y devuelve datos‖SW1‖SW2. Sin reintentos ni GET RESPONSE (los hace la capa común).
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError>;
    /// Identificación SIN efectos secundarios (nunca reinicia la tarjeta): históricos/HLR o pseudo-ATR.
    fn identification(&mut self) -> Result<Vec<u8>, TransportError>;
    fn max_apdu_len(&self) -> usize { 255 }
}

enum SmContext { Plain, Pace(PaceSm), CwaPin(CwaSm), CwaUser(CwaSm), Broken }

pub struct DnieNfcSession<T: ApduTransport> {
    transport: T, ctx: SmContext, can: Zeroizing<String>, idesp: Option<String>,
    cwa_set: CwaSet, objects: Vec<CardKeyPair>, rng: Box<dyn CryptoRngCore + Send>,
}
impl<T: ApduTransport> DnieNfcSession<T> {
    pub fn open(transport: T, ui: &dyn DnieInteraction) -> Result<Self, DnieError>;   // §3, §4, §7
    pub fn key_pairs(&self) -> &[CardKeyPair];          // alias, certificado DER, FID de clave, bits
    pub fn chain(&self, alias: &str) -> Vec<Vec<u8>>;   // §7.7
    pub fn sign(&mut self, alias: &str, alg: DigestAlg, data: &[u8], ui: &dyn DnieInteraction)
        -> Result<Vec<u8>, DnieError>;                  // §6.5, §8, §9 (incluye el SELECT de reinicio)
}
```

`send(cmd)`: según `ctx` → `Plain` tal cual; `Pace` → `wrap` / comprobar SW externa (`9000` o `6282`) / `unwrap` /
`6688` / reintento `6Cxx`; `Cwa*` → `protect` / SW externa `6688` → error / si SW externa ≠ `9000` devolver la SW
sin verificar (paridad, §6.4) / `unprotect` / reintentos `6Cxx` y `62xx` (este último solo con Le).
Establecer canal CWA = ejecutar el handshake con `send()` y, si termina bien, `ctx = CwaPin(nuevo)` o `CwaUser(nuevo)`.

### 13.3 Dependencias sugeridas

| Uso | Crate | Nota |
|---|---|---|
| brainpoolP256r1 | `bp256` (feature `arithmetic`) | **VERIFICAR** que la versión publicada incluya aritmética; si no, `primeorder` + parámetros §4.1 (o aritmética propia con `crypto-bigint`; son 4 multiplicaciones escalares por sesión) |
| AES, CBC, CMAC | `aes`, `cbc`, `cmac` | CMAC truncado a 8 octetos |
| 3DES, MAC retail | `des` (ya en el *workspace*), `cbc`; MAC retail implementado a mano (10 líneas) | ISO 9797-1 alg. 3 con SSC delante |
| SHA-1/2 | `sha1`, `sha2` (ya en el *workspace*) | |
| RSA «crudo» | `num-bigint` o `rsa::BigUint` (`modpow`) | claves del terminal son públicas: no hace falta tiempo constante |
| zlib | `flate2` (ya en el *workspace*) | |
| X.509 | `x509-parser` (ya en el *workspace*) | |
| Secretos | `zeroize` | CAN, PIN, claves de sesión |
| PC/SC | `pcsc` | feature opcional |

### 13.4 Decisiones de paridad

- **Reproducir:** APDU byte a byte (incluidas las ausencias de Le, el `Le = 00` final de SM-PACE, la falta de Le
  en SM-CWA, CLA `10` en GA1–GA3), orden de comandos (incluidos los `SELECT MF` duplicados), troceo `0xDE`, elección
  r1/r2 por IDESP, «reset» con `SELECT` en claro y re-PACE por firma, textos de prompts.
- **No reproducir (corregir):** P1 (X de longitud fija), P2–P5 (validaciones), P6 (MAC caso 1 ICAO), C2 (RNG
  real), C3–C5, `setLe` sin Lc, interpretación de `9000` como 64 intentos, FCI rígido.

---

## 14. Estrategia de pruebas

### 14.1 Vectores disponibles sin conexión

| Vector | Dónde | Estado |
|---|---|---|
| PACE ECDH-GM brainpoolP256r1 AES-128 completo (MRZ) | §4.5 (ICAO 9303-11, ejemplo trabajado) | **verificado por cálculo** de extremo a extremo; procedencia exacta (apéndice/edición): VERIFICAR |
| PACE con CAN en formato JMulticard | §4.6 | generado con el script de referencia; `K_π("123456")` coincide con `TestPaceDnie` |
| SM AES (cifrado de datos y MAC) | §5.4 a (de `TestApduEncrypter`) | verificado (Python y Java) |
| SM AES de una sesión (SELECT/READ y respuestas) | §5.4 b | verificado contra `SecureMessaging` compilado |
| MAC caso 1 (quirk) | §5.2 | verificado contra Java |
| SM 3DES CWA (VERIFY, SELECT, retries, MSE DST) | §6.4 (de `TestApduEncrypter`) | verificado (Python y Java) |
| SM 3DES ICAO (BAC, SELECT EF.COM) | §6.4 | verificado por cálculo |
| XOR K.IFD/K.ICC | §6.3 (`TestKeyGeneration`) | del test |
| `DigestInfo` | §9.3 | cabeceras DER estándar |
| CDF/PrKDF del espécimen | `core/test/resources/CDF_ESPECIMEN.ber`, `PRKDF_ESPECIMEN.ber` (2100 octetos, con relleno `00`) | copiar a `testdata/dnie/` (licencia §15) |
| Certificado de un DNIe | `core/test/resources/DNICERT.cer` (1608 octetos) | para pruebas de parseo/cadena |
| Raíces | `jse/main/resources/ACRAIZ-SHA2*.crt` | §7.7 |

No se conocen (ni se citan) vectores oficiales de **SM AES** de ICAO/BSI; los de esta tabla vienen de JMulticard o
se han generado y validado contra las clases Java.

### 14.2 Pruebas unitarias recomendadas (Rust)

1. `atr`: tabla de §3.2 (las 9 entradas comprobadas) + pseudo-ATR construido desde `appData`/`protInfo`.
2. `pace`: §4.5 (con contraseña MRZ ya derivada) y §4.6 inyectando el RNG; caso X con `00` inicial (forzar con un
   `SK_IFD` elegido) para comprobar la codificación de 32 octetos; rechazo de puntos fuera de curva y de `T_ICC`
   incorrecto.
3. `sm::pace`: §5.4 a/b, desbordamiento del SSC, relleno mal formado, DO8E ausente, SW externa `6982`.
4. `sm::cwa`: §6.4, respuesta sin DO99, MAC erróneo, DO87 de 265 octetos (longitud `82`).
5. `cwa`: handshake completo contra el simulador con las constantes r1 y r2; elección por IDESP (`AAA000001` → r1,
   `BMP100001` → r2, `BMP100000` → r1, vacío → r2).
6. `pkcs15`: espécimen → 3 certificados, 2 claves, alias y rutas de §7.3/§7.4; relleno final.
7. `certs`: cabecera de 8 octetos + zlib; certificado sin comprimir; datos corruptos.
8. `session`: transcripción completa contra el simulador comparada con un *golden* (§14.4).

### 14.3 Simulador de tarjeta

Se ha construido y ejecutado un simulador Java contra JMulticard 2.1 real (clases compiladas) que valida esta
especificación (fuera del repositorio, en el directorio temporal de la sesión de análisis). El simulador Rust
(`transport/sim.rs`) debe implementar el mismo modelo:

- **Estado:** `ctx ∈ {Plain, Pace(K,SSC16), Cwa(K,SSC8, canal)}`, fase PACE, retos pendientes, PIN, intentos (3),
  ficheros, claves.
- **Identificación:** devolver vacío (Android NfcB) o `3B888001E1F35E117781A10003` (PC/SC); configurable.
- **PACE (solo en `Plain`):** MSE:SET AT → `9000` (comprobar OID, `83 01 02`, `84 01 0D`); GA1 → `7C12 80 10 E(K_π,s)`;
  GA2 → mapear y devolver `7C43 82 41 PK_map_ICC`; GA3 → `7C43 84 41 PK_ICC`; GA4 → si `T_IFD` correcto, `7C0A 86 08 T_ICC`
  y activar `Pace`, si no `6300`. K con X de 32 octetos.
- **SM PACE (ICAO):** verificar MAC (variante ICAO), descifrar DO87, ejecutar el comando interno, envolver la
  respuesta con DO87/DO99/DO8E y SW externa `9000`. MAC erróneo → `6988` en claro y volver a `Plain`.
- **Comandos de ficheros:** SELECT por nombre `Master.File` → `9000` sin FCI; SELECT FID → FCI
  `6F 0B 81 02 tamaño 82 01 xx 83 02 FID` (al menos un octeto tras `81`, §7.2); READ BINARY con offset/Le.
- **CWA (bajo el contexto activo):** GET CHIP INFO (7 octetos), MSE `81 B6` y PSO VERIFY CERT (aceptar), MSE `C1 A4`
  (anotar CHR y referencia de clave para distinguir canal PIN/usuario), INTERNAL AUTHENTICATE (construir
  `6A‖PRND1‖K.ICC‖h‖BC`, firmar con la clave de componente, SIGMIN, cifrar con la pública del terminal),
  GET CHALLENGE, EXTERNAL AUTHENTICATE (verificar, derivar claves, **sustituir** el contexto por `Cwa`).
- **PIN (bajo CWA-PIN):** `00 20 00 00` + Le → `63 Cx` dentro de DO99 con SW externa `9000` (configurable a SW
  externa `63Cx`); VERIFY correcto → `9000`, incorrecto → `63 C(x−1)`, a 0 → `6983`.
- **Firma (bajo CWA-USR, tras VERIFY):** MSE:SET DST con `84 02 FID` → `9000`; PSO:CDS → PKCS#1 v1.5 con la clave
  de firma (RSA-2048) → 256 octetos; sin VERIFY previo → `6982`.
- **APDU en claro con SM activo** → `6987` y volver a `Plain` (es lo que provoca el «reset» de JMulticard).
- **Inyección de fallos:** CAN erróneo, PIN erróneo/bloqueado, pérdida del *tag* (error de transporte a mitad),
  MAC corrupto en respuesta, `61xx` en respuestas largas, `6Cxx`, sesiones con X de `K` empezando por `00`.
- **Datos:** CDF/PrKDF del espécimen; certificados y claves RSA de prueba generados (2048 usuario, 1024 componente);
  claves del terminal = las de JMulticard (`e = 65537`, al final de `5F38` de cada `C_CV_IFD`).

Resultados obtenidos con el simulador Java (base de varias afirmaciones de este documento): flujo completo con dos
firmas verificadas; capas de §0.2 confirmadas (nunca hay doble envoltura); longitudes de §11; 20/3000 fallos de PACE
y 15/3000 de firma por el defecto P1; RNG determinista C2; detección de §3.2; caso 1 rechazado por un verificador
ICAO (`6988`).

### 14.4 JMulticard como oráculo

- JMulticard **no** trae *mocks* ni simuladores: sus pruebas de tarjeta (`TestDnieLow`, `TestPaceDnie.main`,
  `TestIcao`…) están desactivadas («Necesita tarjeta»). Sí son reutilizables los vectores de `TestApduEncrypter` y
  `TestKeyGeneration`, y los ficheros de espécimen.
- **Compilación sin Maven (comprobada):** `javac -encoding UTF-8 -d classes` sobre
  `jmulticard/src/main/java` + `jmulticard-crypto/src/main/java` (1258 ficheros, incluye el subconjunto de Bouncy
  Castle; ≈ 5 s con JDK 21) y copiar `cardmessages.properties`. Con eso funcionan `DnieFactory`, `DnieNfc`,
  `BcCryptoHelper`, `SecureMessaging`, etc. (La copia de `BcPaceChannelHelper` de `jmulticard-crypto` fija SHA-1
  para K_enc/K_mac y la de `jmulticard-jse` usa el hash del `CardAccess`; para el DNIe ambos son SHA-1.)
- **Arnés propuesto (`tools/oracle/dnie/`, siguiendo el patrón de los oráculos existentes):** un `ApduConnection`
  Java que reenvía cada APDU por un socket TCP local al simulador Rust (o el simulador Java portado). Así el mismo
  simulador sirve a ambos lados y se comparan transcripciones.
- **Determinismo:** las claves efímeras de PACE usan `new SecureRandom()`; para transcripciones byte a byte, el
  arnés debe registrar en primera posición (`Security.insertProviderAt(…, 1)`) un proveedor con un `SecureRandom`
  determinista (**VERIFICAR** que `SecureRandom()` sin algoritmo lo elige; alternativa: comparar las APDU
  *desprotegidas* en el lado tarjeta). La parte CWA ya es determinista por C2 (`RND.IFD = 6C5544797A91115D`).
  El Rust inyecta el mismo flujo de aleatorios en sus pruebas de paridad (mismo `SK_map_IFD`, `SK_IFD`, `RND.IFD`,
  `PRND2`, `K.IFD`).
- **Comparación:** igualdad exacta de C-APDU en aire (con aleatorios inyectados) o, como mínimo, de la secuencia de
  APDU en claro, sus longitudes en aire y las SW.

### 14.5 Pruebas con tarjeta real (manuales, `#[ignore]`)

Con un DNIe 3.0 y un DNIe 4.0, en Android (si se porta) y en un lector PC/SC sin contacto:
detección (registrar históricos/HLR/pseudo-ATR y `appData`/`protInfo`); CAN correcto/incorrecto (SW de GA4);
lectura de CDF/PrKDF/certificados (rutas y tamaños reales, FCI real, cabecera de compresión); IDESP real; consulta
de intentos (forma de la respuesta); PIN correcto, incorrecto (no bajar de 2 intentos) y respuesta exacta;
firma SHA-256 y SHA-512 verificada; segunda firma; respuesta al `SELECT` en claro; retirar la tarjeta a mitad;
respuesta de 285 octetos o `61xx` según lector; tiempo total por firma.

---

## 15. Licencias

- **JMulticard:** las cabeceras de los fuentes (p. ej. `Dnie.java`) dicen «Copyright (C) 2012 Direccion General de
  Modernizacion Administrativa, Procedimientos e Impulso de la Administracion Electronica» y «licenciamiento dual
  (**LGPL 2.1+** o **EUPL 1.1+**)»; el `pom.xml` declara GPL-2.0 y EUPL-1.1 y como desarrolladores a la Agencia
  Estatal de Administración Digital y a Tomás García-Merás (autores en los fuentes: García-Merás, Carlos Gamuci,
  Sergio Martínez Rico, Alberto Martínez, Ignacio Marín…). No todos los ficheros llevan cabecera (144 de 268 en el
  núcleo).
  `jmulticard-crypto` incluye una copia parcial de **Bouncy Castle** (licencia de Bouncy Castle, tipo MIT).
- **AutoFirma-rs:** `GPL-2.0-or-later OR EUPL-1.1` (`Cargo.toml`), igual que Cliente @firma.
- **Compatibilidad:** un port a Rust es una obra derivada (traducción). LGPL-2.1+ permite redistribuir bajo
  GPL-2.0+ (cláusula 3 de la LGPL 2.1) y EUPL-1.1+ es directamente EUPL-1.1, así que el crate puede publicarse con la
  misma licencia dual que el resto del proyecto. Obligaciones: conservar los avisos de copyright y atribución
  (añadir JMulticard y Bouncy Castle, si se copiara código suyo, a `license/` y a la cabecera de los ficheros
  derivados), indicar que es una versión modificada y mantener el código fuente disponible.
- **Constantes** (certificados CV y claves privadas de los terminales PIN/usuario r1/r2, raíces DNIe): se copian
  literalmente del código de JMulticard y quedan bajo la misma licencia. Son claves de *terminal* publicadas por la
  propia Administración para cualquier aplicación; no se ha encontrado restricción adicional de uso
  (**VERIFICAR** con el responsable del proyecto si se quiere certeza jurídica).
- **Ficheros de espécimen** (`CDF_ESPECIMEN.ber`, `PRKDF_ESPECIMEN.ber`, `DNICERT.cer`): mismos términos que
  JMulticard; datos ficticios («ESPECIMEN»).
- **Vectores ICAO**: datos de una norma pública, usables como datos de prueba.
- Esto no es asesoramiento jurídico.

---

## 16. Riesgos principales del port

1. **Capas de SM** (§0.2): el detalle más fácil de equivocar; un port «lógico» que envuelva CWA dentro de PACE no
   funcionará. Mitigación: modelo explícito de contexto único + transcripción *golden*.
2. **Comportamiento real no observable sin tarjeta:** SW exactas (GA4 con CAN erróneo, intentos de PIN, respuesta
   al `SELECT` de reinicio), FCI real, cabecera de compresión, IDESP real, HLR en Android, rutas en DNIe 4.0. Todo
   marcado VERIFICAR; el simulador modela lo que JMulticard espera, no lo que hace la tarjeta.
3. **Respuesta de 285 octetos** en la firma: algunos lectores PC/SC/NFC limitan a 258; probar y soportar `61xx`.
4. **Reset en PC/SC** tras PACE (§2.2): no reproducir el `reset()` de JMulticard. En Android, las sondas de
   presencia del modo lector (`EXTRA_READER_PRESENCE_CHECK_DELAY`) en API < 28 (§2.1).
5. **brainpoolP256r1 en Rust:** soporte de aritmética en `bp256` incierto; plan B con `primeorder`.
6. **Defecto P1** (X sin longitud fija): corregirlo es obligatorio (si no, ≈ 0,6 % de fallos «CAN incorrecto»), pero
   implica que el Rust y el Java divergen en esas sesiones; los tests de paridad deben excluir esos casos.
7. **Gasto de intentos de PIN** en pruebas: nunca reintentar VERIFY automáticamente; las pruebas con tarjeta real
   deben vigilar el contador.
8. **Seguridad:** JMulticard no autentica la tarjeta en PACE (P2) ni valida el certificado de componente (C1) y su
   RNG CWA es constante (C2). Corregir P2/P3/C2 es seguro (no cambia lo que la tarjeta ve salvo los aleatorios).
9. **Versión:** la app declara JMulticard 2.0; el análisis es de 2.1 (diferencias no verificadas).
10. **Licencia/claves** (§15).

---

## 17. Apéndices

### Apéndice A — Constantes CWA a extraer (longitud y SHA-256 para validar la extracción)

Ficheros en `core/card/dnie/`. Los arrays son `byte[]` literales; `ifdModulus`/`ifdPrivateExponent` son
`new BigInteger(1, new byte[]{…})` (enteros sin signo big-endian de 128 octetos).

| Clase | Campo | Long. | Inicio…fin | SHA-256 |
|---|---|---|---|---|
| `Dnie3Cwa14890Constants` | `REF_C_CV_CA_PUBLIC_KEY` | 2 | `020F` | `58691fae609bc279e385057cde8bc1ac8d035264bc8e0f2bc9469b8548bc1e5d` |
| `Dnie3Cwa14890Constants` | `REF_ICC_PRIVATE_KEY` | 2 | `021F` | `a21b15937d09462bef92a1f7149400c0a067f30d85fb286fca412855d821a887` |
| `Dnie3Cwa14890Constants` | `CA_COMPONENT_PUBLIC_KEY.encoded` | 162 | `30819F300D06…0203010001` | `789c9238e9e03bbcede1bbd8c318dc1270efbb212ba0207b88e21000ddbfb34b` |
| `Dnie3r1Cwa14890Constants` | `C_CV_CA` | 210 | `7F2181CE5F378180…524449600006` | `7a11af8b21afdfc593266b62f1837e744119b6538b9e5472db3e55fe61e1afc7` |
| `Dnie3r1Cwa14890Constants` | `CHR_C_CV_CA` | 8 | `6573534449600006` | `8f8e54d21804ac8e377b462cf8edb70d2b017737590b9c12face38b78bfce771` |
| `Dnie3r2Cwa14890Constants` | `C_CV_CA` | 210 | `7F2181CE5F378180…524449620018` | `be18380faf8016d8b5a55b03cac343774462e1b021899378aa40be40d037af7b` |
| `Dnie3r2Cwa14890Constants` | `CHR_C_CV_CA` | 8 | `6573534449620018` | `012757f92ceb3b7d42c6bb4d770a89b1e3c7e3eb1e15cc786e97b72998e58045` |
| `Dnie3PinCwa14890Constants` | `C_CV_IFD` | 209 | `7F2181CD5F378180…534449600006` | `1fddaade5d2d859a9920c982b54d6840d99221ff22a5e2b9285c533848ed84fe` |
| `Dnie3PinCwa14890Constants` | `CHR_C_CV_IFD` | 8 | `4000000000000001` | `4319b7e1377c0d7b6b35f8172c3fd47254ed05d5bc81db26a791fc34ae932447` |
| `Dnie3PinCwa14890Constants` | `ifdModulus` | 128 | `F427978DA159…6A5A89AD58A5` | `53cfcd6284058e617903e26e3f4c2bc288e431fab4d770075e47559a016c6e4a` |
| `Dnie3PinCwa14890Constants` | `ifdPrivateExponent` | 128 | `D27A03237C72…358B7C115AA1` | `ea90c2d3004f45ae7a94acc8f1f87a21561920829a6ada85c6ee05ef7793c447` |
| `Dnie3UsrCwa14890Constants` | `C_CV_IFD` | 209 | `7F2181CD5F378180825B…534449600006` | `4ec82246e8e8754bd909d7c72447bf37bddb275eb6d35fcad57374b34e8227fb` |
| `Dnie3UsrCwa14890Constants` | `CHR_C_CV_IFD` | 8 | `2000000000000001` | `14346ad58419c0302a86aee319c3a95ac853b3e9775180ff9cf5ea1e73925e05` |
| `Dnie3UsrCwa14890Constants` | `ifdModulus` | 128 | `DB2CB41E112B…36590016BA69` | `0cabe4dd79037bc3935968882034f774d1ebadcf5fbea8923e4192b6084c991a` |
| `Dnie3UsrCwa14890Constants` | `ifdPrivateExponent` | 128 | `18B44A3D155C…00313C0F46ED` | `c22b6257ac263cd01f702f0b19ad4618bdb60234e4a3f7f1045f3ada7f3a37d1` |
| `Dnie3r2PinCwa14890Constants` | `C_CV_IFD` | 209 | `7F2181CD5F3781800A3D…534449620018` | `1e9632d74a828612cb6a59870a48260c079e76ba226716fc5d44ec222d88eab6` |
| `Dnie3r2PinCwa14890Constants` | `CHR_C_CV_IFD` | 8 | `D002E00000000004` | `b71691d7a270afd667d4c16b4662ddad3d75730d87493a454bcf66663a9d5c28` |
| `Dnie3r2PinCwa14890Constants` | `ifdModulus` | 128 | `DF03930D4F1D…D29FC7C99D8B` | `e4f064176f4c7ecc1152973623a5a7edee655e4e6c478bb3937e2397c507a2df` |
| `Dnie3r2PinCwa14890Constants` | `ifdPrivateExponent` | 128 | `866F0F2C0CAF…7CAA2B3D61D1` | `599cc372e62f2a72b6835c12ee37e766b5d38255534c20aea8b0986dffe8b426` |
| `Dnie3r2UsrCwa14890Constants` | `C_CV_IFD` | 209 | `7F2181CD5F3781805DA9…534449620018` | `7b4456a27bf868a1a83497455249b5ae2f517cb1c77e2d425882acc56bf343f1` |
| `Dnie3r2UsrCwa14890Constants` | `CHR_C_CV_IFD` | 8 | `D002E00000000002` | `c35f763c13010f863abee31b9b683f1955f18a5a705d04ce4bd45e93159bca02` |
| `Dnie3r2UsrCwa14890Constants` | `ifdModulus` | 128 | `BDEFDB84ECE6…9522753F18D7` | `8a0c7fe56607219873741878dee013057f20c087cbeb4fac667f4f8ba61ed5f3` |
| `Dnie3r2UsrCwa14890Constants` | `ifdPrivateExponent` | 128 | `A0515593D436…3C17CCBDAA51` | `e6b5643864f6acb3f4f3995cf513d6ba355284afb22b33dac13b6309e62c3845` |

Estructura de un certificado CV (los seis): `7F21 L { 5F37 81 80 firma(128), 5F38 L resto_de_clave, 42 08 CAR }`;
`C_CV_CA` tiene CAR (clave raíz) `6573524449600006` (r1) / `6573524449620018` (r2), y `C_CV_IFD` tiene
CAR = `CHR_C_CV_CA`. El exponente
público del terminal (`00010001`) está al final de `5F38`.

### Apéndice B — Índice de clases y métodos citados

| Comportamiento | Clase.método (JMulticard 2.1) |
|---|---|
| Transporte Android | `android/AndroidNfcConnection` (`internalTransmit`, `reset`, `getMaxApduSize`), `NFCWatchdogRefresher` |
| Transmisión común | `core/connection/AbstractApduConnectionIso7816.transmit` |
| Codificación APDU | `core/apdu/CommandApdu`, `ResponseApdu`, `StatusWord` |
| Detección | `core/card/dnie/DnieFactory.getDnie/getDnieNfc`, `core/card/Atr.equals`, `DnieAtr` |
| CAN, re-PACE, reset | `core/card/dnie/DnieNfc.getPaceConnection`, `.openSecureChannelIfNotAlreadyOpened`, `.sign`, `.resetCard` |
| PACE | `jse/crypto/BcPaceChannelHelper.openPaceChannel`, `.getSecretNonce`, `.padAndDigest`; `core/CryptoHelper.PaceChannelHelper` (constantes, `bigIntToByteArray`, `unwrapEcKey`); `core/asn1/icao/CardAccess`; `core/apdu/iso7816four/pace/*` |
| SM PACE | `core/connection/pace/SecureMessaging.wrap/unwrap`, `PaceConnection.transmit`, `DO87/DO8E/DO97/DO99` |
| Canal CWA | `core/connection/cwa14890/Cwa14890OneV1Connection.open/transmit/internalAuth*/externalAuthentication`, `Cwa14890OneV2Connection`, `ChannelType` |
| SM CWA | `core/connection/AbstractApduEncrypter.protectAPDU`, `ApduEncrypterDes.generateMac/decryptResponseApdu`, `ApduEncrypterDesMac8`, `CipheredApdu` |
| Canales DNIe 3 | `core/card/dnie/Dnie3.openSecureChannelIfNotAlreadyOpened/openPinChannel/openUserChannel/getPinRetriesLeft`; constantes `Dnie3*Cwa14890Constants` |
| Comandos tarjeta | `core/card/dnie/Dnie.getSerialNumber/getIccCertPublicKey/verifyIfdCertificateChain/setKeysToAuthentication/getInternalAuthenticateMessage/externalAuthentication/verifyPin/getPinRetriesLeft/getInternalPasswordCallback/signOperation/loadCertificates/getIdesp` |
| Ficheros | `core/card/iso7816four/AbstractIso7816FourCard.selectFileById/selectFileByName/readBinaryComplete/selectFileByLocation`, `core/card/Location`, `core/apdu/iso7816four/SelectFileApduResponse` |
| PKCS#15 | `core/asn1/der/pkcs15/Cdf`, `PrKdf`, `CertificateObject`, `PrivateKeyObject`, `CommonKeyAttributes`, `Path`; `core/asn1/custom/fnmt/ceressc/CeresScPrKdf` |
| Certificados | `core/card/CompressionUtils`, `jse/provider/DnieKeyStoreImpl.engineGetCertificateChain` |
| Firma | `core/asn1/der/pkcs1/DigestInfo.encode`, `core/apdu/iso7816four/MseSetComputationApduCommand`, `core/apdu/iso7816eight/PsoSignHashApduCommand`, `jse/provider/DnieSignatureImpl` |
| Callbacks | `core/callback/CustomTextInputCallback`, `CardWithRetriesPasswordCallback`; `core/card/CardMessages` (`cardmessages.properties`) |
| Proveedor/almacén | `jse/provider/DnieProvider`, `AbstractJMultiCardKeyStore`, `DnieKeyStoreImpl`, `DniePrivateKey` |
| App Android | `KeyStoreManagerFactory.initNfcKeyStoreManager`, `LoadNfcKeyStoreManagerTask`, `LoadCertificatesTask`, `AndroidDnieNFCCallbackHandler`, `DnieConnectionManager`, `NFCDetectorActivity`, `StepsInsertDataDnieActivity`, `InsertDataDnieStep{1,2,3}Fragment`, `IntroUseDnieActivity`, `LoadKeyStoreFragmentActivity`, `SelectAliasDialog.signWithSignCertificate`, `SignTask`, `errors/ThirdPartyErrors` |

### Apéndice C — Lista de puntos VERIFICAR

1. Diferencias JMulticard 2.0 (usada por la app) frente a 2.1 (analizada).
2. Valor de `IsoDep.getHiLayerResponse()` del DNIe 3.0/4.0 en Android (se espera vacío).
3. Efecto del `reset()` PC/SC tras PACE en lectores sin contacto (§2.2).
4. Si el DNIe permite leer `EF.CardAccess` sin SM y su contenido.
5. SW de GA4 con CAN erróneo (se espera `6300`).
6. Contenido exacto del IDESP (relleno, NUL) y el de los DNIe 4.0 (constantes r2).
7. FCI real devuelto por el DNIe (posición del tamaño, etiquetas `80`/`81`).
8. Significado de la cabecera de 8 octetos de los certificados comprimidos.
9. Forma de la respuesta a la consulta de intentos (SW externa `9000` con DO99 `63Cx`, o `63Cx` en claro).
10. Longitudes de PIN admitidas por el DNIe (8–16).
11. Respuesta al `SELECT` en claro tras la firma (`6987` según el comentario del código).
12. Si mantener el canal de usuario entre firmas funcionaría (mejora opcional §9.4).
13. Que `CA_COMPONENT_PUBLIC_KEY` firme los certificados de componente (mejora opcional C1).
14. Rutas/tamaños de ficheros y longitud de clave en DNIe 4.0; raíz usada.
15. Número de apéndice/edición del ejemplo ICAO de §4.5.
16. Disponibilidad de aritmética en el crate `bp256`.
17. Selección de un `SecureRandom` determinista vía proveedor en el arnés Java.

---

## 18. Notas de implementación

Implementación: `crates/afirma-dnie` (Rust puro; características `sim`, `signing-key`, `keystore`). Lo que sigue
resuelve puntos del apéndice C, precisa la especificación donde el código o las pruebas lo han aclarado y recoge las
decisiones que no son de paridad.

### 18.1 Puntos VERIFICAR resueltos (o acotados)

- **1 (JMulticard 2.0 frente a 2.1).** En el repositorio de JMulticard, entre la etiqueta `v2.0` y el commit analizado
  (`4ec9494f`) los módulos `jmulticard`, `jmulticard-crypto` y `jmulticard-jse` solo cambian en
  `Dnie.getInternalPasswordCallback` (el PIN se pide con `CardWithRetriesPasswordCallback`, subclase de
  `PasswordCallback` con el mismo texto y `getRetriesLeft()`) y en `Ceres`; `DnieNfc`, PACE, mensajería segura,
  CWA-14890, PKCS#15 y firma son idénticos. `jmulticard-android` no estaba en el repositorio en `v2.0`, así que
  `AndroidNfcConnection` 2.0 sigue sin comprobar.
- **9 (respuesta a la consulta de intentos).** Se aceptan las dos formas (SW externa `9000` con `63Cx` en DO99, y SW
  externa `63Cx` con o sin objetos SM; si los trae, se verifica el MAC). `63C0` y `6983` = PIN bloqueado (sin enviar
  `VERIFY`); `9000` = intentos desconocidos.
- **7 (FCI).** El tamaño se toma de la etiqueta `80`, si no de `81` y si no del campo propietario FNMT `85 0A`
  (octetos 3–4 del valor, como JMulticard y OpenSC `card-dnie.c`); sin tamaño se lee hasta un bloque corto, `6282` o
  `6B00`. El FCI real sigue pendiente de tarjeta.
- **16 (`bp256`).** `bp256` 0.6.1 (la compatible con `elliptic-curve` 0.13 del espacio de trabajo) solo trae la
  característica `wip-arithmetic-do-not-use`; la 0.14.0 (2026-09-10) sí tiene `arithmetic`, pero sobre
  `elliptic-curve` 0.14 / `crypto-bigint` 0.7 (una segunda pila RustCrypto). Se implementa la curva en
  `src/ec.rs` sobre `crypto-bigint` 0.5: residuos de Montgomery en tiempo constante, fórmulas completas de
  Renes–Costello–Batina para `a` genérico (las de `primeorder::EquationAIsGeneric`), multiplicación escalar con
  ventana fija de 4 bits y selección en tiempo constante, validación SEC 1 de los puntos recibidos.
- **17 (aleatorios deterministas en el arnés Java).** No ha hecho falta: la comparación con JMulticard se hace con los
  comandos internos (desprotegidos) enmascarando solo lo aleatorio (claves y tokens de GA2–GA4, `RND.IFD` y el
  criptograma de EXTERNAL AUTHENTICATE), más contexto SM, longitudes en el aire y SW de cada APDU. Resultado: las
  131 APDU de `transcript_full.txt` (carga + dos firmas) coinciden con las del controlador Rust, tanto contra el
  simulador Rust (`tests/golden.rs`) como vistas desde el simulador Java en la prueba cruzada (`tests/oracle.rs`);
  también `transcript_r1.txt`, `transcript_outer63.txt` y `transcript_wrongpin.txt` hasta el `VERIFY` erróneo
  (después el Rust descarta el contexto en vez de reutilizar el canal de PIN, §18.3).

### 18.2 Precisiones y erratas

- **Número de APDU de la carga (§11.2).** `testdata/dnie/transcript_full.txt` tiene 59 APDU antes de la primera firma,
  no 56: las 57–59 son una segunda lectura del IDESP que hace el propio arnés (`Main.flow` llama a `card.getIdesp()`
  al registrar la tarjeta), no JMulticard. Las 56 de §11.2 son correctas (comprobado: 56 + 35 + 40).
- **Vector §5.4 b.** El FCI `6F048102000A` termina justo tras el TLV `81`, que `SelectFileApduResponse` de JMulticard
  rechazaría (§7.2); el vector sale del script de referencia, no del flujo de JMulticard. El Rust lo acepta.
- **Interfaces (§10.3, §13.2).** Los nombres reales son `CardTransport` (`transceive`, `identification` con
  `CardIdentification` —ATR, bytes históricos, HLR y datos del ATQB—, `max_command_len`) y
  `DnieInteraction::request_pin(&PinRequest)`, con `retries_left: Option<u8>` (la tarjeta puede no informarlo).
  El RNG inyectable es `RandomSource` (todos los aleatorios de PACE y CWA salen de él).

### 18.3 Decisiones que no son de paridad

- Defectos corregidos: P1 (X de 32 octetos; 3000 sesiones PACE con claves aleatorias contra el simulador Rust y
  2000 contra el Java sin ningún fallo; en cada ejecución hay entre 4 y 20 sesiones con X = `00…`, las que fallaban
  con JMulticard), P2 (`T_ICC` verificado en tiempo
  constante), P3 (puntos validados, `PK_ICC ≠ PK_IFD` y `PK_map_ICC ≠ PK_map_IFD`), P4 (escalares uniformes en
  `[1, n−1]`), P5 (etiquetas), P6 (MAC ICAO en el caso 1), C2 (CSPRNG del sistema), C3–C5, `setLe` sin Lc.
- Detección (§3.2): con los datos del ATQB (`NfcB.getApplicationData()`/`getProtocolInfo()`) se construye el
  pseudo-ATR y se compara entero con `ATR_NFC` (rechaza tipo B que no son DNIe); sin ellos, comparación por sufijo de
  JMulticard. ATR de contacto y DNIe «quemado» se rechazan con «tarjeta no soportada». Tras PACE, cualquier respuesta
  inesperada al leer CDF/PrKDF/certificados (p. ej. TIE) es «tarjeta no soportada»; los errores de enlace siguen
  siendo «error de lectura».
- PIN: se rechaza antes de enviarlo si está vacío, no es ASCII imprimible o supera 16 caracteres (no gasta
  intentos); no se impone mínimo (punto 10 sigue abierto). Nunca se repite un `VERIFY`.
- Errores durante una firma: siempre se envía el `SELECT` en claro para descartar el contexto de la tarjeta (también
  tras un PIN erróneo, en vez de reutilizar el canal de PIN como JMulticard, §8.3). Ante un error de enlace o de SM se
  reabre una vez desde PACE, salvo si el resultado de un `VERIFY` enviado es desconocido; si el `VERIFY` ya había sido
  correcto, el reintento reutiliza ese PIN.
- Cada firma se verifica con la clave pública del certificado antes de devolverla (`BadSignature` si no).
- Confirmación de firma (`DnieInteraction::confirm_signature`): se pide antes de cualquier APDU de la firma
  (JMulticard 2.1 no la emite; por defecto acepta).
- La comprobación opcional C1 (certificado de componente firmado por `CA_COMPONENT_PUBLIC_KEY`) solo se registra.

### 18.4 Oráculo

`tools/oracle/dnie/src/sim/Main.java` tiene un modo `serve` (APDU en hexadecimal por la entrada estándar, una línea
por respuesta; órdenes `ATR`, `#idesp`, `#can`, `#pin`, `#retries`, `#outer63`, `#stats`) y `run.sh` admite
`BUILD_ONLY=1`. `AFIRMA_DNIE_ORACLE=<directorio de trabajo> cargo test -p afirma-dnie --test oracle` ejecuta el host
Rust contra el `SimCard` Java (flujo completo r2 y r1, PIN erróneo, SW externa = interna, CAN erróneo y carga de
PACE); sin la variable, la prueba queda ignorada.

### 18.5 Pendiente de tarjeta real

Siguen abiertos los puntos 2–6, 8, 10–15 del apéndice C (HLR/ATQB reales en Android, reset PC/SC, `EF.CardAccess`,
SW de GA4 con CAN erróneo, IDESP real, cabecera de compresión, longitudes de PIN, respuesta al `SELECT` de reinicio,
canal de usuario entre firmas, CA de componentes, DNIe 4.0, apéndice ICAO) y la prueba de la sonda de presencia en
Android API 23–27 (§2.1).
