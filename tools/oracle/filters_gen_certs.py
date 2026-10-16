#!/usr/bin/env python3
"""Genera los certificados sintéticos de prueba de los filtros de certificados
y de la representación de nombres X.500 (afirma-keystores).

Uso: python -I tools/oracle/filters_gen_certs.py testdata/keystores/filters
Las claves se generan al vuelo y se descartan: solo interesan los certificados.
"""
import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID, ObjectIdentifier

OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)
UTC = dt.timezone.utc


def A(oid, value, t=None):
    if isinstance(oid, str):
        oid = ObjectIdentifier(oid)
    return x509.NameAttribute(oid, value, _type=t) if t is not None else x509.NameAttribute(oid, value)


def name(*rdns):
    """RDN en orden DER (el primero es el más general, p. ej. C)."""
    out = []
    for r in rdns:
        if isinstance(r, list):
            out.append(x509.RelativeDistinguishedName(r))
        else:
            out.append(x509.RelativeDistinguishedName([r]))
    return x509.Name(out)


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def oid_der(dotted):
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(enc))
    return tlv(0x06, body)


def qc_statements(*oids):
    return tlv(0x30, b"".join(tlv(0x30, oid_der(o)) for o in oids))


KU_FIELDS = ["digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
             "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only"]


def ku(*flags):
    kw = {f: (f in flags) for f in KU_FIELDS}
    if not kw["key_agreement"]:
        kw["encipher_only"] = False
        kw["decipher_only"] = False
    return x509.KeyUsage(**kw)


def make(fname, subject, issuer, serial, not_before, not_after, key_usage=None, policies=None, qc=None,
         ca=False, extra=None):
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).serial_number(serial)
         .not_valid_before(not_before).not_valid_after(not_after).public_key(key.public_key()))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if key_usage is not None:
        b = b.add_extension(key_usage, critical=True)
    if policies:
        b = b.add_extension(x509.CertificatePolicies([x509.PolicyInformation(ObjectIdentifier(p), None) for p in policies]),
                            critical=False)
    if qc is not None:
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.5.5.7.1.3"), qc), critical=False)
    for ext, critical in extra or []:
        b = b.add_extension(ext, critical=critical)
    cert = b.sign(key, hashes.SHA256())
    (OUT / f"{fname}.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))


D = lambda *a: dt.datetime(*a, tzinfo=UTC)
NB = D(2020, 1, 1)
NA = D(2045, 1, 1)

DNIE_ROOT = name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.ORGANIZATION_NAME, "DIRECCION GENERAL DE LA POLICIA"),
                 A(NameOID.ORGANIZATIONAL_UNIT_NAME, "DNIE"), A(NameOID.COMMON_NAME, "AC RAIZ DNIE 2"))
DNIE_CA = name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.ORGANIZATION_NAME, "DIRECCION GENERAL DE LA POLICIA"),
               A(NameOID.ORGANIZATIONAL_UNIT_NAME, "DNIE"), A(NameOID.COMMON_NAME, "AC DNIE 004"))
make("dnie-ca", DNIE_CA, DNIE_ROOT, 0x10, NB, NA, ku("key_cert_sign", "crl_sign"), ca=True)


def dnie_subject(kind):
    return name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.SERIAL_NUMBER, "12345678Z"),
                A(NameOID.SURNAME, "ESPAÑOL ESPAÑOL", _ASN1Type.UTF8String), A(NameOID.GIVEN_NAME, "JUAN"),
                A(NameOID.COMMON_NAME, f"ESPAÑOL ESPAÑOL, JUAN ({kind})", _ASN1Type.UTF8String))


DNIE_NA = D(2035, 6, 15, 10, 0, 0)
make("dnie-firma", dnie_subject("FIRMA"), DNIE_CA, 0x1122, NB, DNIE_NA, ku("content_commitment"),
     policies=["2.16.724.1.2.2.2.3"], qc=qc_statements("0.4.0.1862.1.1", "0.4.0.1862.1.4"))
make("dnie-auth", dnie_subject("AUTENTICACIÓN"), DNIE_CA, 0x80AB12, NB, D(2035, 6, 15, 10, 0, 30),
     ku("digital_signature"), policies=["2.16.724.1.2.2.2.4"])
# Otro DNIe (otra persona) para comprobar que no se empareja.
make("dnie-auth-otro", name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.SERIAL_NUMBER, "87654321X"),
                            A(NameOID.COMMON_NAME, "OTRA PERSONA (AUTENTICACIÓN)", _ASN1Type.UTF8String)),
     DNIE_CA, 0x0777, NB, DNIE_NA, ku("digital_signature"))

ACCV_CA = name(A(NameOID.COMMON_NAME, "ACCV-CA2"), A(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKIGVA"),
               A(NameOID.ORGANIZATION_NAME, "Generalitat Valenciana"), A(NameOID.COUNTRY_NAME, "ES"))
ACCV_SUBJ = lambda cn: name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.SERIAL_NUMBER, "11111111H"),
                            A(NameOID.COMMON_NAME, cn))
make("accv-firma", ACCV_SUBJ("PERSONA ACCV FIRMA"), ACCV_CA, 0x0A01, NB, D(2033, 3, 3, 12), ku("digital_signature"))
make("accv-auth", ACCV_SUBJ("PERSONA ACCV AUTH"), ACCV_CA, 0x0A02, NB, D(2033, 3, 3, 12),
     ku("digital_signature", "key_encipherment"))

FNMT_CA = name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.ORGANIZATION_NAME, "FNMT-RCM"),
               A(NameOID.ORGANIZATIONAL_UNIT_NAME, "CERES"), A(NameOID.COMMON_NAME, "AC Sector Público", _ASN1Type.UTF8String))
PS_NA = D(2034, 1, 1, 0, 0, 0)
make("pseudonimo", name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.ORGANIZATION_NAME, "MINISTERIO DE PRUEBAS"),
                        A(NameOID.ORGANIZATIONAL_UNIT_NAME, "UNIDAD DE PRUEBAS"),
                        A(NameOID.TITLE, "JEFE DE SERVICIO"), A(NameOID.PSEUDONYM, "PSEUDO-0001"),
                        A(NameOID.COMMON_NAME, "SEUDONIMO PSEUDO-0001")),
     FNMT_CA, 0x5001, NB, PS_NA, ku("digital_signature", "content_commitment"))
make("pseudonimo-gemelo", name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.SERIAL_NUMBER, "22222222J"),
                               A(NameOID.COMMON_NAME, "EMPLEADO PUBLICO GEMELO")),
     FNMT_CA, 0x5002, NB, D(2034, 1, 1, 0, 0, 30), ku("digital_signature", "content_commitment"))
make("fnmt-otro", name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.SERIAL_NUMBER, "33333333P"),
                       A(NameOID.COMMON_NAME, "EMPLEADO PUBLICO OTRO")),
     FNMT_CA, 0x5003, NB, D(2034, 1, 1, 0, 5, 0), ku("digital_signature", "content_commitment"))
make("representante", name(A(NameOID.COUNTRY_NAME, "ES"), A(ObjectIdentifier("2.5.4.97"), "VATES-B12345678"),
                           A(NameOID.ORGANIZATION_NAME, "EMPRESA DE PRUEBAS, S.L."),
                           A(NameOID.SERIAL_NUMBER, "IDCES-44444444A"),
                           A(NameOID.COMMON_NAME, "44444444A JUAN PRUEBA (R: B12345678)")),
     FNMT_CA, 0x5004, NB, D(2031, 7, 7), ku("digital_signature", "content_commitment", "key_encipherment"),
     policies=["1.3.6.1.4.1.5734.3.11"])

CNP_CA = name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.ORGANIZATION_NAME, "DIRECCION GENERAL DE LA POLICIA"),
              A(NameOID.ORGANIZATIONAL_UNIT_NAME, "CNP"), A(NameOID.COMMON_NAME, "AC CNP 001"))
make("cnp", name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.COMMON_NAME, "AGENTE CNP")), CNP_CA, 0x6001, NB, NA,
     ku("content_commitment"))

GEN_CA = name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.ORGANIZATION_NAME, "Pruebas Genericas"),
              A(NameOID.COMMON_NAME, "CA Generica"))
make("sin-keyusage", name(A(NameOID.COMMON_NAME, "SIN KEYUSAGE")), GEN_CA, 0x7001, NB, NA)
make("ku-todos", name(A(NameOID.COMMON_NAME, "KU TODOS")), GEN_CA, 0x7002, NB, NA,
     ku("digital_signature", "content_commitment", "key_encipherment", "data_encipherment"))
make("ku-cifrado", name(A(NameOID.COMMON_NAME, "KU CIFRADO")), GEN_CA, 0x7003, NB, NA, ku("data_encipherment"))
make("ku-agreement", name(A(NameOID.COMMON_NAME, "KU AGREEMENT")), GEN_CA, 0x7004, NB, NA,
     ku("key_agreement", "encipher_only"))
make("politicas", name(A(NameOID.COMMON_NAME, "POLITICAS VARIAS")), GEN_CA, 0x7005, NB, NA, ku("content_commitment"),
     policies=["2.16.724.1.3.5.7.1", "1.3.6.1.4.1.5734.3.10.1"])
make("qc-sin-sscd", name(A(NameOID.COMMON_NAME, "QC SIN SSCD")), GEN_CA, 0x7006, NB, NA, ku("content_commitment"),
     qc=qc_statements("0.4.0.1862.1.1", "0.4.0.1862.1.6"))
make("futuro", name(A(NameOID.COMMON_NAME, "AUN NO VALIDO")), GEN_CA, 0x7007, D(2040, 1, 1), D(2050, 1, 1),
     ku("content_commitment"))
make("sujeto-vacio", x509.Name([]), GEN_CA, 0x7008, NB, NA, ku("content_commitment"),
     extra=[(x509.SubjectAlternativeName([x509.RFC822Name("vacio@example.com")]), True)])
make("solo-ou", name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.ORGANIZATIONAL_UNIT_NAME, "UNIDAD SIN CN")), GEN_CA,
     0x7009, NB, NA, ku("content_commitment"))
make("solo-o", name(A(NameOID.COUNTRY_NAME, "ES"), A(NameOID.ORGANIZATION_NAME, "ORGANIZACION SIN CN")), GEN_CA,
     0x700A, NB, NA, ku("content_commitment"))

# Tipos de cadena y atributos variados.
make("tipos-cadena", name(
    A(NameOID.COUNTRY_NAME, "ES"),
    A(NameOID.ORGANIZATION_NAME, "Organización T61", _ASN1Type.T61String),
    A(NameOID.ORGANIZATIONAL_UNIT_NAME, "Unidad BMP ñ€", _ASN1Type.BMPString),
    A(NameOID.LOCALITY_NAME, "Localidad Universal ç", _ASN1Type.UniversalString),
    A(NameOID.STATE_OR_PROVINCE_NAME, "Visible", _ASN1Type.VisibleString),
    A(NameOID.POSTAL_CODE, "28001", _ASN1Type.NumericString),
    A(NameOID.EMAIL_ADDRESS, "correo@example.com", _ASN1Type.IA5String),
    A(NameOID.DOMAIN_COMPONENT, "example", _ASN1Type.IA5String),
    A(NameOID.USER_ID, "uid01", _ASN1Type.UTF8String),
    A(NameOID.STREET_ADDRESS, "Calle Mayor 1"),
    A(NameOID.DN_QUALIFIER, "dnq"),
    A(NameOID.INITIALS, "JP"),
    A(NameOID.GENERATION_QUALIFIER, "III"),
    A("1.3.6.1.4.1.42.2.11.2.1", "10.0.0.1"),
    A("1.2.3.4.5", "atributo desconocido", _ASN1Type.UTF8String),
    A(NameOID.COMMON_NAME, "Tipos de cadena"),
), GEN_CA, 0x7010, NB, NA, ku("content_commitment"))

make("escapes", name(
    A(NameOID.COUNTRY_NAME, "ES"),
    A(NameOID.ORGANIZATION_NAME, "  espacios al inicio"),
    A(NameOID.ORGANIZATION_NAME, "espacios al final  "),
    A(NameOID.ORGANIZATIONAL_UNIT_NAME, "dos  espacios"),
    A(NameOID.ORGANIZATIONAL_UNIT_NAME, "a+b,c=d;e<f>g"),
    A(NameOID.LOCALITY_NAME, 'comillas "dobles" y \\barra', _ASN1Type.UTF8String),
    A(NameOID.STATE_OR_PROVINCE_NAME, "#almohadilla", _ASN1Type.UTF8String),
    A(NameOID.STREET_ADDRESS, '"Ya entre comillas"', _ASN1Type.UTF8String),
    A(NameOID.TITLE, "salto\nde linea", _ASN1Type.UTF8String),
    A(NameOID.DESCRIPTION if hasattr(NameOID, "DESCRIPTION") else "2.5.4.13", "retorno\rcarro", _ASN1Type.UTF8String),
    A(NameOID.COMMON_NAME, "CN con, coma"),
), GEN_CA, 0x7011, NB, NA, ku("content_commitment"))

make("multivalor", name(
    A(NameOID.COUNTRY_NAME, "ES"),
    [A(NameOID.ORGANIZATIONAL_UNIT_NAME, "Unidad B"), A(NameOID.COMMON_NAME, "Nombre A")],
    [A(NameOID.SERIAL_NUMBER, "99999999R"), A(NameOID.GIVEN_NAME, "MARIA")],
), GEN_CA, 0x7012, NB, NA, ku("content_commitment"))

make("cn-repetido", name(
    A(NameOID.COUNTRY_NAME, "ES"),
    A(NameOID.COMMON_NAME, "CN Primero"),
    A(NameOID.ORGANIZATIONAL_UNIT_NAME, "OU Primera"),
    A(NameOID.ORGANIZATIONAL_UNIT_NAME, "OU Segunda"),
    A(NameOID.COMMON_NAME, "CN Segundo"),
), GEN_CA, 0x7013, NB, NA, ku("content_commitment"))
print("Certificados generados en", OUT)
