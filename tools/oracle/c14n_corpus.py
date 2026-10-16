import subprocess, sys, os, random, glob
from lxml import etree
BIN = "/home/octo/Projects/autofirma/target/debug/examples/c14n"
OUT = sys.argv[1]
docs = {}
docs["ns_mix"] = '''<?xml version="1.0" encoding="UTF-8"?>
<!-- antes -->
<root xmlns="urn:def" xmlns:a="urn:a" xmlns:b="urn:b" xml:lang="es" attr="x&#9;y">
  <a:child Id="n1" b:z="2" a:y="1" zz="3"><inner xmlns="" xmlns:c="urn:c">texto &amp; &lt;más&gt;<c:deep xml:space="preserve"> sp </c:deep></inner>
  <!-- comentario interno --><?pi datos?></a:child>
  <b:other Id="n2" xmlns:a="urn:a2"><a:q/><![CDATA[ <cdata> & ]]></b:other>
</root>
<!-- despues -->'''
docs["latin1"] = '<?xml version="1.0" encoding="ISO-8859-1"?>\n<factura xmlns="http://www.facturae.es/Facturae/2009/v3.2/Facturae" Id="f"><nombre>España €</nombre><r>\r\nlínea</r></factura>'
docs["deep_redecl"] = '<a xmlns:p="urn:1"><b xmlns:p="urn:2" Id="b"><c xmlns:p="urn:1"><p:d p:x="1"/></c></b><p:e xmlns:p="urn:1"/></a>'
docs["default_undecl"] = '<a xmlns="urn:x"><b xmlns="" Id="b"><c xmlns="urn:x"><d xmlns=""/></c></b></a>'
docs["attrs_sort"] = '<a xmlns:z="urn:a" xmlns:y="urn:b" Id="r" z:k="1" y:k="2" b="3" a="4" xmlns:x="urn:0" x:a="5"/>'
fails = 0
for name, text in docs.items():
    data = text.encode("iso-8859-1" if "ISO-8859-1" in text else "utf-8", errors="xmlcharrefreplace")
    path = os.path.join(OUT, name + ".xml")
    open(path, "wb").write(data)
    tree = etree.fromstring(data, etree.XMLParser(remove_blank_text=False, resolve_entities=False)).getroottree()
    ids = [None] + [e.get("Id") for e in tree.iter() if isinstance(e.tag, str) and e.get("Id")]
    for uri, excl, comments in [
        ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", False, False),
        ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", False, True),
        ("http://www.w3.org/2001/10/xml-exc-c14n#", True, False),
        ("http://www.w3.org/2001/10/xml-exc-c14n#WithComments", True, True),
    ]:
        for idv in ids:
            node = tree if idv is None else tree.xpath('//*[@Id=$i]', i=idv)[0]
            if idv is None:
                exp = etree.tostring(tree, method="c14n", exclusive=excl, with_comments=comments)
            else:
                # Subárbol: c14n de un conjunto de nodos con ancestros omitidos
                exp = etree.tostring(node, method="c14n", exclusive=excl, with_comments=comments)
            got = subprocess.run([BIN, uri, path, idv or ""], capture_output=True).stdout
            if got != exp:
                fails += 1
                print(f"DIFF {name} {uri} id={idv}\n  exp={exp!r}\n  got={got!r}")
print("fallos:", fails)
