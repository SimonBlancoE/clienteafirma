import subprocess, sys, os, glob
BIN = "/home/octo/Projects/autofirma/target/debug/examples/c14n"
SP = sys.argv[1]
fails = 0
for path in sorted(glob.glob(os.path.join(SP, "c14ndiff", "*.xml"))):
    import re
    ids = [None] + re.findall(rb'Id="([^"]+)"', open(path, "rb").read())
    for uri in ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
                "http://www.w3.org/2006/12/xml-c14n11"]:
        for idv in ids:
            idv = idv.decode() if idv else ""
            exp = subprocess.run(["java", "--add-exports", "java.xml.crypto/com.sun.org.apache.xml.internal.security=ALL-UNNAMED",
                "--add-exports", "java.xml.crypto/com.sun.org.apache.xml.internal.security.c14n=ALL-UNNAMED", "-cp", os.path.join(SP, "jc14n"),
                "JC14n", uri, path, idv], capture_output=True)
            got = subprocess.run([BIN, uri, path, idv], capture_output=True).stdout
            if exp.returncode != 0:
                print("java error", path, exp.stderr[-300:]); continue
            if got != exp.stdout:
                fails += 1
                print(f"DIFF {os.path.basename(path)} {uri} id={idv}\n  exp={exp.stdout!r}\n  got={got!r}")
print("fallos:", fails)
