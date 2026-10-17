// Genera la tabla de elementos de colación del JDK que usa la ordenación de
// texto de XSLT (`xsl:sort`): `Collator.getInstance(Locale.ENGLISH)` es un
// `RuleBasedCollator` con las reglas por defecto (`CollationRules.DEFAULTRULES`),
// sin descomposición y con intensidad terciaria. El español solo añade
// `& N < ñ, Ñ`, que Rust deriva de esta tabla.
//
//   java --add-opens java.base/java.text=ALL-UNNAMED tools/oracle/xslt/CollationTable.java \
//       > crates/afirma-xml/src/xslt/collation_table.rs
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.text.CollationElementIterator;
import java.text.Collator;
import java.text.RuleBasedCollator;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class CollationTable {
    public static void main(final String[] a) throws Exception {
        final RuleBasedCollator c = (RuleBasedCollator) Collator.getInstance(Locale.ENGLISH);
        final Field tf = RuleBasedCollator.class.getDeclaredField("tables");
        tf.setAccessible(true);
        final Object tables = tf.get(c);
        final Method maxSec = tables.getClass().getDeclaredMethod("getMaxSecOrder");
        final Method maxTer = tables.getClass().getDeclaredMethod("getMaxTerOrder");
        maxSec.setAccessible(true);
        maxTer.setAccessible(true);
        final StringBuilder sb = new StringBuilder();
        sb.append("//! Elementos de colación del `RuleBasedCollator` por defecto del JDK.\n");
        sb.append("//!\n");
        sb.append("//! Generado con `tools/oracle/xslt/CollationTable.java`; no editar a mano.\n\n");
        sb.append("/// `RBCollationTables.getMaxSecOrder()`.\n");
        sb.append("pub(crate) const MAX_SEC_ORDER: u32 = ").append(maxSec.invoke(tables)).append(";\n");
        sb.append("/// `RBCollationTables.getMaxTerOrder()`.\n");
        sb.append("pub(crate) const MAX_TER_ORDER: u32 = ").append(maxTer.invoke(tables)).append(";\n\n");
        sb.append("/// Carácter, número de elementos y elementos (primario << 16 | secundario << 8 | terciario).\n");
        sb.append("#[rustfmt::skip]\n");
        sb.append("pub(crate) const TABLE: &[(u32, u8, [u32; 3])] = &[\n");
        String line = "   ";
        for (int cp = 0; cp <= 0xFFFF; cp++) {
            if (Character.isSurrogate((char) cp)) {
                continue;
            }
            final CollationElementIterator it = c.getCollationElementIterator(String.valueOf((char) cp));
            final List<Integer> els = new ArrayList<>();
            int e;
            while ((e = it.next()) != CollationElementIterator.NULLORDER) {
                els.add(e);
            }
            if (els.size() == 2 && els.get(0) == 0x7FFF0000) {
                continue; // sin entrada: UNMAPPEDCHARVALUE + carácter
            }
            if (els.size() > 3) {
                throw new IllegalStateException("más de tres elementos: " + Integer.toHexString(cp));
            }
            final StringBuilder t = new StringBuilder(" (0x").append(Integer.toHexString(cp)).append(", ").append(els.size())
                .append(", [");
            for (int i = 0; i < 3; i++) {
                if (i > 0) {
                    t.append(", ");
                }
                t.append("0x").append(Integer.toHexString(i < els.size() ? els.get(i) : 0));
            }
            t.append("]),");
            if (line.length() + t.length() > 118) {
                sb.append(line).append('\n');
                line = "   ";
            }
            line += t;
        }
        sb.append(line).append("\n];\n");
        System.out.print(sb);
    }
}
