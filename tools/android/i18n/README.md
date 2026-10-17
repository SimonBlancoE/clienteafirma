# Catálogos de la app Android

`crates/autofirma-android/locales/*.txt` se generaron a partir de los `strings.xml` de
firma-android 1.9 (`afirma-ui-android/app/src/main/res/values*/strings.xml`):

```sh
python3 tools/android/i18n/xml2cat.py <firma-android>/afirma-ui-android/app/src/main/res cats.json
python3 tools/android/i18n/gencat.py cats.json crates/autofirma-android/locales
```

`gencat.py` aplica las correcciones de `docs/spec/09-android.md` §10 (cada una queda con un
comentario `# Corregido:` en el catálogo) y añade los textos propios de AutoFirma-rs tras la
marca `# [autofirma-rs]`. Los catálogos ya están en el repositorio; los scripts solo hacen
falta para regenerarlos.
