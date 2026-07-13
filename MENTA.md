# Menta

## Qué es Menta

Menta es un CAPTCHA diseñado para defender a las personas de los bots sin entregar su privacidad a terceros. No depende de imágenes, huellas digitales, cookies ni telemetry de proveedores externos. Usa una prueba de trabajo ligera que corre en el navegador del usuario y se verifica en el servidor del operador, manteniendo el tráfico humano bajo control de quien lo publica.

## Misión

Proteger formularios y APIs del abuso automatizado mientras se respeta, por diseño, la privacidad y la autonomía del usuario.

## Visión

Ser el estándar de CAPTCHA por defecto para quienes prefieren soberanía de datos: autoalojable, transparente, accesible, multimarco y sin compromisos comerciales contra la privacidad.

## Objetivo

1. Ofrecer una barrera bot fácil de usar para humanos y costosa de escalar para máquinas.
2. Eliminar la necesidad de enviar datos personales a plataformas de terceros para resolver un CAPTCHA.
3. Cumplir con regímenes globales de privacidad y accesibilidad desde el primer día.
4. Mantener un widget que funcione sin cookies, sin localStorage y sin telemetry.

## Valores

- **Privacidad por diseño.** Minimizar datos, anonimizar IPs por defecto y cifrar en reposo y tránsito.
- **Transparencia.** Código abierto, políticas claras y sin terceros invisibles.
- **Accesibilidad.** El widget debe ser usable con teclado, lectores de pantalla y sin dependencias de movimiento.
- **Soberanía.** SaaS para quien quiere conveniencia; self-hosted para quien quiere control total.
- **Cumplimiento sin concesiones.** Cumplir GDPR, CCPA, PIPEDA/CPPA, LGPD, DPDPA, PIPL y estar listo para HIPAA, sin sacrificar la experiencia.
- **Simplicidad.** Un clic, una prueba de trabajo, un token. Sin puzzles visuales.

## Por nada del mundo se cambia

- **No se usan cookies.** Ni propias, ni de terceros, ni localStorage.
- **No se envía telemetry a terceros.** No Google, no Cloudflare, no hCaptcha, no CDNs de analytics.
- **La IP no se almacena completa por defecto.** Se usa prefijo /24 (IPv4) o /64 (IPv6) salvo configuración expresa del operador.
- **El dato se retiene el mínimo indispensable.** Tiempo configurable y acotado.
- **El cifrado en reposo y tránsito no es opcional.** SQLCipher + TLS.
- **Los derechos de los titulares son accesibles.** Exportación y eliminación por IP/tenant deben existir.
- **La accesibilidad no se negocia.** WCAG 2.2 AA y EAA como piso.
- **El idioma del widget es declarativo.** Se hereda del sitio anfitrión y se puede sobrescribir por atributos, sin almacenamiento del cliente.

## Funciones derivadas de estos principios

La arquitectura y el código de Menta se construyen a partir de los puntos anteriores. Si una función no existe, se crea pensando en estos principios:

- **Anonimización de IP:** `get_ip_prefix()`, `get_client_ip()`.
- **Retención automática:** `_cleanup()` con `DATA_RETENTION_HOURS`.
- **Cifrado en reposo:** `get_db()` con `sqlcipher3`.
- **Separación de tenant:** `current_tenant()`, `set_tenant()`.
- **RBAC de admin:** `_admin_authorized()`, `_log_admin_access()`.
- **Derechos del titular:** `/admin/export-data`, `/admin/delete-data`.
- **Transparencia legal:** `/privacy`, `/terms`, `/dpa`, `/baa`.
- **Headers de seguridad:** `security_headers()`.
- **Accesibilidad e i18n:** `menta-widget.js` y `WIDGET_JS` en `app.py`.
- **Detección de abuso:** `check_rate_limit()`, `check_bot_signals()`, `check_nonce_entropy()`, `check_client_pattern()`.

## Modelo de decisión

Cada nueva función, endpoint o dependencia se pregunta:

1. ¿Recolecta menos datos personales que la alternativa?
2. ¿Puede funcionar sin cookies y sin localStorage?
3. ¿Respalda accesibilidad y WCAG 2.2 AA?
4. ¿Cumple con GDPR, CCPA, LGPD, PIPL, DPDPA y está listo para HIPAA?
5. ¿Mantiene la opción self-hosted intacta?

Si una propuesta rompe cualquiera de estas respuestas, se rechaza o se rediseña.

## Nota legal

Este documento describe la intención y los principios de diseño de Menta. No constituye asesoría legal. Cada reglamento (GDPR, HIPAA, PIPL, etc.) requiere revisión legal por parte del operador antes del lanzamiento.
