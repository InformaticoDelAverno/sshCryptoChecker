"""Message catalogs for the user interface, English and Spanish of Spain.

``MESSAGES[key] = {"en": ..., "es": ...}``. Keys are grouped by a dotted prefix
(``wiz.`` for the wizard, and more as other surfaces are translated). Every key
must carry both languages; ``tests/test_i18n.py`` enforces it.

Placeholders use ``str.format`` syntax (``{name}``) and must match across
languages so either renders with the same arguments.
"""

from __future__ import annotations

from typing import Dict

MESSAGES: Dict[str, Dict[str, str]] = {
    # -- shared prompt primitives ------------------------------------------
    "ui.default_label_all": {"en": "all", "es": "todas"},
    "ui.default_label_none": {"en": "none", "es": "ninguna"},
    "ui.multi_hint": {
        "en": "  Type numbers separated by commas (e.g. 1,3,5), 'a' = all, 'n' = none.",
        "es": "  Escribe números separados por comas (p. ej. 1,3,5), 'a' = todas, 'n' = ninguna.",
    },
    "ui.multi_prompt": {
        "en": "Selection [Enter = {label}]: ",
        "es": "Selección [Enter = {label}]: ",
    },
    "ui.multi_bad_token": {
        "en": "  '{token}' is not valid; use numbers between 1 and {n}, 'a' or 'n'.",
        "es": "  '{token}' no es válido; usa números entre 1 y {n}, 'a' o 'n'.",
    },
    "ui.choice_prompt": {
        "en": "Pick a number [Enter = default]: ",
        "es": "Elige un número [Enter = por defecto]: ",
    },
    "ui.choice_default_mark": {"en": "  (default)", "es": "  (por defecto)"},
    "ui.choice_out_of_range": {
        "en": "  Type a number between 1 and {n}.",
        "es": "  Escribe un número entre 1 y {n}.",
    },
    "ui.yes_no_default_yes": {"en": "Y/n", "es": "S/n"},
    "ui.yes_no_default_no": {"en": "y/N", "es": "s/N"},
    "ui.yes_no_retry": {"en": "  Answer y or n.", "es": "  Responde s o n."},
    "ui.int_retry": {"en": "  Type a whole number.", "es": "  Escribe un número entero."},
    # -- wizard, header ----------------------------------------------------
    "wiz.title": {
        "en": "=== sshCryptoChecker wizard ===",
        "es": "=== Asistente de sshCryptoChecker ===",
    },
    "wiz.intro": {
        "en": "Answer the questions; at the end you will see the command and can run it.",
        "es": "Responde a las preguntas; al final verás el comando y podrás lanzarlo.",
    },
    "wiz.default_hint": {
        "en": "Enter accepts the default value shown in brackets.",
        "es": "Enter acepta el valor por defecto entre corchetes.",
    },
    # -- wizard, sections --------------------------------------------------
    "wiz.sec_targets": {"en": "-- Targets --", "es": "-- Objetivos --"},
    "wiz.sec_credentials": {"en": "-- Credentials --", "es": "-- Credenciales --"},
    "wiz.sec_profiles": {"en": "-- Standards --", "es": "-- Normativas --"},
    "wiz.sec_output": {"en": "-- Output --", "es": "-- Salida --"},
    "wiz.sec_remote": {"en": "-- Remote checks --", "es": "-- Comprobaciones remotas --"},
    "wiz.sec_presentation": {"en": "-- Presentation --", "es": "-- Presentación --"},
    "wiz.sec_scanning": {"en": "-- Scanning --", "es": "-- Escaneo --"},
    "wiz.sec_connection": {"en": "-- Connection --", "es": "-- Conexión --"},
    "wiz.sec_policy": {"en": "-- Policy and plugins --", "es": "-- Política y plugins --"},
    "wiz.sec_history": {"en": "-- History / comparison --", "es": "-- Histórico / comparación --"},
    # -- wizard, targets ---------------------------------------------------
    "wiz.target_prompt": {
        "en": "Target(s) to scan (host, host:port, IP...; separate several with spaces)",
        "es": "Objetivo(s) a escanear (host, host:puerto, IP...; separa varios con espacios)",
    },
    "wiz.inventory_prompt": {
        "en": "Inventory file (one target per line; empty for none)",
        "es": "Fichero de inventario (una línea por objetivo; vacío para ninguno)",
    },
    "wiz.no_target_hint": {
        "en": "  With no target and no inventory there is nothing to scan; add at least one.",
        "es": "  Sin objetivo ni inventario no hay nada que escanear; añade al menos uno.",
    },
    "wiz.target_reprompt": {"en": "Target(s) to scan", "es": "Objetivo(s) a escanear"},
    "wiz.cancelled_no_target": {
        "en": "Cancelled: no target was given.",
        "es": "Cancelado: no se indicó ningún objetivo.",
    },
    "wiz.port_prompt": {
        "en": "Default port (for targets without one)",
        "es": "Puerto por defecto (para objetivos sin puerto)",
    },
    "wiz.user_prompt": {
        "en": "Default user (empty for none)",
        "es": "Usuario por defecto (vacío = ninguno)",
    },
    # -- wizard, credentials -----------------------------------------------
    "wiz.credentials_gate": {
        "en": "Configure credentials or a key (to probe authentication or --audit-config)?",
        "es": "¿Configurar credenciales o una clave (para sondear autenticación o --audit-config)?",
    },
    "wiz.auth_mode": {
        "en": "Default authentication mode",
        "es": "Modo de autenticación por defecto",
    },
    "wiz.identity_prompt": {
        "en": "Private key file (-i, empty for none)",
        "es": "Fichero de clave privada (-i, vacío = ninguno)",
    },
    "wiz.password_file_prompt": {
        "en": "File with the password (--password-file, empty for none)",
        "es": "Fichero con la contraseña (--password-file, vacío = ninguno)",
    },
    "wiz.password_env_prompt": {
        "en": "Environment variable with the password (--password-env, empty for none)",
        "es": "Variable de entorno con la contraseña (--password-env, vacío = ninguna)",
    },
    # -- wizard, profiles --------------------------------------------------
    "wiz.profiles_intro1": {
        "en": "Two different things that combine; first one, then the other:",
        "es": "Son dos cosas distintas, que se combinan; primero una, luego la otra:",
    },
    "wiz.profiles_intro2": {
        "en": "  - EVALUATE (--profile): which standards are measured and SHOWN in the",
        "es": "  · EVALUAR (--profile): contra qué normas se mide y se MUESTRAN en el",
    },
    "wiz.profiles_intro3": {
        "en": "    report. It does not change the process result, only what is shown.",
        "es": "    informe. No cambia el resultado del proceso, solo qué se enseña.",
    },
    "wiz.profiles_intro4": {
        "en": "  - REQUIRE (--require-profile): of those evaluated, which make the",
        "es": "  · EXIGIR (--require-profile): de las evaluadas, cuáles hacen que el",
    },
    "wiz.profiles_intro5": {
        "en": "    process EXIT WITH ERROR (code 1) if not met. The CI gate. You can",
        "es": "    proceso TERMINE CON ERROR (código 1) si no se cumplen. Es la puerta",
    },
    "wiz.profiles_intro6": {
        "en": "    evaluate without requiring.",
        "es": "    para bloquear un despliegue en CI. Puedes evaluar sin exigir.",
    },
    "wiz.evaluate_lead": {
        "en": "First, what is EVALUATED (shown in the report):",
        "es": "Primero, qué se EVALÚA (se mostrará en el informe):",
    },
    "wiz.evaluate_prompt": {
        "en": "Which standards to evaluate? (default: all)",
        "es": "¿Contra qué normativas se evalúa? (por defecto, todas)",
    },
    "wiz.require_lead": {
        "en": "Now, what is REQUIRED (of those evaluated; the only thing that fails the process):",
        "es": "Ahora, qué se EXIGE (de entre las evaluadas; lo único que hace fallar el proceso):",
    },
    "wiz.require_gate": {
        "en": "Require conformance to any standard (exit 1 if a target does not meet it)?",
        "es": "¿Exigir conformidad con alguna normativa (código 1 si algún objetivo no la cumple)?",
    },
    "wiz.require_prompt": {
        "en": "Standards to require (only from those evaluated)",
        "es": "Normativas a exigir (solo de entre las evaluadas)",
    },
    # -- wizard, output ----------------------------------------------------
    "wiz.format_prompt": {
        "en": "Output format(s) (default: console)",
        "es": "Formato(s) de salida (por defecto, console)",
    },
    "wiz.write_file_gate": {
        "en": "Write the output to a file?",
        "es": "¿Escribir la salida a un fichero?",
    },
    "wiz.output_path_prompt": {
        "en": "Output path (base name if several formats)",
        "es": "Ruta de salida (base si hay varios formatos)",
    },
    "wiz.fail_on_prompt": {
        "en": "Fail (exit 1) on findings of a given severity?",
        "es": "¿Fallar (código 1) si hay hallazgos de cierta severidad?",
    },
    # -- wizard, remote checks ---------------------------------------------
    "wiz.remote_gate": {
        "en": "Configure additional remote checks?",
        "es": "¿Configurar comprobaciones remotas adicionales?",
    },
    "wiz.all_checks_gate": {
        "en": "All the non-intrusive ones (--all-checks)?",
        "es": "¿Todas las no intrusivas (--all-checks)?",
    },
    "wiz.remote_pick": {"en": "Pick checks", "es": "Elige comprobaciones"},
    "wiz.chk_auth_methods": {
        "en": "authentication methods the server accepts",
        "es": "métodos de autenticación que acepta el servidor",
    },
    "wiz.chk_sshfp": {
        "en": "compare host keys with SSHFP records in DNS",
        "es": "comparar claves de host con registros SSHFP en DNS",
    },
    "wiz.chk_known_hosts": {
        "en": "compare host keys with known_hosts",
        "es": "comparar claves de host con known_hosts",
    },
    "wiz.chk_login_grace": {
        "en": "measure how long an unauthenticated connection is held open",
        "es": "medir cuánto mantiene abierta una conexión sin autenticar",
    },
    "wiz.chk_audit_client": {
        "en": "also audit this machine's ssh client",
        "es": "auditar también el cliente ssh de esta máquina",
    },
    "wiz.chk_max_startups": {
        "en": "probe how many unauthenticated connections it accepts (uses slots)",
        "es": "sondear cuántas conexiones sin autenticar acepta (ocupa ranuras)",
    },
    "wiz.chk_audit_config": {
        "en": "log in and audit the effective config with 'sshd -T' (needs credentials)",
        "es": "iniciar sesión y auditar la config efectiva con 'sshd -T' (necesita credenciales)",
    },
    # -- wizard, presentation ----------------------------------------------
    "wiz.presentation_gate": {
        "en": "Adjust the presentation (colour, notes, summary...)?",
        "es": "¿Ajustar la presentación (color, notas, resumen...)?",
    },
    "wiz.presentation_pick": {"en": "Pick options", "es": "Elige opciones"},
    "wiz.pres_summary_only": {"en": "summary table only", "es": "solo la tabla resumen"},
    "wiz.pres_notes": {
        "en": "include each algorithm's explanation",
        "es": "incluir la explicación de cada algoritmo",
    },
    "wiz.pres_no_config": {
        "en": "omit the generated sshd_config",
        "es": "omitir el sshd_config generado",
    },
    "wiz.pres_no_color": {"en": "no colour", "es": "sin color"},
    "wiz.pres_verbose": {
        "en": "report each target as it finishes",
        "es": "informar de cada objetivo al terminar",
    },
    "wiz.pres_quiet": {
        "en": "silence progress messages",
        "es": "silenciar los mensajes de progreso",
    },
    # -- wizard, scanning --------------------------------------------------
    "wiz.scanning_gate": {
        "en": "Adjust scanning options (timeout, concurrency...)?",
        "es": "¿Ajustar opciones de escaneo (timeout, concurrencia...)?",
    },
    "wiz.timeout_prompt": {
        "en": "Per-connection timeout (seconds)",
        "es": "Timeout por conexión (segundos)",
    },
    "wiz.concurrency_prompt": {"en": "Targets in parallel", "es": "Objetivos en paralelo"},
    "wiz.retries_prompt": {"en": "Retries per target", "es": "Reintentos por objetivo"},
    "wiz.no_host_keys_gate": {
        "en": "Skip host key retrieval (--no-host-keys)?",
        "es": "¿Omitir la obtención de claves de host (--no-host-keys)?",
    },
    "wiz.no_cert_probes_gate": {
        "en": "Skip only the certificate probes (--no-cert-probes)?",
        "es": "¿Omitir solo las sondas de certificado (--no-cert-probes)?",
    },
    # -- wizard, connection ------------------------------------------------
    "wiz.connection_gate": {
        "en": "Connection options (bastion, source IP, IPv4/IPv6)?",
        "es": "¿Opciones de conexión (bastión, IP de origen, IPv4/IPv6)?",
    },
    "wiz.jump_prompt": {
        "en": "Bastion (-J [user@]host[:port], empty for none)",
        "es": "Bastión (-J [usuario@]host[:puerto], vacío = ninguno)",
    },
    "wiz.source_ip_prompt": {
        "en": "Source IP (--source-ip, empty for none)",
        "es": "IP de origen (--source-ip, vacío = ninguna)",
    },
    "wiz.family_prompt": {"en": "IP family?", "es": "¿Familia de IP?"},
    "wiz.family_both": {"en": "both", "es": "ambas"},
    "wiz.family_ipv4": {"en": "IPv4 only", "es": "solo IPv4"},
    "wiz.family_ipv6": {"en": "IPv6 only", "es": "solo IPv6"},
    # -- wizard, policy ----------------------------------------------------
    "wiz.policy_gate": {
        "en": "Custom algorithm policy or plugins?",
        "es": "¿Política de algoritmos propia o plugins?",
    },
    "wiz.config_prompt": {
        "en": "Policy file (--config, empty for the bundled one)",
        "es": "Fichero de política (--config, vacío = la incorporada)",
    },
    "wiz.plugin_dir_prompt": {
        "en": "Plugin directory (--plugin-dir, empty for none)",
        "es": "Directorio de plugins (--plugin-dir, vacío = ninguno)",
    },
    # -- wizard, history ---------------------------------------------------
    "wiz.history_gate": {
        "en": "History or comparison with an earlier report?",
        "es": "¿Histórico o comparación con un informe anterior?",
    },
    "wiz.history_prompt": {
        "en": "History file (--history, empty for none)",
        "es": "Fichero de histórico (--history, vacío = ninguno)",
    },
    "wiz.compare_prompt": {
        "en": "Compare with an earlier report/history (--compare, empty for no)",
        "es": "Comparar con un informe/histórico anterior (--compare, vacío = no)",
    },
    "wiz.regression_gate": {
        "en": "Fail if any target got worse (--fail-on-regression)?",
        "es": "¿Fallar si algún objetivo empeoró (--fail-on-regression)?",
    },
    # -- wizard, closing ---------------------------------------------------
    "wiz.command_header": {"en": "=== Command ===", "es": "=== Comando ==="},
    "wiz.command_save": {
        "en": "Save it to run again without the wizard.",
        "es": "Guárdalo para volver a lanzarlo sin el asistente.",
    },
    "wiz.launch_gate": {"en": "Run it now?", "es": "¿Lanzarlo ahora?"},
    "wiz.declined": {
        "en": "All right. Copy the command above whenever you want to run it.",
        "es": "De acuerdo. Copia el comando de arriba cuando quieras ejecutarlo.",
    },
    # -- CLI: description and epilog ---------------------------------------
    "cli.desc": {
        "en": (
            "Audit the cryptography an SSH server is willing to negotiate: key exchange,\n"
            "host key, cipher, MAC and compression algorithms, plus host key sizes, strict\n"
            "key exchange and post-quantum readiness.\n"
            "\n"
            "Reports an effective security strength in bits (NIST SP 800-57) and conformance\n"
            "against published standards: NIST SP 800-131A, FIPS 140-3, CNSA 2.0,\n"
            "BSI TR-02102-4, ENS (MEDIA and ALTA), PCI DSS v4.0, the CIS benchmark and the\n"
            "ANSSI RGS. See --list-profiles.\n"
            "\n"
            "Each server is classified against an editable policy file, so the lists can be\n"
            "kept current without touching the code. No authentication is ever attempted and\n"
            "no user data is exchanged; scans do appear in the server's auth log as a\n"
            "connection closed before authentication.\n"
        ),
        "es": (
            "Audita la criptografía que un servidor SSH está dispuesto a negociar: intercambio\n"
            "de claves, clave de host, algoritmos de cifrado, MAC y compresión, además del\n"
            "tamaño de la clave de host, el intercambio estricto de claves y la preparación\n"
            "poscuántica.\n"
            "\n"
            "Informa de una fuerza de seguridad efectiva en bits (NIST SP 800-57) y de la\n"
            "conformidad con normas publicadas: NIST SP 800-131A, FIPS 140-3, CNSA 2.0,\n"
            "BSI TR-02102-4, ENS (MEDIA y ALTA), PCI DSS v4.0, el benchmark CIS y el RGS de\n"
            "ANSSI. Ver --list-profiles.\n"
            "\n"
            "Cada servidor se clasifica según un fichero de política editable, de modo que las\n"
            "listas se mantienen al día sin tocar el código. Nunca se intenta autenticar ni se\n"
            "intercambian datos de usuario; los escaneos sí aparecen en el registro de\n"
            "autenticación del servidor como una conexión cerrada antes de autenticarse.\n"
        ),
    },
    "cli.epilog": {
        "en": (
            "examples:\n"
            "  %(prog)s server.example.com\n"
            "      Scan one host on the default port and print the report to the terminal.\n"
            "\n"
            "  %(prog)s 192.0.2.10:2222 [2001:db8::1]:22 backup.example.com\n"
            "      Scan several hosts at once. IPv6 addresses need brackets when a port is given.\n"
            "\n"
            "  %(prog)s -f inventory.txt --format html -o audit.html\n"
            "      Scan every host listed in a file and write a shareable HTML report.\n"
            "\n"
            "  %(prog)s -f inventory.txt --format json --format html -o reports/audit\n"
            "      Write reports/audit.json and reports/audit.html in the same run.\n"
            "\n"
            "  %(prog)s --config my-policy.json server.example.com\n"
            "      Use a custom algorithm policy instead of the bundled one.\n"
            "\n"
            "  %(prog)s -f inventory.txt --format json -o out.json --fail-on high -q\n"
            "      Typical CI usage: silent, machine readable, "
            "non-zero exit on a serious finding.\n"
            "\n"
            "  %(prog)s --export-policy my-policy.json\n"
            "      Write a copy of the bundled policy so the algorithm lists can be edited.\n"
            "\n"
            "  %(prog)s --list-profiles\n"
            "      Show the standards a server can be measured against: NIST, FIPS, CNSA,\n"
            "      BSI, ENS, PCI DSS, CIS, ANSSI and ISO.\n"
            "\n"
            "  %(prog)s -f inventory.txt --require-profile fips-140-3 --fail-on high\n"
            "      Fail the run unless every host conforms to FIPS 140-3 approved algorithms.\n"
            "\n"
            "target file format:\n"
            "  One target per line. '#' starts a comment. Anything after the first\n"
            "  whitespace-separated token becomes a label shown in the report:\n"
            "\n"
            "      # production\n"
            "      web01.example.com:22      web frontend\n"
            "      192.0.2.10                database\n"
            "      [2001:db8::1]:2222        edge router\n"
            "\n"
            "exit codes:\n"
            "  0  success            1  findings at or above --fail-on\n"
            "  2  usage error        3  a target could not be scanned\n"
        ),
        "es": (
            "ejemplos:\n"
            "  %(prog)s servidor.example.com\n"
            "      Escanear un host en el puerto por defecto e imprimir el informe "
            "en la terminal.\n"
            "\n"
            "  %(prog)s 192.0.2.10:2222 [2001:db8::1]:22 backup.example.com\n"
            "      Escanear varios hosts a la vez. Las IPv6 necesitan corchetes si llevan puerto.\n"
            "\n"
            "  %(prog)s -f inventario.txt --format html -o auditoria.html\n"
            "      Escanear cada host de un fichero y escribir un informe HTML para compartir.\n"
            "\n"
            "  %(prog)s -f inventario.txt --format json --format html -o informes/auditoria\n"
            "      Escribir informes/auditoria.json e informes/auditoria.html en la misma pasada.\n"
            "\n"
            "  %(prog)s --config mi-politica.json servidor.example.com\n"
            "      Usar una política de algoritmos propia en vez de la incorporada.\n"
            "\n"
            "  %(prog)s -f inventario.txt --format json -o salida.json --fail-on high -q\n"
            "      Uso típico en CI: silencioso, legible por máquina, código distinto de cero\n"
            "      ante un hallazgo grave.\n"
            "\n"
            "  %(prog)s --export-policy mi-politica.json\n"
            "      Escribir una copia de la política incorporada para editar las listas.\n"
            "\n"
            "  %(prog)s --list-profiles\n"
            "      Mostrar las normas contra las que se puede medir un servidor: NIST, FIPS,\n"
            "      CNSA, BSI, ENS, PCI DSS, CIS, ANSSI e ISO.\n"
            "\n"
            "  %(prog)s -f inventario.txt --require-profile fips-140-3 --fail-on high\n"
            "      Hacer fallar la pasada salvo que cada host cumpla los algoritmos aprobados\n"
            "      por FIPS 140-3.\n"
            "\n"
            "formato del fichero de objetivos:\n"
            "  Un objetivo por línea. '#' inicia un comentario. Todo lo que sigue al primer\n"
            "  token separado por espacios se convierte en una etiqueta que se muestra en el\n"
            "  informe:\n"
            "\n"
            "      # producción\n"
            "      web01.example.com:22      frontend web\n"
            "      192.0.2.10                base de datos\n"
            "      [2001:db8::1]:2222        router de borde\n"
            "\n"
            "códigos de salida:\n"
            "  0  éxito               1  hallazgos en --fail-on o por encima\n"
            "  2  error de uso        3  no se pudo escanear un objetivo\n"
        ),
    },
    # -- CLI: runtime messages --------------------------------------------
    "cli.err.wizard_needs_tty": {
        "en": (
            "error: --wizard needs an interactive terminal; use the options directly "
            "in a script.\n"
        ),
        "es": (
            "error: --wizard necesita un terminal interactivo; usa las opciones "
            "directamente en un script.\n"
        ),
    },
    # -- CLI: argument-group titles ---------------------------------------
    "cli.grp.sources": {"en": "target sources", "es": "orígenes de objetivos"},
    "cli.grp.scanning": {"en": "scanning", "es": "escaneo"},
    "cli.grp.remote": {
        "en": "additional remote checks",
        "es": "comprobaciones remotas adicionales",
    },
    "cli.grp.policy": {"en": "algorithm policy", "es": "política de algoritmos"},
    "cli.grp.output": {"en": "output", "es": "salida"},
    "cli.grp.behaviour": {"en": "exit behaviour", "es": "comportamiento de salida"},
    # -- CLI: metavars -----------------------------------------------------
    "cli.mv.target": {"en": "TARGET", "es": "OBJETIVO"},
    "cli.mv.file": {"en": "FILE", "es": "FICHERO"},
    "cli.mv.name": {"en": "NAME", "es": "NOMBRE"},
    "cli.mv.seconds": {"en": "SECONDS", "es": "SEGUNDOS"},
    "cli.mv.n": {"en": "N", "es": "N"},
    "cli.mv.addr": {"en": "ADDR", "es": "DIRECCIÓN"},
    "cli.mv.path": {"en": "PATH", "es": "RUTA"},
    "cli.mv.port": {"en": "PORT", "es": "PUERTO"},
    "cli.mv.dir": {"en": "DIR", "es": "DIR"},
    "cli.mv.fmt": {"en": "FMT", "es": "FMT"},
    "cli.mv.var": {"en": "VAR", "es": "VAR"},
    "cli.mv.id": {"en": "ID", "es": "ID"},
    "cli.mv.opt": {"en": "OPT", "es": "OPCIÓN"},
    "cli.mv.jump": {"en": "[USER@]HOST[:PORT]", "es": "[USUARIO@]HOST[:PUERTO]"},
    # -- CLI: option help --------------------------------------------------
    "cli.h.targets": {
        "en": "host, host:port, IP, IP:port or [IPv6]:port",
        "es": "host, host:puerto, IP, IP:puerto o [IPv6]:puerto",
    },
    "cli.h.wizard": {
        "en": (
            "interactive mode: build the command by answering questions (targets, standards, "
            "formats, checks...), show it so you can copy it, and offer to run it"
        ),
        "es": (
            "modo interactivo: construye el comando respondiendo preguntas (objetivos, "
            "normativas, formatos, comprobaciones...), lo muestra para copiarlo y ofrece "
            "lanzarlo"
        ),
    },
    "cli.h.lang": {
        "en": (
            "language of the interface and the reports: 'en' (default) or 'es'. Without it, "
            "the system language (LANG/LC_ALL) is used if it is Spanish, otherwise English"
        ),
        "es": (
            "idioma de la interfaz y los informes: 'en' (por defecto) o 'es'. Sin él se usa "
            "el idioma del sistema (LANG/LC_ALL) si es español, y si no, inglés"
        ),
    },
    "cli.h.file": {
        "en": "file with one target per line ('-' reads standard input); may be repeated",
        "es": "fichero con un objetivo por línea ('-' lee la entrada estándar); repetible",
    },
    "cli.h.user": {
        "en": "default account for targets that do not set user= in the inventory",
        "es": "cuenta por defecto para objetivos que no fijan user= en el inventario",
    },
    "cli.h.auth": {
        "en": (
            "default authentication mode: 'none' for anonymous checks only, 'key' for public "
            "key, 'password', or 'any' to let the client decide (default: %(default)s)"
        ),
        "es": (
            "modo de autenticación por defecto: 'none' solo comprobaciones anónimas, 'key' "
            "clave pública, 'password', o 'any' para dejar decidir al cliente (por defecto: "
            "%(default)s)"
        ),
    },
    "cli.h.identity": {
        "en": "default private key file for targets that do not set key=",
        "es": "fichero de clave privada por defecto para objetivos que no fijan key=",
    },
    "cli.h.password_file": {
        "en": "read the default password from the first line of FILE",
        "es": "leer la contraseña por defecto de la primera línea del FICHERO",
    },
    "cli.h.password_env": {
        "en": "read the default password from the environment variable VAR",
        "es": "leer la contraseña por defecto de la variable de entorno VAR",
    },
    "cli.h.port": {
        "en": "default port for targets that do not specify one (default: %(default)s)",
        "es": "puerto por defecto para objetivos que no indican uno (por defecto: %(default)s)",
    },
    "cli.h.timeout": {
        "en": "per-connection timeout (default: %(default)s)",
        "es": "tiempo máximo por conexión (por defecto: %(default)s)",
    },
    "cli.h.concurrency": {
        "en": "targets scanned in parallel (default: %(default)s)",
        "es": "objetivos escaneados en paralelo (por defecto: %(default)s)",
    },
    "cli.h.retries": {
        "en": "retries per target on failure (default: %(default)s)",
        "es": "reintentos por objetivo ante un fallo (por defecto: %(default)s)",
    },
    "cli.h.no_host_keys": {
        "en": "skip host key retrieval (faster, but key sizes and fingerprints are not checked)",
        "es": (
            "no obtener las claves de host (más rápido, pero no se comprueban "
            "tamaños ni huellas)"
        ),
    },
    "cli.h.no_cert_probes": {
        "en": "skip host certificate algorithms when retrieving host keys",
        "es": "omitir los algoritmos de certificado de host al obtener las claves",
    },
    "cli.h.ipv4": {
        "en": "resolve target names to IPv4 only",
        "es": "resolver los nombres de objetivo solo a IPv4",
    },
    "cli.h.ipv6": {
        "en": "resolve target names to IPv6 only",
        "es": "resolver los nombres de objetivo solo a IPv6",
    },
    "cli.h.jump_host": {
        "en": (
            "reach every target through this bastion. The scan opens its own sockets, so "
            "ProxyJump cannot apply to it; a local port forward is opened through the bastion "
            "instead, and the report still names the real target. --max-startups is skipped "
            "when this is used, because through a forward it would measure the bastion"
        ),
        "es": (
            "llegar a cada objetivo a través de este bastión. El escaneo abre sus propios "
            "sockets, así que ProxyJump no se le aplica; en su lugar se abre un reenvío de "
            "puerto local a través del bastión, y el informe sigue nombrando al objetivo real. "
            "--max-startups se omite al usarlo, porque a través de un reenvío mediría el bastión"
        ),
    },
    "cli.h.jump_option": {
        "en": (
            "an extra option for the connection to the bastion, passed straight to ssh; "
            "repeat for several. Use the --jump-option=VALUE form, since the value itself "
            "starts with a dash: --jump-option=-oIdentityFile=~/.ssh/bastion. Needed only "
            "when the bastion is not already described in ssh_config"
        ),
        "es": (
            "una opción extra para la conexión al bastión, pasada tal cual a ssh; repite para "
            "varias. Usa la forma --jump-option=VALOR, ya que el valor empieza por guion: "
            "--jump-option=-oIdentityFile=~/.ssh/bastion. Solo hace falta si el bastión no "
            "está ya descrito en ssh_config"
        ),
    },
    "cli.h.source_ip": {
        "en": "local address to originate connections from",
        "es": "dirección local desde la que originar las conexiones",
    },
    "cli.h.auth_methods": {
        "en": (
            "enumerate the authentication methods the server accepts. This completes a key "
            "exchange and sends a deliberately failing 'none' request, so it leaves a "
            "failed-login entry in the server's log"
        ),
        "es": (
            "enumerar los métodos de autenticación que acepta el servidor. Completa un "
            "intercambio de claves y envía una petición 'none' que falla a propósito, así que "
            "deja una entrada de inicio de sesión fallido en el registro del servidor"
        ),
    },
    "cli.h.sshfp": {
        "en": "compare the host keys against SSHFP records published in DNS",
        "es": "contrastar las claves de host con los registros SSHFP publicados en DNS",
    },
    "cli.h.audit_client": {
        "en": (
            "also audit this machine's own ssh client with 'ssh -G': a permissive client "
            "(StrictHostKeyChecking no, a forwarded agent, weak algorithms) undoes much of "
            "what a hardened server buys. Resolves only, it opens no connection"
        ),
        "es": (
            "auditar también el propio cliente ssh de esta máquina con 'ssh -G': un cliente "
            "permisivo (StrictHostKeyChecking no, un agente reenviado, algoritmos débiles) "
            "echa a perder buena parte de lo que aporta un servidor endurecido. Solo resuelve, "
            "no abre ninguna conexión"
        ),
    },
    "cli.h.client_config": {
        "en": (
            "audit this ssh_config instead of the current user's, which is how a "
            "configuration is checked before it is deployed rather than after"
        ),
        "es": (
            "auditar este ssh_config en vez del del usuario actual, que es como se comprueba "
            "una configuración antes de desplegarla en lugar de después"
        ),
    },
    "cli.h.dns_server": {
        "en": (
            "ask this name server for SSHFP records instead of the ones in "
            "/etc/resolv.conf; repeat for several. Useful when the records live in an "
            "internal zone, or to check an authoritative server before a rollout"
        ),
        "es": (
            "pedir los registros SSHFP a este servidor de nombres en vez de a los de "
            "/etc/resolv.conf; repite para varios. Útil cuando los registros viven en una "
            "zona interna, o para comprobar un servidor autoritativo antes de un despliegue"
        ),
    },
    "cli.h.login_grace": {
        "en": (
            "measure how long the server holds an unauthenticated connection open "
            "(default wait: %(const)s seconds; runs concurrently across targets)"
        ),
        "es": (
            "medir cuánto mantiene abierta el servidor una conexión sin autenticar "
            "(espera por defecto: %(const)s segundos; se ejecuta en paralelo entre objetivos)"
        ),
    },
    "cli.h.known_hosts": {
        "en": (
            "compare the host keys against a known_hosts file (default: the files OpenSSH "
            "reads, ~/.ssh/known_hosts and /etc/ssh/ssh_known_hosts)"
        ),
        "es": (
            "contrastar las claves de host con un fichero known_hosts (por defecto: los que "
            "lee OpenSSH, ~/.ssh/known_hosts y /etc/ssh/ssh_known_hosts)"
        ),
    },
    "cli.h.max_startups": {
        "en": (
            "probe how many concurrent unauthenticated connections the server accepts, up to N "
            "(default: %(const)s). This briefly occupies the server's pre-authentication slots"
        ),
        "es": (
            "sondear cuántas conexiones simultáneas sin autenticar acepta el servidor, hasta N "
            "(por defecto: %(const)s). Esto ocupa brevemente las ranuras de preautenticación "
            "del servidor"
        ),
    },
    "cli.h.audit_config": {
        "en": (
            "log in and audit the effective configuration with 'sshd -T'. Needs credentials "
            "(see --user and the inventory options) and an account that is root or has "
            "passwordless sudo for sshd. This is the only check that authenticates"
        ),
        "es": (
            "iniciar sesión y auditar la configuración efectiva con 'sshd -T'. Necesita "
            "credenciales (ver --user y las opciones de inventario) y una cuenta que sea root "
            "o tenga sudo sin contraseña para sshd. Es la única comprobación que se autentica"
        ),
    },
    "cli.h.all_checks": {
        "en": (
            "run every non-intrusive remote check: --auth-methods, --sshfp, --known-hosts and "
            "--login-grace. --max-startups is excluded because it occupies the server's "
            "connection slots"
        ),
        "es": (
            "ejecutar todas las comprobaciones remotas no intrusivas: --auth-methods, --sshfp, "
            "--known-hosts y --login-grace. --max-startups queda fuera porque ocupa las ranuras "
            "de conexión del servidor"
        ),
    },
    "cli.h.config": {
        "en": (
            "policy file with the algorithm classification "
            "(default: ${env_var}, ./ssh-crypto-checker.json, "
            "~/.config/ssh-crypto-checker/algorithms.json, "
            "/etc/ssh-crypto-checker/algorithms.json, "
            "then the bundled copy)"
        ),
        "es": (
            "fichero de política con la clasificación de algoritmos "
            "(por defecto: ${env_var}, ./ssh-crypto-checker.json, "
            "~/.config/ssh-crypto-checker/algorithms.json, "
            "/etc/ssh-crypto-checker/algorithms.json, "
            "y luego la copia incorporada)"
        ),
    },
    "cli.h.export_policy": {
        "en": "write a copy of the bundled policy to FILE and exit",
        "es": "escribir una copia de la política incorporada en FICHERO y salir",
    },
    "cli.h.show_policy": {
        "en": "print a summary of the loaded policy and exit",
        "es": "imprimir un resumen de la política cargada y salir",
    },
    "cli.h.plugin_dir": {
        "en": (
            "load detection plugins from this directory as well; repeat for several. "
            "Plugins run as whoever runs the scan, so the working directory is never "
            "searched and a directory writable by others is refused"
        ),
        "es": (
            "cargar plugins de detección también de este directorio; repite para varios. "
            "Los plugins se ejecutan como quien lanza el escaneo, así que nunca se busca en "
            "el directorio de trabajo y se rechaza un directorio en el que otros puedan escribir"
        ),
    },
    "cli.h.list_plugins": {
        "en": "list the detection plugins that would be loaded, and where from, then exit",
        "es": "listar los plugins de detección que se cargarían, y desde dónde, y salir",
    },
    "cli.h.list_vulnerabilities": {
        "en": "list the known vulnerabilities the policy checks for, and exit",
        "es": "listar las vulnerabilidades conocidas que comprueba la política, y salir",
    },
    "cli.h.list_profiles": {
        "en": "list the conformance profiles the policy defines, and exit",
        "es": "listar los perfiles de conformidad que define la política, y salir",
    },
    "cli.h.format": {
        "en": (
            "output format: console, json, txt, html, csv, sarif, inventory (a PCI DSS "
            "12.3.3 cryptographic inventory) or openmetrics (Prometheus exposition, for "
            "node_exporter's textfile collector). Repeat or comma-separate "
            "for several (default: console)"
        ),
        "es": (
            "formato de salida: console, json, txt, html, csv, sarif, inventory (un "
            "inventario criptográfico PCI DSS 12.3.3) u openmetrics (exposición Prometheus, "
            "para el colector de ficheros de texto de node_exporter). Repite o separa por "
            "comas para varios (por defecto: console)"
        ),
    },
    "cli.h.output": {
        "en": (
            "write the report to PATH instead of standard output. Each format appends its "
            "extension unless PATH already ends with it, so '-o informe --format html' writes "
            "'informe.html'; with several formats PATH is the shared base name"
        ),
        "es": (
            "escribir el informe en RUTA en vez de en la salida estándar. Cada formato añade su "
            "extensión salvo que RUTA ya termine en ella, así que '-o informe --format html' "
            "escribe 'informe.html'; con varios formatos RUTA es el nombre base compartido"
        ),
    },
    "cli.h.color": {
        "en": "colourise terminal output (default: %(default)s)",
        "es": "colorear la salida de la terminal (por defecto: %(default)s)",
    },
    "cli.h.no_color": {
        "en": "shorthand for --color never",
        "es": "atajo de --color never",
    },
    "cli.h.summary_only": {
        "en": "print only the summary table, without per-target detail",
        "es": "imprimir solo la tabla resumen, sin el detalle por objetivo",
    },
    "cli.h.notes": {
        "en": "include the policy's explanation of every algorithm in the text output",
        "es": "incluir en la salida de texto la explicación de cada algoritmo según la política",
    },
    "cli.h.no_config_suggestions": {
        "en": "omit the generated sshd_config block",
        "es": "omitir el bloque de sshd_config generado",
    },
    "cli.h.quiet": {
        "en": "suppress progress messages on standard error",
        "es": "silenciar los mensajes de progreso en la salida de error estándar",
    },
    "cli.h.verbose": {
        "en": "report each target as it completes",
        "es": "informar de cada objetivo a medida que termina",
    },
    "cli.h.history": {
        "en": (
            "append this scan to a history file, one report per line. --compare accepts the "
            "same file and uses its most recent entry, so a series needs no separate baseline"
        ),
        "es": (
            "añadir este escaneo a un fichero de histórico, un informe por línea. --compare "
            "acepta el mismo fichero y usa su entrada más reciente, así que una serie no "
            "necesita una línea base aparte"
        ),
    },
    "cli.h.history_report": {
        "en": "with --history, print how the estate has moved across the recorded scans",
        "es": "con --history, mostrar cómo ha evolucionado el parque en los escaneos registrados",
    },
    "cli.h.compare": {
        "en": (
            "compare this scan against an earlier JSON report and show what changed: new and "
            "resolved findings, grade movement, algorithm and host key changes"
        ),
        "es": (
            "comparar este escaneo con un informe JSON anterior y mostrar qué cambió: hallazgos "
            "nuevos y resueltos, movimiento de nota, y cambios de algoritmos y de claves de host"
        ),
    },
    "cli.h.fail_on_regression": {
        "en": "with --compare, exit 1 if any target got worse than the baseline",
        "es": "con --compare, salir con 1 si algún objetivo empeoró respecto a la línea base",
    },
    "cli.h.profile": {
        "en": (
            "only evaluate these conformance profiles instead of all of them "
            "(see --list-profiles); may be repeated or comma-separated"
        ),
        "es": (
            "evaluar solo estos perfiles de conformidad en vez de todos "
            "(ver --list-profiles); repetible o separado por comas"
        ),
    },
    "cli.h.require_profile": {
        "en": (
            "exit with code 1 unless every target conforms to this profile "
            "(see --list-profiles); may be repeated or comma-separated"
        ),
        "es": (
            "salir con código 1 salvo que todos los objetivos cumplan este perfil "
            "(ver --list-profiles); repetible o separado por comas"
        ),
    },
    "cli.h.fail_on": {
        "en": (
            "exit with code 1 when a finding of this severity or worse is "
            "reported (default: %(default)s)"
        ),
        "es": (
            "salir con código 1 cuando se informe de un hallazgo de esta severidad o peor "
            "(por defecto: %(default)s)"
        ),
    },
    # -- reports: shared labels (human formats only) ----------------------
    # Machine formats (json/sarif/openmetrics/csv/inventory) keep the English
    # enum values, so these translations never reach a tool that parses them.
    "rep.verdict.secure": {"en": "SECURE", "es": "SEGURO"},
    "rep.verdict.acceptable": {"en": "ACCEPTABLE", "es": "ACEPTABLE"},
    "rep.verdict.weak": {"en": "WEAK", "es": "DÉBIL"},
    "rep.verdict.insecure": {"en": "INSECURE", "es": "INSEGURO"},
    "rep.verdict.unjudged": {"en": "UNJUDGED", "es": "SIN EVALUAR"},
    "rep.verdict.unreachable": {"en": "UNREACHABLE", "es": "INACCESIBLE"},
    "rep.severity.critical": {"en": "CRITICAL", "es": "CRÍTICA"},
    "rep.severity.high": {"en": "HIGH", "es": "ALTA"},
    "rep.severity.medium": {"en": "MEDIUM", "es": "MEDIA"},
    "rep.severity.low": {"en": "LOW", "es": "BAJA"},
    "rep.severity.info": {"en": "INFO", "es": "INFO"},
    "rep.pq.enforced": {
        "en": "ENFORCED (only post-quantum methods offered)",
        "es": "EXIGIDO (solo se ofrecen métodos poscuánticos)",
    },
    "rep.pq.ready": {
        "en": "READY (hybrid method available)",
        "es": "PREPARADO (hay método híbrido disponible)",
    },
    "rep.pq.not_ready": {
        "en": "NOT READY (no post-quantum method offered)",
        "es": "NO PREPARADO (no se ofrece método poscuántico)",
    },
    "rep.pq.unknown": {"en": "UNKNOWN", "es": "DESCONOCIDO"},
    "rep.compression.disabled": {
        "en": "disabled (no compression offered)",
        "es": "desactivada (no se ofrece compresión)",
    },
    "rep.compression.post_auth": {
        "en": "enabled, after authentication only",
        "es": "activada, solo tras autenticarse",
    },
    "rep.compression.pre_auth": {
        "en": "enabled BEFORE authentication",
        "es": "activada ANTES de autenticarse",
    },
    "rep.compression.unknown": {"en": "unknown", "es": "desconocida"},
    # Row labels in the per-target overview.
    "rep.field.grade": {"en": "Grade", "es": "Nota"},
    "rep.field.strength": {"en": "Strength", "es": "Fuerza"},
    "rep.field.post_quantum": {"en": "Post-quantum", "es": "Poscuántico"},
    "rep.field.strict_kex": {"en": "Strict KEX", "es": "KEX estricto"},
    "rep.field.compression": {"en": "Compression", "es": "Compresión"},
    "rep.field.software": {"en": "Software", "es": "Software"},
    "rep.field.protocol": {"en": "Protocol", "es": "Protocolo"},
    "rep.field.login_banner": {"en": "Login banner", "es": "Banner de acceso"},
    # Section titles.
    "rep.sec.host_keys": {"en": "Host keys", "es": "Claves de host"},
    "rep.sec.remote_checks": {
        "en": "Additional remote checks",
        "es": "Comprobaciones remotas adicionales",
    },
    "rep.sec.conformance": {"en": "Standards conformance", "es": "Conformidad con normativas"},
    "rep.sec.vulnerabilities": {"en": "Known vulnerabilities", "es": "Vulnerabilidades conocidas"},
    "rep.sec.findings": {"en": "Findings", "es": "Hallazgos"},
    "rep.sec.recommendations": {"en": "Suggested sshd_config", "es": "sshd_config sugerido"},
    "rep.sec.summary": {"en": "Summary", "es": "Resumen"},
    # Summary table headers.
    "rep.sumhdr.target": {"en": "Target", "es": "Objetivo"},
    "rep.sumhdr.grade": {"en": "Grade", "es": "Nota"},
    "rep.sumhdr.score": {"en": "Score", "es": "Puntuación"},
    "rep.sumhdr.strength": {"en": "Strength", "es": "Fuerza"},
    "rep.sumhdr.verdict": {"en": "Verdict", "es": "Veredicto"},
    "rep.sumhdr.pq": {"en": "PQ", "es": "PQ"},
    "rep.sumhdr.strict_kex": {"en": "StrictKEX", "es": "KEXestricto"},
    "rep.sumhdr.software": {"en": "Software", "es": "Software"},
    # Short post-quantum / strict-kex words used in the summary table cells.
    "rep.pqcell.enforced": {"en": "enforced", "es": "exigido"},
    "rep.pqcell.ready": {"en": "ready", "es": "listo"},
    "rep.pqcell.no": {"en": "no", "es": "no"},
    "rep.cell.yes": {"en": "yes", "es": "sí"},
    "rep.cell.no": {"en": "no", "es": "no"},
    # -- reports: console renderer ----------------------------------------
    "rep.con.policy": {"en": "policy: {name} v{version}", "es": "política: {name} v{version}"},
    "rep.con.started": {"en": "started {when}", "es": "iniciado {when}"},
    "rep.con.rating_source": {
        "en": (
            "Where the rating comes from: the categories are defined in the policy "
            "(--show-policy), from published standards and known results, not invented in "
            "the report. {hint}docs/auditoria-integridad.md traces which document backs each "
            "judgement."
        ),
        "es": (
            "De dónde sale la valoración: las categorías se definen en la política "
            "(--show-policy), a partir de normas publicadas y resultados conocidos, no se "
            "inventan en el informe. {hint}docs/auditoria-integridad.md rastrea qué documento "
            "respalda cada juicio."
        ),
    },
    "rep.con.notes_hint": {
        "en": "Add --notes to print each algorithm's reason and source. ",
        "es": "Añade --notes para imprimir el motivo y la fuente de cada algoritmo. ",
    },
    "rep.con.unreachable": {"en": "UNREACHABLE", "es": "INACCESIBLE"},
    "rep.con.score": {"en": "score {score}", "es": "puntuación {score}"},
    "rep.con.software_unknown": {"en": "unknown", "es": "desconocido"},
    "rep.con.protocol": {"en": "SSH {version}", "es": "SSH {version}"},
    "rep.con.strength_unknown": {"en": "unknown", "es": "desconocida"},
    "rep.con.strength_value": {"en": "{bits}-bit — {label}", "es": "{bits} bits — {label}"},
    "rep.con.login_banner_lines": {
        "en": "{n} line(s) sent before the SSH identification",
        "es": "{n} línea(s) enviada(s) antes de la identificación SSH",
    },
    "rep.con.none_offered": {"en": "(none offered)", "es": "(no se ofrece ninguno)"},
    "rep.con.directions_differ": {
        "en": "(the two directions differ)",
        "es": "(las dos direcciones difieren)",
    },
    "rep.con.first_choice": {"en": "first choice: {name}", "es": "primera opción: {name}"},
    "rep.con.compression_preauth_note": {
        "en": "  — the decompressor is reachable by anyone who can connect",
        "es": "  — el descompresor es accesible por cualquiera que pueda conectar",
    },
    "rep.con.compression_postauth_note": {
        "en": "  — see the note if the session carries untrusted data",
        "es": "  — mira la nota si la sesión transporta datos no fiables",
    },
    "rep.con.none_offered_class": {"en": "(none offered)", "es": "(no se ofrece ninguno)"},
    "rep.con.signed_by": {"en": "signed by {type} {fp}", "es": "firmada por {type} {fp}"},
    "rep.con.signed_by_unreadable": {
        "en": "signed by a key whose type could not be read: {fp}",
        "es": "firmada por una clave cuyo tipo no se pudo leer: {fp}",
    },
    "rep.con.dh_group": {
        "en": "Diffie-Hellman group used during the probe: {bits} bits",
        "es": "grupo Diffie-Hellman usado durante el sondeo: {bits} bits",
    },
    # remote checks
    "rep.con.rc_auth_methods": {"en": "Auth methods", "es": "Métodos auth"},
    "rep.con.rc_login_grace": {"en": "Login grace", "es": "Gracia acceso"},
    "rep.con.rc_max_startups": {"en": "Max startups", "es": "Máx arranques"},
    "rep.con.rc_known_hosts": {"en": "known_hosts", "es": "known_hosts"},
    "rep.con.rc_sshd_t": {"en": "sshd -T", "es": "sshd -T"},
    "rep.con.rc_authorized_keys": {"en": "authorized_keys", "es": "authorized_keys"},
    "rep.con.rc_sshfp": {"en": "SSHFP (DNS)", "es": "SSHFP (DNS)"},
    "rep.con.auth_none_accepted": {
        "en": "NONE ACCEPTED — the server grants access to anyone",
        "es": "NINGUNO ACEPTADO — el servidor da acceso a cualquiera",
    },
    "rep.con.auth_as_user": {"en": "   (as user '{user}')", "es": "   (como usuario '{user}')"},
    "rep.con.auth_none_offered": {"en": "(none offered)", "es": "(no se ofrece ninguno)"},
    "rep.con.login_grace_hangup": {
        "en": "{secs}s before the server hangs up",
        "es": "{secs}s antes de que el servidor cuelgue",
    },
    "rep.con.max_startups_more_than": {
        "en": "more than {n} concurrent unauthenticated connections accepted",
        "es": "más de {n} conexiones simultáneas sin autenticar aceptadas",
    },
    "rep.con.max_startups_refused": {
        "en": "refused after {n} concurrent connections",
        "es": "rechazadas tras {n} conexiones simultáneas",
    },
    "rep.con.kh_no_record": {
        "en": "no local record of this host",
        "es": "no hay registro local de este host",
    },
    "rep.con.kh_revoked": {
        "en": "the recorded key is marked @revoked and is still in service",
        "es": "la clave registrada está marcada @revoked y sigue en servicio",
    },
    "rep.con.kh_changed": {
        "en": "the recorded key does not match",
        "es": "la clave registrada no coincide",
    },
    "rep.con.kh_match": {
        "en": "{n} key(s) match the local record",
        "es": "{n} clave(s) coinciden con el registro local",
    },
    "rep.con.cfg_directives": {
        "en": "{n} directives read as user '{user}'",
        "es": "{n} directivas leídas como usuario '{user}'",
    },
    "rep.con.cfg_unavailable": {"en": "unavailable", "es": "no disponible"},
    "rep.con.ak_entries": {
        "en": "{n} entry(ies), {restricted} restricted",
        "es": "{n} entrada(s), {restricted} restringida(s)",
    },
    "rep.con.ak_expired": {"en": ", {n} expired", "es": ", {n} caducada(s)"},
    "rep.con.sshfp_no_records": {"en": "no records published", "es": "no hay registros publicados"},
    "rep.con.sshfp_match": {
        "en": "{matched}/{found} record(s) match",
        "es": "{matched}/{found} registro(s) coinciden",
    },
    "rep.con.sshfp_dnssec_ok": {"en": ", DNSSEC validated", "es": ", validado con DNSSEC"},
    "rep.con.sshfp_dnssec_no": {"en": ", not DNSSEC validated", "es": ", sin validar con DNSSEC"},
    # conformance
    "rep.con.effective_strength": {
        "en": "Effective security strength {bits} bits ({label}): {desc} ",
        "es": "Fuerza de seguridad efectiva {bits} bits ({label}): {desc} ",
    },
    "rep.con.held_down_by": {
        "en": "Held down by {items}.",
        "es": "Limitada por {items}.",
    },
    "rep.con.badge_pass": {"en": "[PASS]", "es": "[CUMPLE]"},
    "rep.con.badge_fail": {"en": "[FAIL]", "es": "[FALLA]"},
    "rep.con.badge_unknown": {"en": "[ ?  ]", "es": "[ ?  ]"},
    "rep.con.not_assessed": {
        "en": "not assessed: this profile {reason}",
        "es": "sin evaluar: este perfil {reason}",
    },
    "rep.con.and_more": {"en": "... and {n} more", "es": "... y {n} más"},
    # vulnerabilities
    "rep.con.none_matched": {"en": "none matched", "es": "ninguna coincide"},
    "rep.con.affects_client": {
        "en": "Affects the SSH client, not this server.",
        "es": "Afecta al cliente SSH, no a este servidor.",
    },
    "rep.con.version_based": {
        "en": (
            "Matched on the advertised version. Distributions backport fixes without "
            "changing it, so confirm against the package changelog before acting."
        ),
        "es": (
            "Coincide por la versión anunciada. Las distribuciones retroportan parches sin "
            "cambiarla, así que confirma con el changelog del paquete antes de actuar."
        ),
    },
    "rep.con.fix": {"en": "Fix: {text}", "es": "Solución: {text}"},
    "rep.con.see": {"en": "See: {refs}", "es": "Ver: {refs}"},
    "rep.con.not_determined": {"en": "Not determined", "es": "Sin determinar"},
    "rep.con.not_determined_detail": {
        "en": "{n} check(s) need information this scan did not collect.",
        "es": "{n} comprobación(es) necesitan información que este escaneo no recogió.",
    },
    "rep.con.rerun_with": {"en": "Re-run with: {needed}", "es": "Reejecuta con: {needed}"},
    # recommendations
    "rep.con.recommendations_intro": {
        "en": "Read the comment above each line before applying it, then reload sshd.",
        "es": "Lee el comentario sobre cada línea antes de aplicarla, y luego recarga sshd.",
    },
    # summary
    "rep.con.targets_scanned": {
        "en": "{n} target(s) scanned",
        "es": "{n} objetivo(s) escaneado(s)",
    },
    "rep.con.unreachable_count": {"en": "{n} unreachable", "es": "{n} inaccesible(s)"},
    "rep.con.average_score": {"en": "average score {score}", "es": "puntuación media {score}"},
    "rep.con.pq_ready_count": {
        "en": "{n} post-quantum ready",
        "es": "{n} preparado(s) para poscuántica",
    },
    "rep.con.most_widespread": {
        "en": "Most widespread vulnerabilities",
        "es": "Vulnerabilidades más extendidas",
    },
    "rep.con.widespread_targets": {"en": "target(s)", "es": "objetivo(s)"},
    "rep.con.conformance_by_profile": {
        "en": "Conformance by profile",
        "es": "Conformidad por perfil",
    },
    "rep.con.conform": {"en": "{passed}/{total} conform", "es": "{passed}/{total} conformes"},
    "rep.con.fail_offenders": {"en": "fail {server}: {items}", "es": "falla {server}: {items}"},
    "rep.con.fail": {"en": "fail", "es": "falla"},
    "rep.con.to_comply": {"en": "to comply: {fix}", "es": "para cumplir: {fix}"},
    "rep.con.findings_prefix": {"en": "Findings: ", "es": "Hallazgos: "},
    "rep.con.completed_in": {"en": "Completed in {secs}s", "es": "Completado en {secs}s"},
    # -- reports: plain text renderer -------------------------------------
    "rep.txt.doc_title": {
        "en": "{tool} {version} - SSH cryptography audit report",
        "es": "{tool} {version} - Informe de auditoría criptográfica SSH",
    },
    "rep.txt.lbl_generated": {"en": "Generated", "es": "Generado"},
    "rep.txt.lbl_targets": {"en": "Targets", "es": "Objetivos"},
    "rep.txt.lbl_policy": {"en": "Policy", "es": "Política"},
    "rep.txt.lbl_policy_source": {"en": "Policy source", "es": "Fuente de política"},
    "rep.txt.lbl_command": {"en": "Command", "es": "Comando"},
    "rep.txt.targets_value": {
        "en": "{total} ({failed} unreachable)",
        "es": "{total} ({failed} inaccesibles)",
    },
    "rep.txt.policy_value": {
        "en": "{name} v{version} (updated {updated})",
        "es": "{name} v{version} (actualizada {updated})",
    },
    "rep.txt.summary_title": {"en": "SUMMARY", "es": "RESUMEN"},
    "rep.txt.lbl_verdicts": {"en": "Verdicts", "es": "Veredictos"},
    "rep.txt.lbl_grades": {"en": "Grades", "es": "Notas"},
    "rep.txt.lbl_average_score": {"en": "Average score", "es": "Puntuación media"},
    "rep.txt.lbl_post_quantum": {"en": "Post-quantum", "es": "Poscuántico"},
    "rep.txt.lbl_most_widespread": {"en": "Most widespread", "es": "Más extendidas"},
    "rep.txt.lbl_findings": {"en": "Findings", "es": "Hallazgos"},
    "rep.txt.lbl_strength": {"en": "Strength", "es": "Fuerza"},
    "rep.txt.lbl_duration": {"en": "Duration", "es": "Duración"},
    "rep.txt.pq_ready_of": {
        "en": "{ready} of {total} target(s) ready",
        "es": "{ready} de {total} objetivo(s) listos",
    },
    "rep.txt.conformance_heading": {
        "en": "Conformance by profile (servers conforming / assessed)",
        "es": "Conformidad por perfil (servidores conformes / evaluados)",
    },
    "rep.txt.fail_offenders": {"en": "fail {server}: {items}", "es": "falla {server}: {items}"},
    "rep.txt.fail_server": {"en": "fail {server}", "es": "falla {server}"},
    "rep.txt.to_comply": {"en": "to comply: {fix}", "es": "para cumplir: {fix}"},
    "rep.txt.not_assessed": {
        "en": "not assessed: {items}",
        "es": "sin evaluar: {items}",
    },
    "rep.txt.legend_title": {"en": "HOW TO READ THIS REPORT", "es": "CÓMO LEER ESTE INFORME"},
    "rep.txt.algorithm_categories": {
        "en": "Algorithm categories",
        "es": "Categorías de algoritmos",
    },
    "rep.txt.rating_source": {
        "en": (
            "Where the rating comes from: the categories are defined in the policy file, "
            "not invented in the report -- inspect it with --show-policy. Each algorithm "
            "carries a note with the reason for its rating and its source (a standard, an "
            "RFC or a published attack); add --notes to print them. Which document backs "
            "each judgement is traced in docs/auditoria-integridad.md."
        ),
        "es": (
            "De dónde sale la valoración: las categorías se definen en el fichero de política, "
            "no se inventan en el informe -- inspecciónalo con --show-policy. Cada algoritmo "
            "lleva una nota con el motivo de su valoración y su fuente (una norma, un RFC o un "
            "ataque publicado); añade --notes para imprimirlas. Qué documento respalda cada "
            "juicio se rastrea en docs/auditoria-integridad.md."
        ),
    },
    "rep.txt.severities_heading": {
        "en": "Finding severities, worst first",
        "es": "Severidades de los hallazgos, peor primero",
    },
    "rep.txt.scoring": {
        "en": (
            "Scoring: each algorithm class is scored by its weakest member, because a server is "
            "only as strong as the worst algorithm it will negotiate. Class scores are combined "
            "using the weights in the policy file, then adjusted for protocol level issues such "
            "as a missing strict key exchange or an undersized host key."
        ),
        "es": (
            "Puntuación: cada clase de algoritmos se puntúa por su miembro más débil, porque un "
            "servidor es tan fuerte como el peor algoritmo que negocie. Las puntuaciones de clase "
            "se combinan con los pesos del fichero de política, y luego se ajustan por problemas "
            "de nivel de protocolo como la falta de intercambio estricto de claves o una clave de "
            "host demasiado pequeña."
        ),
    },
    "rep.txt.unknown_algorithms": {
        "en": (
            "Algorithms the policy does not know are reported but never scored. If you see them, "
            "add an entry to {source}."
        ),
        "es": (
            "Los algoritmos que la política no conoce se informan pero nunca se puntúan. Si los "
            "ves, añade una entrada a {source}."
        ),
    },
    "rep.txt.conformance_heading2": {
        "en": "Standards conformance",
        "es": "Conformidad con normativas",
    },
    "rep.txt.conformance_intro": {
        "en": (
            "Each profile is evaluated against its own published rules, independently of the "
            "grade above. A server can fail this tool's policy while passing a baseline standard, "
            "or the reverse. Security strength in bits follows NIST SP 800-57 Part 1 Rev. 5 and "
            "is the weakest algorithm on offer."
        ),
        "es": (
            "Cada perfil se evalúa contra sus propias reglas publicadas, con independencia de la "
            "nota de arriba. Un servidor puede fallar la política de esta herramienta y cumplir "
            "una norma de base, o al revés. La fuerza de seguridad en bits sigue el NIST SP "
            "800-57 Parte 1 Rev. 5 y es la del algoritmo más débil que se ofrece."
        ),
    },
    "rep.txt.edition_checked": {
        "en": "Edition checked: {edition}",
        "es": "Edición comprobada: {edition}",
    },
    # -- reports: HTML renderer -------------------------------------------
    "rep.html.audit_title": {
        "en": "SSH cryptography audit",
        "es": "Auditoría criptográfica de SSH",
    },
    "rep.html.generated": {"en": "Generated {when}", "es": "Generado {when}"},
    "rep.html.targets_count": {"en": "{count} target(s)", "es": "{count} objetivo(s)"},
    "rep.html.policy": {"en": "Policy {name} v{version}", "es": "Política {name} v{version}"},
    "rep.html.doc_title": {
        "en": "{tool} report &mdash; {count} target(s)",
        "es": "Informe de {tool} &mdash; {count} objetivo(s)",
    },
    "rep.html.details_heading": {"en": "Details", "es": "Detalle"},
    "rep.html.expand_all": {"en": "Expand all", "es": "Expandir todo"},
    "rep.html.collapse_all": {"en": "Collapse all", "es": "Contraer todo"},
    "rep.html.footer_generated_by": {
        "en": "Generated by {tool} {version}.",
        "es": "Generado por {tool} {version}.",
    },
    "rep.html.footer_command": {"en": "Command:", "es": "Comando:"},
    "rep.html.footer_reflects": {
        "en": (
            "This report reflects the algorithms the servers advertised at scan time; "
            "re-run after any change to sshd_config."
        ),
        "es": (
            "Este informe refleja los algoritmos que los servidores anunciaron en el momento "
            "del escaneo; reejecuta tras cualquier cambio en sshd_config."
        ),
    },
    # stats
    "rep.html.stat_targets": {"en": "Targets", "es": "Objetivos"},
    "rep.html.stat_secure": {"en": "Secure", "es": "Seguros"},
    "rep.html.stat_need_action": {"en": "Need action", "es": "Requieren acción"},
    "rep.html.stat_pq_ready": {"en": "Post-quantum ready", "es": "Listos poscuánticos"},
    "rep.html.stat_cve": {"en": "With a known CVE", "es": "Con un CVE conocido"},
    "rep.html.stat_avg_score": {"en": "Average score", "es": "Puntuación media"},
    "rep.html.stat_unreachable": {"en": "Unreachable", "es": "Inalcanzables"},
    # widespread vulnerabilities
    "rep.html.widespread_heading": {
        "en": "Most widespread vulnerabilities",
        "es": "Vulnerabilidades más extendidas",
    },
    "rep.html.count_of": {"en": "{count} of {total}", "es": "{count} de {total}"},
    "rep.html.col_identifier": {"en": "Identifier", "es": "Identificador"},
    "rep.html.col_targets": {"en": "Targets", "es": "Objetivos"},
    # conformance by profile
    "rep.html.conformance_heading": {
        "en": "Conformance by profile",
        "es": "Conformidad por perfil",
    },
    "rep.html.conformance_intro": {
        "en": (
            "Each normativa, and the servers that pass, fail or could not be assessed. "
            "Click to expand."
        ),
        "es": (
            "Cada normativa, y los servidores que cumplen, fallan o no se pudieron evaluar. "
            "Pulsa para expandir."
        ),
    },
    "rep.html.conf_conform": {"en": "Conform", "es": "Conformes"},
    "rep.html.conf_fail": {"en": "Fail", "es": "Fallan"},
    "rep.html.conf_not_assessed": {"en": "Not assessed", "es": "Sin evaluar"},
    "rep.html.conf_to_comply": {"en": "To comply", "es": "Para cumplir"},
    "rep.html.conf_summary": {
        "en": "{passed}/{total} conform",
        "es": "{passed}/{total} conformes",
    },
    # all targets table
    "rep.html.all_targets": {"en": "All targets", "es": "Todos los objetivos"},
    # overview
    "rep.html.software_unknown": {"en": "unknown", "es": "desconocido"},
    "rep.html.identification": {"en": "Identification", "es": "Identificación"},
    "rep.html.address": {"en": "Address", "es": "Dirección"},
    "rep.html.security_strength": {"en": "Security strength", "es": "Fuerza de seguridad"},
    "rep.html.n_bit": {"en": "{bits}-bit", "es": "{bits} bits"},
    "rep.html.compression_preauth_note": {
        "en": "the decompressor is reachable by anyone who can open a connection",
        "es": "el descompresor es accesible para cualquiera que pueda abrir una conexión",
    },
    "rep.html.scanned_at": {"en": "Scanned at", "es": "Escaneado el"},
    "rep.html.duration": {"en": "Duration", "es": "Duración"},
    # algorithm table
    "rep.html.nothing_offered": {
        "en": "The server offered nothing for this class.",
        "es": "El servidor no ofreció nada para esta clase.",
    },
    "rep.html.col_rating": {"en": "Rating", "es": "Valoración"},
    "rep.html.col_algorithm": {"en": "Algorithm", "es": "Algoritmo"},
    "rep.html.col_properties": {"en": "Properties", "es": "Propiedades"},
    "rep.html.col_notes": {"en": "Notes", "es": "Notas"},
    "rep.html.directions_differ": {
        "en": "the two directions differ",
        "es": "las dos direcciones difieren",
    },
    # host keys table
    "rep.html.col_type": {"en": "Type", "es": "Tipo"},
    "rep.html.col_bits": {"en": "Bits", "es": "Bits"},
    "rep.html.col_fingerprint": {"en": "Fingerprint", "es": "Huella"},
    "rep.html.cert_id": {"en": "id {id}", "es": "id {id}"},
    "rep.html.cert_type": {"en": "{type} certificate", "es": "certificado {type}"},
    "rep.html.cert_principals": {"en": "principals: {items}", "es": "principales: {items}"},
    "rep.html.cert_ca": {"en": "CA {type} {fp}", "es": "CA {type} {fp}"},
    "rep.html.cert_ca_unreadable": {
        "en": "CA of an unreadable type: {fp}",
        "es": "CA de un tipo ilegible: {fp}",
    },
    # standards conformance
    "rep.html.effective_strength_bits": {
        "en": "{bits}-bit effective security strength",
        "es": "{bits} bits de fuerza de seguridad efectiva",
    },
    "rep.html.held_down_by": {"en": "Held down by {items}.", "es": "Limitada por {items}."},
    "rep.html.source": {"en": "Source: {ref}", "es": "Fuente: {ref}"},
    "rep.html.badge_pass": {"en": "PASS", "es": "CUMPLE"},
    "rep.html.badge_not_assessed": {"en": "NOT ASSESSED", "es": "SIN EVALUAR"},
    "rep.html.badge_fail": {"en": "FAIL", "es": "FALLA"},
    "rep.html.not_assessed_reason": {
        "en": "Not assessed: this profile {reason}.",
        "es": "Sin evaluar: este perfil {reason}.",
    },
    "rep.html.and_more": {"en": "… and {n} more", "es": "… y {n} más"},
    "rep.html.conditional_on": {"en": "Conditional on: {caveat}", "es": "Condicionado a: {caveat}"},
    "rep.html.col_result": {"en": "Result", "es": "Resultado"},
    "rep.html.col_standard": {"en": "Standard", "es": "Norma"},
    "rep.html.col_detail": {"en": "Detail", "es": "Detalle"},
    # known vulnerabilities
    "rep.html.affects_client": {
        "en": "Affects the SSH client, not this server.",
        "es": "Afecta al cliente SSH, no a este servidor.",
    },
    "rep.html.version_based": {
        "en": (
            "Matched on the advertised version. Distributions backport fixes without "
            "changing it, so confirm against the package changelog before acting."
        ),
        "es": (
            "Coincide por la versión anunciada. Las distribuciones retroportan parches sin "
            "cambiarla, así que confirma con el changelog del paquete antes de actuar."
        ),
    },
    "rep.html.fix_label": {"en": "Fix:", "es": "Solución:"},
    "rep.html.see_label": {"en": "See:", "es": "Ver:"},
    "rep.html.none_matched": {
        "en": "No known vulnerability matched.",
        "es": "Ninguna vulnerabilidad conocida coincide.",
    },
    "rep.html.badge_not_determined": {"en": "NOT DETERMINED", "es": "SIN DETERMINAR"},
    "rep.html.checks_incomplete": {
        "en": "{n} check(s) could not be completed",
        "es": "{n} comprobación(es) no se pudieron completar",
    },
    "rep.html.not_determined_detail": {
        "en": (
            "These depend on information this scan did not collect, so the server is neither "
            "confirmed affected nor confirmed clear. A check that was never run must not be "
            "mistaken for one that came back clean."
        ),
        "es": (
            "Dependen de información que este escaneo no recogió, así que el servidor no está "
            "confirmado ni como afectado ni como libre. Una comprobación que nunca se ejecutó "
            "no debe confundirse con una que salió limpia."
        ),
    },
    "rep.html.rerun_with_label": {"en": "Re-run with:", "es": "Reejecuta con:"},
    # findings
    "rep.html.no_issue": {
        "en": "No issue was detected.",
        "es": "No se detectó ningún problema.",
    },
    # suggested sshd_config
    "rep.html.config_intro": {
        "en": (
            "Read the comment above each line before applying it, then reload sshd. Lines "
            "marked as safe to apply only name algorithms this server already supports, so "
            "they cannot lock out a client that can reach it today."
        ),
        "es": (
            "Lee el comentario sobre cada línea antes de aplicarla, y luego recarga sshd. Las "
            "líneas marcadas como seguras solo nombran algoritmos que este servidor ya admite, "
            "así que no pueden dejar fuera a un cliente que hoy puede alcanzarlo."
        ),
    },
    # target section
    "rep.html.finding_note": {
        "en": "{n} high or critical finding(s)",
        "es": "{n} hallazgo(s) alto(s) o crítico(s)",
    },
    "rep.html.scan_failed": {"en": "Scan failed: {error}", "es": "Escaneo fallido: {error}"},
    "rep.html.unknown_error": {"en": "unknown error", "es": "error desconocido"},
    # legend
    "rep.html.legend_heading": {
        "en": "How to read this report",
        "es": "Cómo leer este informe",
    },
    "rep.html.rating_source_html": {
        "en": (
            "<strong>Where the rating comes from:</strong> the categories are defined in the "
            "policy ({source}), from published standards and known cryptographic results, not "
            "invented in the report. The note beside each algorithm above gives the reason for "
            "its rating and its source &mdash; a standard, an RFC or a published attack. Which "
            "document backs each judgement is traced in {doc}."
        ),
        "es": (
            "<strong>De dónde sale la valoración:</strong> las categorías se definen en la "
            "política ({source}), a partir de normas publicadas y resultados criptográficos "
            "conocidos, no se inventan en el informe. La nota junto a cada algoritmo de arriba "
            "da el motivo de su valoración y su fuente &mdash; una norma, un RFC o un ataque "
            "publicado. Qué documento respalda cada juicio se rastrea en {doc}."
        ),
    },
    "rep.html.scoring": {
        "en": (
            "Each algorithm class is scored by its weakest member: a server is only as strong "
            "as the worst algorithm it will negotiate, because any client &mdash; or an "
            "attacker downgrading one &mdash; can select it. Class scores are combined using "
            "the weights in the policy file and adjusted for protocol level issues such as a "
            "missing strict key exchange or an undersized host key."
        ),
        "es": (
            "Cada clase de algoritmos se puntúa por su miembro más débil: un servidor es tan "
            "fuerte como el peor algoritmo que negocie, porque cualquier cliente &mdash; o un "
            "atacante que fuerce una degradación &mdash; puede seleccionarlo. Las puntuaciones "
            "de clase se combinan con los pesos del fichero de política y se ajustan por "
            "problemas de nivel de protocolo como la falta de un intercambio estricto de claves "
            "o una clave de host demasiado pequeña."
        ),
    },
    "rep.html.unknown_algorithms_html": {
        "en": (
            "Algorithms the policy does not know are listed but never scored. Add them to "
            "{source} so future scans judge them."
        ),
        "es": (
            "Los algoritmos que la política no conoce se listan pero nunca se puntúan. "
            "Añádelos a {source} para que los próximos escaneos los evalúen."
        ),
    },
    # -- compliance: violation reasons and remediation --------------------
    # Kept as keys+args so a human report renders them in its language while
    # the machine formats keep the English rendered by compliance.py.
    "comp.reason.excluded_no_strict_kex": {
        "en": (
            "{name} is excluded while the server does not negotiate strict key "
            "exchange. {detail}"
        ),
        "es": (
            "{name} queda excluido mientras el servidor no negocia el intercambio "
            "estricto de claves. {detail}"
        ),
    },
    "comp.reason.exclusion_lifts": {
        "en": "The exclusion lifts once it is in place.",
        "es": "La exclusión se levanta en cuanto está en su sitio.",
    },
    "comp.remedy.excluded_no_strict_kex": {
        "en": "Negotiate strict key exchange, or stop offering {name} for {label}.",
        "es": "Negocia el intercambio estricto de claves, o deja de ofrecer {name} para {label}.",
    },
    "comp.reason.disallowed": {
        "en": "{name} is not permitted for {label}.",
        "es": "{name} no está permitido para {label}.",
    },
    "comp.remedy.disallowed": {
        "en": "Remove {name} from the server's {label} list.",
        "es": "Quita {name} de la lista de {label} del servidor.",
    },
    "comp.reason.not_allowlisted": {
        "en": "{name} is not on the permitted {label} list.",
        "es": "{name} no está en la lista permitida de {label}.",
    },
    "comp.remedy.not_allowlisted": {
        "en": "Restrict {label} to this profile's allowed set: {allowed}",
        "es": "Restringe {label} al conjunto permitido de este perfil: {allowed}",
    },
    "comp.reason.strength": {
        "en": "This profile requires at least {minimum}-bit security strength.",
        "es": "Este perfil exige al menos {minimum} bits de fuerza de seguridad.",
    },
    "comp.reason.strength_limited": {
        "en": (
            "This profile requires at least {minimum}-bit security strength. "
            "Held down by {limiting}."
        ),
        "es": (
            "Este perfil exige al menos {minimum} bits de fuerza de seguridad. "
            "Limitada por {limiting}."
        ),
    },
    "comp.remedy.strength": {
        "en": (
            "Stop offering the weakest algorithms so the effective strength reaches "
            "at least {minimum} bits."
        ),
        "es": (
            "Deja de ofrecer los algoritmos más débiles para que la fuerza efectiva "
            "alcance al menos {minimum} bits."
        ),
    },
    "comp.remedy.strength_limited": {
        "en": (
            "Stop offering the weakest algorithms so the effective strength reaches "
            "at least {minimum} bits ({limiting})."
        ),
        "es": (
            "Deja de ofrecer los algoritmos más débiles para que la fuerza efectiva "
            "alcance al menos {minimum} bits ({limiting})."
        ),
    },
    "comp.reason.key_size": {
        "en": "This profile requires at least {minimum}-bit {family} host keys.",
        "es": "Este perfil exige claves de host {family} de al menos {minimum} bits.",
    },
    "comp.remedy.key_size": {
        "en": (
            "Regenerate the {family} host key with at least {minimum} bits "
            "(ssh-keygen -b {minimum})."
        ),
        "es": (
            "Regenera la clave de host {family} con al menos {minimum} bits "
            "(ssh-keygen -b {minimum})."
        ),
    },
    "comp.reason.strict_kex": {
        "en": "This profile requires strict key exchange to be negotiated.",
        "es": "Este perfil exige que se negocie el intercambio estricto de claves.",
    },
    "comp.remedy.strict_kex": {
        "en": (
            "Update the server to an OpenSSH that negotiates strict key exchange "
            "(kex-strict-s-v00@openssh.com), 8.9 or newer."
        ),
        "es": (
            "Actualiza el servidor a un OpenSSH que negocie el intercambio estricto de "
            "claves (kex-strict-s-v00@openssh.com), 8.9 o posterior."
        ),
    },
    "comp.reason.post_quantum": {
        "en": "This profile requires a quantum-resistant key exchange method.",
        "es": "Este perfil exige un método de intercambio de claves resistente a la cuántica.",
    },
    "comp.remedy.post_quantum": {
        "en": (
            "Offer a hybrid post-quantum key exchange, e.g. "
            "sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha256."
        ),
        "es": (
            "Ofrece un intercambio de claves híbrido poscuántico, p. ej. "
            "sntrup761x25519-sha512@openssh.com o mlkem768x25519-sha256."
        ),
    },
    "comp.reason.local_policy": {
        "en": (
            "The documented policy rates this {category}, so allowing it breaches the "
            "organisation's own cryptographic rules."
        ),
        "es": (
            "La política documentada lo califica como {category}, así que permitirlo "
            "incumple las propias reglas criptográficas de la organización."
        ),
    },
    # -- CLI: detection sources (--list-vulnerabilities) -------------------
    "cli.det.version": {"en": "the advertised version", "es": "la versión anunciada"},
    "cli.det.protocol": {
        "en": "the protocol version in the banner",
        "es": "la versión de protocolo del banner",
    },
    "cli.det.algorithms": {"en": "the algorithms offered", "es": "los algoritmos ofrecidos"},
    "cli.det.host_key": {"en": "the host key", "es": "la clave de host"},
    "cli.det.auth_methods": {
        "en": "the authentication methods",
        "es": "los métodos de autenticación",
    },
    "cli.det.extensions": {"en": "the advertised extensions", "es": "las extensiones anunciadas"},
    "cli.det.config": {"en": "the server configuration", "es": "la configuración del servidor"},
    "cli.det.always": {"en": "always", "es": "siempre"},
    "cli.det.needs": {"en": "  (needs {flags})", "es": "  (necesita {flags})"},
    # -- CLI: --list-plugins -----------------------------------------------
    "cli.pl.loaded": {
        "en": "{n} detection plugin(s) loaded",
        "es": "{n} plugin(s) de detección cargado(s)",
    },
    "cli.pl.lbl_from": {"en": "from", "es": "desde"},
    "cli.pl.lbl_needs": {"en": "needs", "es": "necesita"},
    "cli.pl.lbl_affects": {"en": "affects", "es": "afecta a"},
    "cli.pl.lbl_references": {"en": "references", "es": "referencias"},
    "cli.pl.affects_client": {
        "en": "the SSH client, not the server",
        "es": "el cliente SSH, no el servidor",
    },
    "cli.pl.not_loaded": {"en": "Not loaded:", "es": "No cargados:"},
    # -- CLI: --list-vulnerabilities ---------------------------------------
    "cli.lv.header": {
        "en": "{n} known vulnerability check(s) in {source}",
        "es": "{n} comprobación(es) de vulnerabilidades conocidas en {source}",
    },
    "cli.lv.lbl_detected": {"en": "detected by", "es": "se detecta por"},
    "cli.lv.footer": {
        "en": (
            "Adding a check is editing the 'vulnerabilities' list in the policy file; no code\n"
            "change is needed. Run --export-policy to get an editable copy.\n"
        ),
        "es": (
            "Añadir una comprobación es editar la lista 'vulnerabilities' del fichero de\n"
            "política; no hace falta tocar el código. Ejecuta --export-policy para obtener\n"
            "una copia editable.\n"
        ),
    },
    # -- CLI: --list-profiles ----------------------------------------------
    "cli.lp.header": {
        "en": (
            "{profiles} conformance profile(s), {editions} edition(s) in total, for {source}\n"
            "A bare name is the edition in force; name@edition asks for a particular one.\n\n"
        ),
        "es": (
            "{profiles} perfil(es) de conformidad, {editions} edición(es) en total, "
            "para {source}\n"
            "El nombre a secas es la edición en vigor; nombre@edición pide una concreta.\n\n"
        ),
    },
    "cli.lp.lbl_authority": {"en": "authority", "es": "autoridad"},
    "cli.lp.lbl_kind": {"en": "kind", "es": "tipo"},
    "cli.lp.lbl_edition": {"en": "edition", "es": "edición"},
    "cli.lp.lbl_reference": {"en": "reference", "es": "referencia"},
    "cli.lp.lbl_url": {"en": "url", "es": "url"},
    "cli.lp.lbl_editions": {"en": "editions", "es": "ediciones"},
    "cli.lp.lbl_minimum": {"en": "minimum", "es": "mínimo"},
    "cli.lp.lbl_summary": {"en": "summary", "es": "resumen"},
    "cli.lp.in_force": {"en": "{selector} (in force)", "es": "{selector} (en vigor)"},
    "cli.lp.minimum_value": {
        "en": "{bits}-bit security strength",
        "es": "{bits} bits de fuerza de seguridad",
    },
    "cli.lp.footer": {
        "en": (
            "Use --profile ID to evaluate only some of them, and --require-profile ID to "
            "make a scan fail when a target does not conform.\n"
        ),
        "es": (
            "Usa --profile ID para evaluar solo algunos, y --require-profile ID para que "
            "el escaneo falle cuando un objetivo no cumpla.\n"
        ),
    },
    # -- CLI: --export-policy ----------------------------------------------
    "cli.exp.exists": {
        "en": "error: {destination} already exists; refusing to overwrite it\n",
        "es": "error: {destination} ya existe; no se sobrescribe\n",
    },
    "cli.exp.exists_diff": {
        "en": (
            "error: {target} already exists and is not the one this would "
            "write; refusing to overwrite it\n"
        ),
        "es": (
            "error: {target} ya existe y no es el que se escribiría; "
            "no se sobrescribe\n"
        ),
    },
    "cli.exp.write_failed": {
        "en": "error: could not write {file}: {exc}\n",
        "es": "error: no se pudo escribir {file}: {exc}\n",
    },
    "cli.exp.wrote": {"en": "Wrote {destination}\n", "es": "Escrito {destination}\n"},
    "cli.exp.wrote_profiles": {
        "en": (
            "Wrote {directory} with {count} conformance profile edition(s) "
            "({written} written now); the policy reads them from beside "
            "itself, so keep them together.\n"
        ),
        "es": (
            "Escrito {directory} con {count} edición(es) de perfiles de conformidad "
            "({written} escritas ahora); la política los lee de su lado, "
            "así que mantenlos juntos.\n"
        ),
    },
    "cli.exp.edit_hint": {
        "en": "Edit it and pass --config {destination}, or set {var}={destination}.\n",
        "es": "Edítalo y pasa --config {destination}, o define {var}={destination}.\n",
    },
    # -- CLI: --show-policy ------------------------------------------------
    "cli.sp.lbl_source": {"en": "source", "es": "fuente"},
    "cli.sp.lbl_schema": {"en": "schema", "es": "esquema"},
    "cli.sp.entries": {
        "en": "{entries} entries, {patterns} pattern(s): {breakdown}",
        "es": "{entries} entradas, {patterns} patrón(es): {breakdown}",
    },
    "cli.sp.suggested": {"en": "suggested: {names}", "es": "sugerido: {names}"},
    "cli.sp.weights": {"en": "weights: {weights}", "es": "pesos: {weights}"},
    "cli.sp.grades": {"en": "grades: {ladder}", "es": "notas: {ladder}"},
    "cli.sp.advisories": {"en": "advisories: {n}", "es": "avisos de versión: {n}"},
    "cli.sp.search_order": {"en": "search order:", "es": "orden de búsqueda:"},
    "cli.sp.missing": {"en": "  (missing)", "es": "  (no existe)"},
    # -- CLI: runtime messages ---------------------------------------------
    "cli.err.generic": {"en": "error: {exc}\n", "es": "error: {exc}\n"},
    "cli.warn.plugin_not_loaded": {
        "en": "warning: plugin not loaded: {problem}\n",
        "es": "aviso: plugin no cargado: {problem}\n",
    },
    "cli.warn.skipping_target": {
        "en": "warning: skipping target: {message}\n",
        "es": "aviso: se omite el objetivo: {message}\n",
    },
    "cli.err.no_target": {
        "en": (
            "error: no target to scan. Pass a host name or address, or a list "
            "with -f FILE.\nRun with --help for examples.\n"
        ),
        "es": (
            "error: no hay objetivo que escanear. Pasa un nombre de host o una "
            "dirección, o una lista con -f FICHERO.\nEjecuta --help para ver ejemplos.\n"
        ),
    },
    "cli.err.unknown_format": {
        "en": "unknown format '{name}'; choose from {valid}",
        "es": "formato desconocido '{name}'; elige entre {valid}",
    },
    "cli.err.unknown_profile": {
        "en": (
            "unknown profile '{id}'; run --list-profiles. "
            "A bare name is the edition in force and name@edition is a "
            "particular one: {known}"
        ),
        "es": (
            "perfil desconocido '{id}'; ejecuta --list-profiles. "
            "El nombre a secas es la edición en vigor y nombre@edición es una "
            "concreta: {known}"
        ),
    },
    "cli.err.output_required": {
        "en": "-o/--output is required when more than one --format is requested",
        "es": "-o/--output es obligatorio cuando se piden varios --format",
    },
    "cli.err.could_not_write": {
        "en": "error: could not write {destination}: {exc}\n",
        "es": "error: no se pudo escribir {destination}: {exc}\n",
    },
    "cli.msg.wrote": {"en": "Wrote {path}\n", "es": "Escrito {path}\n"},
    "cli.msg.scanning": {
        "en": "[{done}/{total}] scanning...",
        "es": "[{done}/{total}] escaneando...",
    },
    "cli.msg.scan_start": {
        "en": "Scanning {n} target(s) with policy {policy}...\n",
        "es": "Escaneando {n} objetivo(s) con la política {policy}...\n",
    },
    "cli.msg.credentials": {
        "en": "Credentials: {desc}\n",
        "es": "Credenciales: {desc}\n",
    },
    "cli.msg.unreachable": {"en": "unreachable", "es": "inaccesible"},
    "cli.msg.history_header": {"en": "History", "es": "Histórico"},
    "cli.cmp.header": {
        "en": "Changes since the baseline",
        "es": "Cambios respecto a la línea base",
    },
    "cli.cmp.scanned": {"en": ", scanned {when}", "es": ", escaneado {when}"},
    # -- comparison summary (compare.summarise) ----------------------------
    # The cmp.mark_* fragments MUST appear verbatim inside the corresponding
    # templates: the console colours a line by finding them in it.
    "cmp.nothing": {
        "en": "Nothing changed since the baseline.",
        "es": "Nada ha cambiado respecto a la línea base.",
    },
    "cmp.new_target": {
        "en": "{name}: new since the baseline (grade {grade})",
        "es": "{name}: nuevo desde la línea base (nota {grade})",
    },
    "cmp.gone": {
        "en": "{name}: was in the baseline and is not in this scan",
        "es": "{name}: estaba en la línea base y no está en este escaneo",
    },
    "cmp.grade_improved": {
        "en": "{name}: improved, grade {a} -> {b}",
        "es": "{name}: mejoró, nota {a} -> {b}",
    },
    "cmp.grade_regressed": {
        "en": "{name}: regressed, grade {a} -> {b}",
        "es": "{name}: empeoró, nota {a} -> {b}",
    },
    "cmp.new_finding": {
        "en": "{name}: NEW [{severity}] {title}",
        "es": "{name}: NUEVO [{severity}] {title}",
    },
    "cmp.fixed_finding": {
        "en": "{name}: fixed [{severity}] {title}",
        "es": "{name}: corregido [{severity}] {title}",
    },
    "cmp.host_key_changed": {
        "en": "{name}: HOST KEY CHANGED {change}",
        "es": "{name}: CLAVE DE HOST CAMBIADA {change}",
    },
    "cmp.now_offers": {
        "en": "{name}: now offers {item}",
        "es": "{name}: ahora ofrece {item}",
    },
    "cmp.no_longer_offers": {
        "en": "{name}: no longer offers {item}",
        "es": "{name}: ya no ofrece {item}",
    },
    "cmp.mark_new": {"en": "NEW [", "es": "NUEVO ["},
    "cmp.mark_host_key": {"en": "HOST KEY CHANGED", "es": "CLAVE DE HOST CAMBIADA"},
    "cmp.mark_fixed": {"en": "fixed [", "es": "corregido ["},
    "cmp.mark_improved": {"en": "improved", "es": "mejoró"},
    # -- history summary (history.summarise) -------------------------------
    "his.empty": {
        "en": "The history file has no readable scans yet.",
        "es": "El fichero de histórico aún no tiene escaneos legibles.",
    },
    "his.hdr_scanned": {"en": "Scanned", "es": "Escaneado"},
    "his.hdr_hosts": {"en": "Hosts", "es": "Hosts"},
    "his.hdr_avg": {"en": "Avg", "es": "Media"},
    "his.hdr_worst": {"en": "Worst", "es": "Peor"},
    "his.hdr_vuln": {"en": "Vuln", "es": "Vuln"},
    "his.hdr_crit": {"en": "Crit", "es": "Crít"},
    "his.hdr_high": {"en": "High", "es": "Alta"},
    "his.more": {
        "en": "({n} scans recorded; showing the last {limit})",
        "es": "({n} escaneos registrados; se muestran los últimos {limit})",
    },
}
