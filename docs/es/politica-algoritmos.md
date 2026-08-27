# Manual de política — algoritmos

> Antes de esto, lee [`politicas.md`](politicas.md).

Esta es la parte de la política que decide **qué opina la herramienta de cada
algoritmo que un servidor ofrece**. Es lo que más se edita y lo que envejece
más rápido.

---

## Las seis categorías

Se definen en la clave `categories`. Cada una tiene una etiqueta, una
abreviatura, una **puntuación** y una **severidad**:

| Categoría | Puntos | Severidad | Qué significa |
|---|---|---|---|
| `recommended` | 100 | info | Moderno, sin debilidad práctica conocida. |
| `acceptable` | 75 | low | Sirve, pero hay algo mejor. |
| `weak` | 35 | medium | Debilidad conocida; hay que quitarlo. |
| `insecure` | 0 | critical | Roto. Nada debería ofrecerlo. |
| `informational` | *(sin puntos)* | info | Se informa, no puntúa. Para lo que no es bueno ni malo. |
| `unknown` | *(sin puntos)* | info | La política no lo conoce. **No puntúa a propósito.** |

```json
"categories": {
  "weak": {
    "label": "Weak",
    "short": "WEAK",
    "score": 35,
    "severity": "medium",
    "description": "Debilidad conocida. Quítalo cuando puedas."
  }
}
```

> **`unknown` no penaliza, y es deliberado.** Los servidores ofrecen nombres
> que nadie ha catalogado todo el tiempo. Bajar la nota por un algoritmo que
> la política no conoce castiga a quien usa algo nuevo y bueno exactamente
> igual que a quien usa algo raro y malo.

Puedes añadir categorías propias. Lo único que hace falta es que tengan
`label` y `severity`; sin `score`, no puntúan.

---

## Las cinco clases

`algorithms` tiene exactamente cinco claves, y **las cinco son obligatorias**:

| Clase | Directiva de `sshd_config` |
|---|---|
| `kex` | `KexAlgorithms` |
| `host_key` | `HostKeyAlgorithms` |
| `cipher` | `Ciphers` |
| `mac` | `MACs` |
| `compression` | `Compression` |

Borrar una no significa «esta clase no me importa»: significa que un servidor
podría ofrecer cualquier cosa ahí sin que nadie dijese nada. El cargador lo
rechaza.

Cada clase se escribe así:

```json
"cipher": {
  "label": "Cipher",
  "sshd_config_directive": "Ciphers",
  "entries": { ... },
  "patterns": [ ... ]
}
```

---

## Las entradas: un algoritmo, una opinión

```json
"entries": {
  "aes256-gcm@openssh.com": {
    "category": "recommended",
    "security_strength_bits": 256,
    "tags": ["aead"],
    "suggest": true,
    "notes": "AES-256 en GCM. Cifrado autenticado, sin MAC aparte.",
    "references": ["RFC 5647"]
  }
}
```

| Campo | Obligatorio | Qué hace |
|---|---|---|
| `category` | **sí** | Una de las categorías definidas arriba. |
| `security_strength_bits` | no | Bits de seguridad efectivos. Alimenta la fuerza total y las normativas. |
| `tags` | no | Etiquetas. **Esto es lo más útil de todo el fichero**, ver abajo. |
| `suggest` | no | Si esta entrada aparece en el bloque de `sshd_config` sugerido. |
| `notes` | no | Por qué. Sale en el informe con `--show-algorithm-notes`. |
| `references` | no | RFC, CVE, aviso. |

### Las etiquetas hacen el trabajo pesado

Una etiqueta es una propiedad que cruza nombres: `cbc`, `sha1`, `aead`, `etm`,
`post-quantum`, `terrapin-vector`, `nist-curve`, `legacy`…

Importan porque **las detecciones y los plugins razonan por etiqueta**, no por
nombre. Una regla escrita sobre la etiqueta `cbc` sigue funcionando el día que
alguien invente un CBC nuevo; una escrita sobre `aes128-cbc` no.

Dales nombre legible en `tag_labels`, que es lo que el informe imprime:

```json
"tag_labels": { "cbc": "CBC mode", "aead": "Authenticated encryption" }
```

Siete etiquetas no son informativas: **disparan comportamiento**, y la
detección de Terrapin, la de *encrypt-then-MAC* y el estado de la compresión se
basan en ellas, no en el nombre del algoritmo:

| Etiqueta | Efecto |
|---|---|
| `post-quantum` | El algoritmo cuenta para el estado post-cuántico. |
| `aead` | Cuenta para `require_aead_cipher`. |
| `etm` | Marca un MAC como *encrypt-then-MAC*: cuenta para `require_etm_mac` y para el segundo vector de Terrapin. |
| `cbc` | Marca un cifrado como modo CBC: junto a un MAC `etm` forma un vector de Terrapin. |
| `terrapin-vector` | El cifrado es explotable por Terrapin por sí solo (ChaCha20-Poly1305). |
| `post-auth` | La compresión solo arranca tras autenticar: decide el estado `Compression` del informe. |
| `protocol-marker` | No es un algoritmo sino una señal (`ext-info-s`, `kex-strict-*`): los perfiles no lo juzgan. |

Etiquetar de más y de menos falla de formas distintas, así que las dos reglas
frontera están fijadas por un test:

- **`protocol-marker` se salta; todo lo demás se juzga.** Marcar de más equivale
  a dejar de comprobar un algoritmo de verdad. Por eso los MAC `AEAD_AES_*_GCM`
  **no** la llevan aunque sean `informational`: son nombres reales de RFC 5647 que
  CNSA 2.0 exige, no banderas.
- **Con `post-auth` la regla es la contraria:** lo que *no* la lleva se da por
  previo a la autenticación. «Espera a que te autentiques» es la afirmación que
  necesita pruebas, así que una compresión nueva y sin clasificar sale como
  `enabled BEFORE authentication` hasta que alguien la etiquete. Un test comprueba
  que `zlib@openssh.com` la lleva y `zlib` no, porque esa etiqueta es lo único que
  distingue a los dos.

Así se reconocen alias como `rijndael-cbc@lysator.liu.se` (que es AES-256-CBC pero
no acaba en `-cbc`) o variantes de fabricante como `hmac-sha2-256-etm@ssh.com`. Si
añades un cifrado CBC o un MAC EtM nuevo, etiquétalo o quedará fuera de la
comprobación.

---

## Los patrones: para lo que aún no está en la lista

Un patrón captura lo que las entradas no nombran, con comodines al estilo
*shell*:

```json
"patterns": [
  {
    "match": "*-cbc*",
    "category": "weak",
    "tags": ["cbc"],
    "notes": "Modo CBC no listado explícitamente. En SSH es encrypt-and-MAC."
  }
]
```

Las entradas ganan a los patrones. El orden importa: **el primer patrón que
encaja es el que manda**, así que pon lo específico antes que lo general.

Sirven para dos cosas: no tener que enumerar cuarenta variantes de lo mismo,
y para que un algoritmo nuevo de una familia mala no salga como
*desconocido* — que no penaliza — sino con la categoría de su familia.

---

## Añadir un algoritmo nuevo: la receta

1. **Búscalo primero.** ¿Ya lo captura un patrón? `--show-policy` cuenta
   cuántas entradas y patrones tiene cada clase.
2. Añade la entrada en la clase que toca, con `category` y, si lo sabes,
   `security_strength_bits`.
3. **Ponle etiquetas**, aunque parezcan obvias. Es lo que hará que las reglas
   de otros lo cojan.
4. Escribe `notes` con el porqué y `references` con la fuente. Dentro de dos
   años, quien lo lea querrá saber en qué te basaste.
5. Marca `suggest: true` solo si de verdad recomiendas ponerlo en un
   `sshd_config`.
6. Compruébalo:

```bash
ssh-crypto-checker --config mi-politica.json --show-policy
ssh-crypto-checker --config mi-politica.json 127.0.0.1:2222 --show-algorithm-notes
```

---

## Tamaños de clave: `requirements`

Aparte de los nombres, están los tamaños:

```json
"requirements": {
  "host_keys": {
    "rsa":     { "minimum_bits": 2048, "recommended_bits": 3072 },
    "ed25519": { "minimum_bits": 256,  "recommended_bits": 256 }
  },
  "dh_group": { "minimum_bits": 2048, "recommended_bits": 3072 }
}
```

`minimum_bits` es lo que dispara un hallazgo grave (y puede activar un tope de
nota); `recommended_bits` es lo que dispara un aviso. Si no pones
`recommended_bits`, se toma igual que el mínimo.
