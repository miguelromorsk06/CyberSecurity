# 🛡️ Primer Lab de SOC — Investigación y Análisis de Alertas

## 📌 Introducción

Después de dedicar un tiempo a investigar cómo funciona un **SOC (Security Operations Center)** y cuáles son las principales funciones dentro de un equipo **Blue Team**, decidí comenzar mis primeros laboratorios prácticos en **TryHackMe**.

Este primer laboratorio estuvo centrado principalmente en la investigación y clasificación de alertas procedentes de diferentes fuentes:

* 📧 Email
* 🔥 Firewall
* 🌐 URLs
* 🖥️ Direcciones IP
* 🚨 Phishing
* 🔎 Análisis de indicadores de compromiso (IoC)

El objetivo principal era determinar si una alerta correspondía a un **True Positive (TP)** o **False Positive (FP)** y, posteriormente, decidir si era necesario **escalarla a un nivel superior (N2)**.

El laboratorio terminó con **puntuación máxima**, aunque posteriormente revisé mis propios reportes y encontré varios aspectos que podía mejorar, principalmente:

* Explicaciones demasiado breves.
* Falta de contexto en las investigaciones.
* Poco análisis de las direcciones IP.
* Falta de una diferenciación clara entre **clasificar una alerta** y **decidir si debe escalarse**.
* Indicadores de ataque poco desarrollados.
* Recomendaciones de remediación demasiado genéricas.

Esta es la retrospectiva de los cuatro casos investigados.

---

# 1. 📧 Caso 1 — Posible Phishing / Onboarding

### Datos de la alerta

**Datasource:** Email

**Sender:**

`onboarding@hrconnex.thm`

**URL:**

`https://hrconnex.thm/onboarding/15400654060/j.garcia`

**Affected entity:**

`j.garcia@thetrydaily.thm`

### 🔎 Investigación

La primera alerta estaba relacionada con un supuesto correo de **onboarding**.

Inicialmente podía parecer sospechoso debido a que contenía un enlace externo, por lo que procedí a analizar tanto la dirección de correo del remitente como la URL incluida en el mensaje.

Los elementos que tuve en cuenta fueron:

* El dominio del remitente era `hrconnex.thm`.
* La URL también pertenecía al dominio `hrconnex.thm`.
* El contexto del mensaje estaba relacionado con un proceso de onboarding.
* El identificador incluido en la URL hacía referencia al usuario afectado.
* No observé una discrepancia evidente entre el remitente y el dominio utilizado por el enlace.
* Realicé comprobaciones adicionales mediante VirusTotal sobre los indicadores disponibles.

La coincidencia entre el dominio del remitente y el dominio de la URL era un indicador importante para determinar que no se trataba, en principio, de una campaña de phishing.

### 🧠 Clasificación

**False Positive (FP)**

La alerta se clasificó como FP porque los elementos analizados eran coherentes entre sí y no se encontraron indicadores suficientes que justificaran considerar el correo como malicioso.

### 📝 Reporte original

> **Time of Activity:** 1 minute
> **List of Related Entities:** [j.garcia@thetrydaily.thm](mailto:j.garcia@thetrydaily.thm), [onboarding@hrconnex.thm](mailto:onboarding@hrconnex.thm)
> **Reason for Classifying as False Positive:** The URL and the username of the sender match. It is related to an onboarding account and the sender is [onboarding@hrconnex.thm](mailto:onboarding@hrconnex.thm). When analyzing the URL, it appears to be clean.
> **Reason for Escalating the Alert:** None.

### 🔧 Qué podría mejorar

Aunque la clasificación fue correcta, el reporte podía ser bastante más completo.

Por ejemplo, habría sido conveniente documentar:

* La reputación del dominio.
* La reputación de la URL.
* El resultado concreto de VirusTotal.
* La IP asociada al dominio, si estaba disponible.
* La fecha de registro del dominio, cuando fuera relevante.
* Si existían redirecciones.
* Si el enlace utilizaba HTTP o HTTPS.
* Por qué exactamente la coincidencia entre remitente y URL reducía la sospecha.

### 📚 Lección aprendida

Una coincidencia entre el dominio del remitente y el dominio del enlace es un indicador útil, pero **no debería ser suficiente por sí sola para declarar un correo legítimo**.

Un atacante podría comprometer un dominio legítimo o utilizar infraestructura aparentemente confiable.

Por tanto, el proceso debería ser:

```text
Email
  ↓
Sender
  ↓
Domain
  ↓
URL
  ↓
Redirects
  ↓
IP / Infrastructure
  ↓
Reputation
  ↓
Context
  ↓
Final classification
```

---

# 2. 🚨 Caso 2 — Microsoft Account / Credential Phishing

### Datos de la alerta

**Datasource:** Email

**Timestamp:**

`09/29/2026 11:22:16.091`

**Subject:**

`Unusual Sign-In Activity on Your Microsoft Account`

**Sender:**

`no-reply@m1crosoftsupport.co`

**Recipient:**

`c.allen@thetrydaily.thm`

**Attachment:**

`None`

**Direction:**

`Inbound`

### 📩 Contenido relevante

El correo notificaba al usuario sobre un supuesto inicio de sesión sospechoso desde:

* **Location:** Lagos, Nigeria
* **IP:** `102.89.222.143`
* **Date:** `2025-01-24 06:42`

Además, el mensaje incluía un enlace:

`https://m1crosoftsupport.co/login`

### 🔎 Indicadores sospechosos

En este caso aparecieron varios indicadores claros de phishing.

#### 1. Typosquatting

El dominio:

`m1crosoftsupport.co`

utiliza un `1` en lugar de una `i`.

Este tipo de técnica se conoce como **typosquatting** y busca que el dominio parezca legítimo a simple vista.

La diferencia:

```text
microsoft
   ↓
m1crosoft
```

es pequeña visualmente, pero suficiente para utilizar un dominio diferente.

#### 2. Dominio sospechoso

El dominio tampoco corresponde al dominio oficial utilizado por Microsoft para este tipo de comunicaciones.

Esto es especialmente relevante porque el correo pretende hacerse pasar por un servicio de seguridad de Microsoft.

#### 3. Urgencia

El mensaje utiliza un patrón muy habitual en campañas de phishing:

> El usuario debe actuar inmediatamente para evitar consecuencias.

La creación de sensación de urgencia busca reducir el tiempo que tiene el usuario para analizar el mensaje.

#### 4. Enlace de autenticación

El correo dirige al usuario a:

`https://m1crosoftsupport.co/login`

El hecho de que el destino sea un dominio diferente al legítimo constituye un indicador importante de posible **credential phishing**.

#### 5. IP indicada en el correo

También debería investigarse:

`102.89.222.143`

La IP aparece asociada al supuesto inicio de sesión.

No debería asumirse automáticamente que una IP extranjera implica actividad maliciosa. Una ubicación geográfica por sí sola **no es suficiente para determinar que un inicio de sesión es malicioso**.

En este caso, la IP debería analizarse junto con:

* Reputación.
* ASN.
* ISP.
* Geolocalización.
* Historial conocido.
* Aparición en listas de abuso.
* Relación con otros indicadores del correo.

### 🧠 Clasificación

**True Positive (TP)**

La combinación de:

* Typosquatting.
* Dominio no legítimo.
* URL sospechosa.
* Intento de generar urgencia.
* Suplantación de Microsoft.
* Solicitud de revisión de actividad de cuenta.

proporciona suficiente evidencia para clasificar el correo como phishing.

### 📚 Lección aprendida

Una de las principales mejoras respecto al primer análisis es entender que **un único indicador rara vez debería ser la base de la decisión**.

Es mucho más útil construir una cadena de evidencias:

```text
Suspicious sender
       +
Typosquatting
       +
Suspicious domain
       +
Credential login page
       +
Urgency
       ↓
High confidence phishing
```

---

# 3. 📦 Caso 3 — Amazon Package Phishing

### Datos de la alerta

**Datasource:** Email

**Timestamp:**

`09/29/2026 12:18:37.543`

**Subject:**

`Your Amazon Package Couldn’t Be Delivered – Action Required`

**Sender:**

`urgents@amazon.biz`

**Recipient:**

`h.harris@thetrydaily.thm`

**Attachment:**

`None`

**Direction:**

`Inbound`

### 🔎 Investigación inicial

El mensaje notificaba al usuario de un supuesto problema con una entrega de Amazon.

El correo indicaba que la dirección de entrega estaba incompleta y solicitaba al usuario confirmar sus datos mediante un enlace.

El enlace utilizado era:

`http://bit.ly/3sHkX3da12340`

### 🚩 Indicadores sospechosos

#### 1. Dominio del remitente

El remitente era:

`urgents@amazon.biz`

mientras que el correo pretendía representar a Amazon.

El dominio utilizado no era el dominio habitual de Amazon.

#### 2. Uso de un acortador de URL

El enlace:

`http://bit.ly/3sHkX3da12340`

es especialmente interesante porque no muestra directamente el destino final.

Esto dificulta al usuario comprobar dónde terminará la conexión.

Por este motivo, los enlaces acortados deben investigarse antes de considerarlos legítimos.

#### 3. Ingeniería social

El correo utiliza dos técnicas muy habituales:

**Urgencia:**

El usuario dispone de un tiempo limitado antes de que el paquete sea devuelto.

**Pretexto legítimo:**

Se utiliza una entrega de Amazon como contexto para conseguir que el usuario proporcione información.

### 🔬 Análisis del enlace

La investigación del enlace confirmó que el destino era malicioso.

Por tanto, ya no se trataba únicamente de un correo sospechoso: existía evidencia adicional que permitía confirmar la actividad maliciosa.

### 🧠 Clasificación

**True Positive (TP)**

La clasificación se basa en la combinación de:

* Remitente sospechoso.
* Dominio que no corresponde con Amazon.
* Uso de un acortador.
* Ingeniería social.
* URL maliciosa.
* Intento de obtener información del usuario.

### 📝 Reporte

**Time of Activity:** 4 minutes

**Affected Entity:**

`h.harris@thetrydaily.thm`

**Classification:**

`True Positive`

**Reason for Classification:**

The email contains multiple indicators associated with phishing. The sender uses the suspicious domain `amazon.biz` while impersonating Amazon, and the message uses urgency to encourage the recipient to interact with the provided link. The URL is shortened through Bitly, preventing the final destination from being immediately visible. Further analysis confirmed that the destination URL is malicious.

**Attack Indicators:**

* `urgents@amazon.biz`
* `amazon.biz`
* `http://bit.ly/3sHkX3da12340`
* Amazon impersonation
* Urgency-based social engineering
* Malicious destination URL

**Potential Impact:**

Potential credential theft or collection of sensitive information from the affected user.

### ⚠️ Error cometido durante la investigación

Inicialmente decidí **no escalar** la alerta porque consideré que se trataba de un phishing sencillo.

Después de revisar el caso y consultar diferentes fuentes, entendí que la decisión de escalado no debería depender únicamente de la complejidad aparente de la técnica utilizada.

La pregunta relevante es:

> **¿Existe evidencia de que el atacante haya conseguido interactuar con el usuario o con la infraestructura?**

Esto cambia significativamente la investigación.

---

# 4. 🔥 Caso 4 — Firewall Alert

### Datos de la alerta

**Datasource:** Firewall

**Timestamp:**

`09/29/2026 12:19:51.543`

**Action:**

`Blocked`

**Source IP:**

`10.20.2.17`

**Source Port:**

`34257`

**Destination IP:**

`67.199.248.11`

**Destination Port:**

`80`

**URL:**

`http://bit.ly/3sHkX3da12340`

**Application:**

`web-browsing`

**Protocol:**

`TCP`

**Rule:**

`Blocked Websites`

### 🔎 Correlación con el caso anterior

Este caso es especialmente interesante porque aparece inmediatamente después del correo de phishing del caso 3.

Tenemos:

```text
Caso 3
Email phishing
      ↓
bit.ly/3sHkX3da12340
      ↓
Caso 4
Firewall connection attempt
      ↓
10.20.2.17
```

Por tanto, existe una posible relación entre ambas alertas.

El endpoint:

`10.20.2.17`

intentó realizar una conexión hacia:

`67.199.248.11:80`

y el firewall la bloqueó mediante la regla:

`Blocked Websites`

### 🚨 Indicadores relevantes

#### Source IP

`10.20.2.17`

Es una dirección IP privada perteneciente al espacio RFC1918.

Por sí misma no identifica públicamente al equipo, por lo que sería necesario consultar otros sistemas para determinar qué endpoint corresponde a esa IP.

Por ejemplo:

* DHCP logs.
* EDR.
* Asset inventory.
* Proxy logs.
* DNS logs.

#### Destination IP

`67.199.248.11`

Esta IP debería investigarse en fuentes de reputación y enriquecimiento de infraestructura.

Es importante distinguir entre:

```text
IP maliciosa
```

y:

```text
IP asociada a infraestructura legítima que está siendo utilizada
como parte de una redirección o servicio.
```

Además, el hecho de que una IP aparezca como "clean" en una fuente de reputación **no demuestra que toda la actividad asociada a ella sea legítima**.

#### Destination Port

`80`

El puerto 80 está asociado normalmente con HTTP.

Sin embargo, **utilizar el puerto 80 no convierte una conexión en maliciosa**.

Este fue uno de los errores de interpretación de mi reporte inicial.

Lo relevante no era:

> "Intentó acceder al puerto 80."

sino:

> "El endpoint intentó acceder mediante HTTP a una URL previamente identificada como maliciosa y la conexión fue bloqueada por el firewall."

Esto proporciona mucho más contexto.

### 🧠 Clasificación

**True Positive (TP)**

Existe actividad que merece investigación porque:

1. El endpoint intentó acceder al mismo enlace que apareció en el correo de phishing.
2. La URL había sido identificada previamente como maliciosa.
3. El firewall detectó la conexión.
4. La regla de seguridad bloqueó la comunicación.

### 🛑 ¿Era necesario escalar?

En este caso, **no necesariamente**.

La acción del firewall fue:

`blocked`

Esto significa que el control de seguridad evitó la conexión.

Por tanto, la alerta puede clasificarse como TP porque se produjo un intento de conexión sospechoso, pero eso no significa automáticamente que deba escalarse a N2.

Aquí es importante separar dos conceptos:

```text
Detection
   ↓
True Positive
   ↓
Impact / Success
   ↓
Escalation decision
```

Una detección puede ser un **True Positive** y aun así quedar resuelta en N1 si el control preventivo bloqueó correctamente la actividad y no existen evidencias adicionales de compromiso.

### 📝 Reporte mejorado

**Time of Activity:** 12 minutes

**Affected Entity:**

`10.20.2.17`

**Source IP:**

`10.20.2.17`

**Destination IP:**

`67.199.248.11`

**Destination Port:**

`80/TCP`

**URL:**

`http://bit.ly/3sHkX3da12340`

**Firewall Action:**

`Blocked`

**Classification:**

`True Positive`

**Reason for Classification:**

The internal endpoint `10.20.2.17` attempted to establish an HTTP connection to the URL `http://bit.ly/3sHkX3da12340`, which was previously identified as a malicious destination during the investigation of the phishing email from case 3. The firewall blocked the connection using the `Blocked Websites` rule.

The correlation between the phishing email and the subsequent network connection attempt increases the confidence that the endpoint interacted with the malicious link.

**Reason for Not Escalating:**

The connection was successfully blocked by the firewall and there is currently no evidence in the provided telemetry that the endpoint successfully reached the malicious destination or that a compromise occurred.

Further escalation would become necessary if additional telemetry showed that the endpoint had successfully connected to the destination, downloaded a payload, executed malicious content, or otherwise interacted with attacker infrastructure.

**Recommended Remediation Actions:**

* Identify the endpoint associated with `10.20.2.17`.
* Check proxy/DNS logs for additional requests.
* Review EDR telemetry for suspicious processes or downloads.
* Search for additional connections to the destination IP/domain.
* Check whether the same URL was accessed by other internal hosts.
* Maintain the malicious URL in the appropriate security blocklists.

**Attack Indicators:**

* Source IP: `10.20.2.17`
* Destination IP: `67.199.248.11`
* Destination port: `80/TCP`
* URL: `http://bit.ly/3sHkX3da12340`
* Related phishing campaign from case 3
* Firewall rule: `Blocked Websites`

---

# 🔗 Correlación entre los casos 3 y 4

Probablemente esta sea una de las partes más interesantes del laboratorio.

Si analizamos ambos casos de forma independiente:

```text
CASE 3
Inbound phishing email
        ↓
Malicious shortened URL
        ↓
Potential user interaction
```

Y posteriormente:

```text
CASE 4
Internal host 10.20.2.17
        ↓
HTTP request
        ↓
Same malicious URL
        ↓
Firewall BLOCK
```

Cuando juntamos ambas alertas obtenemos una historia mucho más completa:

```text
Attacker
   │
   ▼
Phishing Email
   │
   ▼
User receives malicious URL
   │
   ▼
User/Endpoint attempts connection
   │
   ▼
Firewall detects request
   │
   ▼
Connection BLOCKED
   │
   ▼
No confirmed compromise
```

Esta correlación es mucho más valiosa desde el punto de vista de un SOC que analizar cada alerta de manera completamente aislada.

---

# 🧠 Principales lecciones aprendidas

## 1. TP ≠ Escalación

Una de las lecciones más importantes de este laboratorio.

```text
True Positive
      ≠
Automatically escalate
```

Primero hay que determinar si la actividad realmente ocurrió.

Después hay que determinar:

* ¿Funcionó el ataque?
* ¿Hubo interacción?
* ¿Hubo compromiso?
* ¿Hubo ejecución?
* ¿Hubo exfiltración?
* ¿El control de seguridad bloqueó el ataque?
* ¿Existe evidencia suficiente para N2?

---

## 2. Una IP no es automáticamente maliciosa

Una dirección IP debe analizarse dentro de su contexto.

Por ejemplo:

```text
IP
│
├── Reputation
├── ASN
├── ISP
├── Geolocation
├── DNS
├── Historical activity
├── Related domains
└── Connections observed internally
```

Una IP "limpia" tampoco significa necesariamente que una actividad sea legítima.

---

## 3. El puerto 80 no es un indicador de compromiso

El puerto:

`80/TCP`

normalmente corresponde a HTTP.

Pero:

```text
Port 80
```

por sí solo no constituye un IoC.

Lo importante es:

```text
Endpoint
   +
Destination
   +
URL
   +
Context
   +
Action
```

En este caso, la relevancia del puerto 80 venía del hecho de que la conexión estaba relacionada con una **URL previamente identificada como maliciosa**.

---

## 4. Hay que buscar correlaciones

Un SOC no debería analizar necesariamente cada alerta de manera aislada.

La pregunta debe ser:

> **¿Hay otras alertas relacionadas con esta actividad?**

En este laboratorio:

```text
Phishing email
       ↓
Malicious URL
       ↓
Firewall connection attempt
       ↓
Same URL
       ↓
Same environment
```

Esto proporciona mucho más contexto que cualquiera de las alertas por separado.

---

# 📈 Qué quiero mejorar en los siguientes labs

Después de este primer laboratorio, mis principales objetivos para los siguientes casos son:

### 🔎 Investigación

* Mejorar el análisis de IPs.
* Investigar dominios y subdominios.
* Analizar URLs y redirecciones.
* Revisar DNS.
* Correlacionar eventos.
* Identificar infraestructura relacionada.
* Utilizar mejor los logs disponibles.

### 📝 Reporting

Quiero que mis reportes sean menos escuetos y respondan siempre a:

```text
What happened?
      ↓
Who was affected?
      ↓
When did it happen?
      ↓
What indicators were involved?
      ↓
Why is it malicious?
      ↓
What evidence supports the conclusion?
      ↓
Was the attack successful?
      ↓
Does it require escalation?
      ↓
What should be done next?
```

### 🚨 Escalation

También quiero mejorar la diferenciación entre:

* Alert classification.
* Incident severity.
* Impact.
* Successful vs blocked attack.
* N1 resolution.
* N2 escalation.

---

# 🏁 Conclusión

Este primer laboratorio me ha servido para pasar de estudiar la teoría de un SOC a enfrentarme a casos donde tengo que **investigar, correlacionar evidencias y justificar una decisión**.

Aunque conseguí la puntuación máxima del laboratorio, la revisión posterior de mis propios reportes me permitió detectar varias carencias, principalmente relacionadas con la profundidad de la investigación y la documentación de los indicadores.

La principal conclusión que saco es que un buen análisis de SOC no consiste únicamente en decir:

> **"Esto es phishing."**

Sino en poder explicar:

> **qué ocurrió, qué evidencia tengo, qué indicadores lo demuestran, qué sistemas están afectados, si el ataque tuvo éxito y qué acciones deberían realizarse a continuación.**

El siguiente objetivo será aplicar esta metodología en los próximos laboratorios y mejorar progresivamente la calidad de mis investigaciones y reportes.
