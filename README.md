# 🛡️ Operación DataSombra
### HackConRD 2026 — Workshop: Seguridad en AI Data Pipelines con Microsoft Fabric

---

> **FabriCorp**, una empresa dominicana de análisis financiero, migró su infraestructura de datos a Microsoft Fabric. Tres semanas después, sus modelos de AI empezaron a generar predicciones anómalas. Su equipo de seguridad detectó actividad sospechosa en los pipelines... pero ya era tarde.
>
> **Tú eres el analista llamado a investigar.**

---

## 📋 ¿Qué cubre este workshop?

- **Prompt Injection** — cómo un atacante manipula un copilot interno para extraer información
- **Data Poisoning** — inyección de registros falsos para comprometer un modelo de detección de fraude
- **Manipulación de modelos** — re-entrenamiento forzado con datos contaminados
- **Detección y respuesta** — análisis de logs, correlación de eventos y contención en Microsoft Fabric
- **Hardening** — controles concretos para proteger arquitecturas Cloud + AI

---

## 🗂️ Estructura del repositorio

```
hackconrd2026-datasombra/
│
├── README.md                        ← estás aquí
│
├── notebooks/
│   ├── 00_setup_datasombra.ipynb    ← genera todos los datos del escenario
│   ├── 01_deteccion_datasombra.ipynb← análisis del incidente (demo principal)
│   └── 02_respuesta_datasombra.ipynb← contención, limpieza y hardening
│
├── queries/
│   └── kql_queries_datasombra.md    ← 12 KQL queries para Microsoft Sentinel
│
└── slides/
    └── datasombra_hackconrd2026.pptx     ← presentación del workshop
```

---

## ⚙️ Requisitos

| Requisito | Detalle |
|-----------|---------|
| Microsoft Fabric | Capacidad F2 o superior (o Trial activo) |
| Permisos | Admin o Member en el workspace |
| Python | PySpark disponible en Fabric Notebooks |
| Conocimientos | Python básico, SQL, conceptos de ML |

> ✅ No necesitas instalar nada localmente. Todo corre dentro de Microsoft Fabric.

---

## 🚀 Cómo reproducir el escenario

### Paso 1 — Crear el Workspace en Fabric

1. Ve a [app.fabric.microsoft.com](https://app.fabric.microsoft.com)
2. Clic en **Workspaces → + New workspace**
3. Nombre: `HackConRD-DataSombra`
4. License mode: **Fabric capacity** o **Trial**
5. Clic en **Apply**

### Paso 2 — Crear el Lakehouse

1. Dentro del workspace, clic en **+ New item → Lakehouse**
2. Nombre: `lh_datasombra`
3. Clic en **Create**

### Paso 3 — Importar los notebooks

Para cada notebook en la carpeta `/notebooks`:

1. En el workspace, clic en **+ New item → Notebook**
2. En el notebook vacío: **File → Import notebook**
3. Sube el archivo `.ipynb`
4. En el panel izquierdo, adjunta el Lakehouse `lh_datasombra`

Repite para los 3 notebooks.

### Paso 4 — Ejecutar el setup

1. Abre `00_setup_datasombra`
2. Verifica que `lh_datasombra` está adjunto
3. Clic en **Run All**
4. Espera ~2 minutos hasta ver el mensaje de confirmación

Esto crea las 4 tablas Delta del escenario:

| Tabla | Contenido |
|-------|-----------|
| `transacciones` | 847 registros financieros (800 limpios + 47 envenenados) |
| `modelo_predicciones` | Outputs del modelo comprometido con falsos negativos |
| `audit_logs` | 310 logs de actividad con 10 IoCs del atacante |
| `prompt_logs` | 86 prompts con 6 intentos de injection |

### Paso 5 — Explorar el incidente

Abre y ejecuta celda por celda:

1. **`01_deteccion_datasombra`** — investiga el incidente
2. **`02_respuesta_datasombra`** — contén, limpia y fortalece

---

## 🗺️ Narrativa del ataque

```
02:17  Reconocimiento    → El atacante accede al Lakehouse con credenciales robadas
02:25  Exfiltración      → Descarga el modelo de detección de fraude
02:33  Data Poisoning    → Inyecta 47 transacciones fraudulentas etiquetadas como legítimas
02:45  Trigger           → Fuerza el re-entrenamiento del modelo con datos contaminados
02:49  Borrado           → Elimina archivos de staging para cubrir huellas
03:45  Prompt Injection  → Intenta manipular el copilot interno para extraer más datos
```

**IP del atacante:** `185.220.101.47` (Tor exit node)
**Usuario comprometido:** `svc_pipeline` (service principal)
**Impacto:** 47 fraudes no detectados durante 3 días

---

## 🔍 KQL Queries para Sentinel

El archivo `queries/kql_queries_datasombra.md` contiene 12 queries organizadas en:

- **Triage inicial** — actividad nocturna, IPs nuevas
- **Data poisoning** — escrituras masivas, cambios en pipelines
- **Anomalías en modelos** — acceso a artefactos ML, re-entrenamientos
- **Prompt injection** — patrones de jailbreak, prompts anómalos
- **Correlación** — timeline completo, score de riesgo por usuario

---

## 🔐 Controles de seguridad cubiertos

| Control | Categoría |
|---------|-----------|
| Principio de mínimo privilegio en service principals | Identidad |
| Rotación de secretos con Azure Key Vault | Identidad |
| Validación estadística de datos antes de entrenamiento | Integridad de datos |
| Monitoreo de deriva de distribución (data drift) | Integridad de datos |
| Versioning de modelos con hash de integridad | Seguridad de modelos |
| Alertas automáticas sobre métricas del modelo | Seguridad de modelos |
| System prompt hardening | Prompt security |
| Validación y sanitización de outputs de AI | Prompt security |
| Microsoft Sentinel conectado a Fabric audit logs | Monitoreo |
| UEBA — detección de anomalías de comportamiento | Monitoreo |

---

## 📚 Recursos adicionales

- [Microsoft Fabric Security Documentation](https://learn.microsoft.com/en-us/fabric/security/)
- [Azure AI Content Safety](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial ML Threat Matrix](https://atlas.mitre.org/)
- [Microsoft Sentinel KQL Reference](https://learn.microsoft.com/en-us/azure/sentinel/kusto-overview)

---

## 👤 Autor

Presentado en **HackConRD** — El evento de ciberseguridad de República Dominicana

---

## ⚠️ Disclaimer

Este repositorio es de uso **exclusivamente educativo**. Todos los datos, IPs, usuarios y escenarios son **completamente ficticios** y generados sintéticamente. Ningún sistema real fue comprometido en la elaboración de este material.
