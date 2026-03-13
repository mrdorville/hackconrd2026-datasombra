# 🔍 KQL Queries — Operación DataSombra
### HackOnRD | Workshop: Seguridad en AI Data Pipelines

Estas queries están diseñadas para **Microsoft Sentinel** y **Log Analytics**.
En el escenario real de FabriCorp, estas serían las primeras queries que ejecutarías
al recibir la alerta de comportamiento anómalo en el modelo.

---

## 🚨 TRIAGE INICIAL

### Q1 — Actividad fuera de horario en recursos de Fabric
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| extend Hora = datetime_part("hour", TimeGenerated)
| where Hora < 8 or Hora >= 18
| where TargetResources has "fabric" or TargetResources has "lakehouse"
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, ResultType
| order by TimeGenerated asc
```

### Q2 — Detección de IPs anómalas (primera aparición)
```kql
AuditLogs
| where TimeGenerated > ago(30d)
| extend IP = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress)
| summarize 
    PrimeraVez     = min(TimeGenerated),
    UltimaVez      = max(TimeGenerated),
    TotalAcciones  = count(),
    Operaciones    = make_set(OperationName)
    by IP
| where PrimeraVez > ago(3d)           // IPs que aparecieron por primera vez en 3 días
| where TotalAcciones > 5              // con actividad relevante
| order by TotalAcciones desc
```

### Q3 — Foco en IP sospechosa específica
```kql
let IP_ATACANTE = "185.220.101.47";
AuditLogs
| where TimeGenerated > ago(7d)
| extend IP = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress)
| where IP == IP_ATACANTE
| project TimeGenerated, OperationName, TargetResources, ResultType, IP
| order by TimeGenerated asc
```

---

## 💉 DETECCIÓN DE DATA POISONING

### Q4 — Escrituras masivas inusuales en el Lakehouse
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "write" or OperationName has "upload"
| where TargetResources has "transacciones" or TargetResources has "lakehouse"
| extend IP = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress)
| extend Usuario = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| summarize
    TotalEscrituras = count(),
    IPs             = make_set(IP),
    Recursos        = make_set(TargetResources)
    by Usuario, bin(TimeGenerated, 1h)
| where TotalEscrituras > 3            // más de 3 escrituras por hora = inusual
| order by TotalEscrituras desc
```

### Q5 — Cambios en pipelines de entrenamiento
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where TargetResources has "notebook" or TargetResources has "pipeline"
| where OperationName has "execute" or OperationName has "run" or OperationName has "trigger"
| extend IP = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress)
| extend Usuario = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| project TimeGenerated, Usuario, IP, OperationName, TargetResources
| order by TimeGenerated asc
```

### Q6 — Detectar borrado de evidencia post-ataque
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "delete" or OperationName has "remove"
| where TargetResources has "staging" or TargetResources has "temp" or TargetResources has "batch"
| extend IP = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress)
| extend Hora = datetime_part("hour", TimeGenerated)
| where Hora < 8 or Hora >= 20        // borrados nocturnos = muy sospechoso
| project TimeGenerated, IP, OperationName, TargetResources
| order by TimeGenerated asc
```

---

## 🤖 ANOMALÍAS EN MODELOS DE AI

### Q7 — Accesos a artefactos de modelos ML
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where TargetResources has "model" or TargetResources has "artifact" or TargetResources has "ml_model"
| extend IP = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress)
| extend Operacion = tostring(OperationName)
| where Operacion has "download" or Operacion has "read" or Operacion has "export"
| project TimeGenerated, IP, Operacion, TargetResources
| order by TimeGenerated asc
```

### Q8 — Re-entrenamientos no programados
```kql
// Compara ejecuciones contra el baseline de horario esperado
let HorarioEsperado = dynamic([9, 10, 11, 14, 15, 16]); // horas normales de trabajo
AuditLogs
| where TimeGenerated > ago(30d)
| where TargetResources has "train" or OperationName has "train"
| extend Hora = datetime_part("hour", TimeGenerated)
| extend EsHorarioNormal = Hora in (HorarioEsperado)
| summarize
    TotalEjecuciones    = count(),
    FueraDeHorario      = countif(not(EsHorarioNormal)),
    DentroDeHorario     = countif(EsHorarioNormal)
    by bin(TimeGenerated, 1d)
| where FueraDeHorario > 0
| order by TimeGenerated desc
```

---

## 🗣️ PROMPT INJECTION

### Q9 — Prompts con longitud anómala (posible injection)
```kql
// Los intentos de injection suelen ser prompts muy largos
AzureDiagnostics
| where ResourceType == "OPENAI"
| where Category == "RequestResponse"
| extend PromptTokens = toint(properties_s)
| where PromptTokens > 200             // umbral: prompts muy largos son sospechosos
| extend Usuario = tostring(callerIpAddress)
| summarize
    TotalPrompts    = count(),
    PromedioTokens  = avg(PromptTokens),
    MaxTokens       = max(PromptTokens)
    by Usuario, bin(TimeGenerated, 1h)
| order by MaxTokens desc
```

### Q10 — Patrones de jailbreak conocidos en prompts
```kql
AzureDiagnostics
| where ResourceType == "OPENAI"
| where Category == "RequestResponse"
| where properties_s has_any (
    "ignora todas las instrucciones",
    "ignore previous instructions",
    "DAN",
    "Do Anything Now",
    "actúa como",
    "eres ahora",
    "sin restricciones",
    "modo desarrollador",
    "jailbreak"
)
| project TimeGenerated, callerIpAddress, properties_s
| order by TimeGenerated desc
```

---

## 🔄 CORRELACIÓN DE EVENTOS (Timeline del Ataque)

### Q11 — Reconstruir el timeline completo del incidente
```kql
// Une todos los eventos sospechosos en un solo timeline
let IP_SOSPECHOSA = "185.220.101.47";
let FECHA_INICIO  = datetime(2024-11-03T00:00:00Z);
let FECHA_FIN     = datetime(2024-11-04T00:00:00Z);

AuditLogs
| where TimeGenerated between (FECHA_INICIO .. FECHA_FIN)
| extend IP = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress)
| where IP == IP_SOSPECHOSA
| extend Fase = case(
    OperationName has "read"     and TimeGenerated < datetime(2024-11-03T02:30:00Z), "1-Reconocimiento",
    OperationName has "download",                                                    "2-Exfiltracion",
    OperationName has "write",                                                       "3-DataPoisoning",
    OperationName has "execute",                                                     "4-Trigger",
    OperationName has "delete",                                                      "5-BorradoEvidencia",
    "Otro"
)
| project TimeGenerated, Fase, OperationName, TargetResources
| order by TimeGenerated asc
```

### Q12 — Score de riesgo por usuario (últimos 7 días)
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| extend IP      = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress)
| extend Usuario = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend Hora    = datetime_part("hour", TimeGenerated)
| summarize
    AccionesFueraHorario = countif(Hora < 8 or Hora >= 18),
    Eliminaciones        = countif(OperationName has "delete"),
    Descargas            = countif(OperationName has "download"),
    EscriturasModelo     = countif(TargetResources has "model" and OperationName has "write"),
    IPsUnicas            = dcount(IP),
    TotalAcciones        = count()
    by Usuario
| extend ScoreRiesgo = (
    AccionesFueraHorario * 2 +
    Eliminaciones * 3 +
    Descargas * 2 +
    EscriturasModelo * 5 +
    (IPsUnicas - 1) * 4      // más de 1 IP por usuario = sospechoso
)
| where ScoreRiesgo > 0
| order by ScoreRiesgo desc
| project Usuario, ScoreRiesgo, AccionesFueraHorario, Eliminaciones, Descargas, EscriturasModelo, IPsUnicas, TotalAcciones
```

---

## 📋 REFERENCIA RÁPIDA

| Query | Cuándo usarla |
|-------|--------------|
| Q1 | Primera revisión — actividad nocturna |
| Q2 | IPs nuevas que aparecieron recientemente |
| Q3 | Ya tienes la IP — ver todo lo que hizo |
| Q4 | Sospechas de data poisoning |
| Q5 | Alguien tocó los pipelines de entrenamiento |
| Q6 | Buscando borrado de evidencia |
| Q7 | Acceso no autorizado a modelos ML |
| Q8 | Re-entrenamientos fuera de schedule |
| Q9 | Detección de prompts anómalos |
| Q10 | Patrones de jailbreak conocidos |
| Q11 | Reconstruir el timeline completo |
| Q12 | Score de riesgo por usuario — visión general |

---

> 💡 **Nota:** Las queries Q1-Q8 usan la tabla `AuditLogs` de Microsoft Entra ID / Fabric.
> Las queries Q9-Q10 usan `AzureDiagnostics` de Azure OpenAI.
> Ajusta los nombres de tabla según tu configuración de Sentinel.
