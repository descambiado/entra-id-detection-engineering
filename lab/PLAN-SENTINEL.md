# Plan: workspace de Sentinel con el crédito de Azure

**Fecha límite dura: 2026-09-19.** Verificado en el portal el 2026-08-29: *"Su crédito gratuito
restante de 200,00 US$ expirará dentro de 21 días."* Cuando expira, la suscripción de prueba deja de
funcionar y **el workspace se muere con ella** salvo que se pase a pago por uso antes.

## El malentendido que hay que quitarse de encima

El objetivo NO es gastar los 175 €. El tenant de pruebas genera unos pocos megas al día, así que
Log Analytics más Sentinel costarán del orden de 1 a 5 € al mes. El crédito no se agota, **caduca**.

El objetivo es **cuántos hallazgos verificados se sacan antes del 19 de septiembre**.

## Por qué esto importa, en una frase

Hoy David escribe KQL para Azure-Sentinel **sin haberlo ejecutado nunca contra datos reales**. Tiene
19 PRs mergeados de hunting queries validadas leyendo esquemas. Un workspace convierte eso en queries
que se han ejecutado de verdad.

Es el mismo principio que ya demostró funcionar: el laboratorio de Entra reveló que dos de sus reglas
estaban muertas. Un workspace revelará lo mismo de sus queries, antes de mandarlas en vez de después.

## Montaje

Requisitos: `az` CLI, y permisos de Global Admin en el tenant para las diagnostic settings.

1. Crear grupo de recursos y workspace de Log Analytics en una región europea.
2. Habilitar Microsoft Sentinel sobre ese workspace. Hay prueba gratuita de Sentinel de 31 días
   independiente del crédito, comprobar si aplica antes de asumir coste.
3. **Diagnostic settings en Entra ID** exportando `AuditLogs` y `SignInLogs` al workspace. Este es el
   paso que da el valor: es lo que pone la tabla real delante.
4. Generar eventos en el tenant, esperar ingesta, y a partir de ahí trabajar con datos propios.

**Poner presupuesto y alerta de coste el primer día.** No por el importe, sino por disciplina: es la
misma razón por la que el laboratorio devuelve el tenant a su estado original después de cada sesión.

## Los tres trabajos que producen resultado, por orden

### 1. Medir la tabla `AuditLogs`, no deducirla

Es lo primero porque cierra un agujero **ya escrito en público**. En el comentario del PR
[SigmaHQ#6247](https://github.com/SigmaHQ/sigma/pull/6247#issuecomment-5463002942) consta:

> *"The diagnostic shape value I have not put a diagnostic settings export in front of myself; I am
> inferring it from Microsoft's and Elastic's own rules."*

Con el workspace se mide. Concretamente: qué emite `OperationName` para
`Update application - Certificates and secrets management`, con qué guion y con o sin espacio final.
Si confirma la deducción, se vuelve al PR con dato medido. Si la desmiente, mejor todavía: se corrige
antes de que se mergee.

Recordatorio de lo ya medido, para contrastar: Graph `directoryAudits` devuelve `activityDisplayName`
con **U+2013 y espacio final**, longitud 57.

### 2. Ejecutar sus propias hunting queries mergeadas contra datos reales

19 PRs mergeados en Azure-Sentinel que **nunca se han ejecutado**. Si alguna está rota, encontrarlo él
y arreglarlo es exactamente el patrón que ya funcionó con SigmaHQ: el hallazgo vale, y contarlo vale
más.

Empezar por las que dependen de nombres de operación literales, que es donde ya apareció el fallo:
las de credenciales de service principal y las de break-glass.

### 3. Buscar huecos de cobertura con eventos reales

Generar operaciones en el tenant, ver qué aparece en la tabla, y contrastar contra el contenido
existente de Azure-Sentinel, SigmaHQ y Elastic. Los huecos verificados con evento real son candidatos
directos a PR.

Ya identificados en la sesión del 20/08 y sin cubrir en SigmaHQ: `Add service principal credentials`,
`Add owner to service principal`, `Delete named location` / `Update named location`, y las operaciones
de cross-tenant access.

## Secuencia con el resto de frentes

Las dos fechas no compiten, van seguidas:

- **10/09**: fecha del Norte (SotyHub, 3 usuarios). Va primero.
- **19/09**: caduca el crédito. Quedan 9 días limpios después del Norte.

Si el Norte se resuelve o se cierra conscientemente el 10, hay margen de sobra. Lo que no se puede es
montar esto **en vez de** hablar con usuarios, que es el patrón que ya está documentado.

## Antes del 19: decidir

Pasar la suscripción a pago por uso o dejar que muera. Si se deja morir, **exportar antes** cualquier
hallazgo, query validada o evidencia que se quiera conservar. Un hallazgo que solo existe dentro de un
workspace que se apaga no existe.
