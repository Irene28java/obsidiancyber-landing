'use strict';

const menu = document.querySelector('.menu');
const nav = document.querySelector('nav');
const orderForm = document.querySelector('#orderForm');
const orderDomain = document.querySelector('#orderDomain');
const orderEmail = document.querySelector('#orderEmail');
const orderAuth = document.querySelector('#orderAuth');
const externalIntelConsent = document.querySelector('#externalIntelConsent');
const termsConsent = document.querySelector('#termsConsent');
const immediateDeliveryConsent = document.querySelector('#immediateDeliveryConsent');
const createOrderButton = document.querySelector('#createOrderButton');
const verifyDomainButton = document.querySelector('#verifyDomainButton');
const payButton = document.querySelector('#payButton');
const orderMessage = document.querySelector('#orderMessage');
const checkoutStatus = document.querySelector('#checkoutStatus');
const verificationPanel = document.querySelector('#verificationPanel');
const verificationMessage = document.querySelector('#verificationMessage');
const txtNameEl = document.querySelector('#txtName');
const txtValueEl = document.querySelector('#txtValue');
const reportEl = document.querySelector('#report');
let activeOrder = null;
let commercialHealth = null;
let paypalSdkPromise = null;
let paypalInlineMounted = false;
let activeCardFields = null;
let activePaypalOrderId = null;
let activePaypalOrderFor = null;
let activePaypalOrderMethod = null;

const inlinePayPalPanel = document.querySelector('#inlinePayPalPanel');
const inlinePaymentMessage = document.querySelector('#inlinePaymentMessage');
const paypalButtonContainer = document.querySelector('#paypalButtonContainer');
const cardFieldsPanel = document.querySelector('#cardFieldsPanel');
const cardPayButton = document.querySelector('#cardPayButton');

document.querySelector('#year').textContent = String(new Date().getFullYear());
menu?.addEventListener('click', () => {
  const open = nav.classList.toggle('open');
  menu.setAttribute('aria-expanded', String(open));
});
nav?.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => {
  nav.classList.remove('open');
  menu?.setAttribute('aria-expanded', 'false');
}));

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function line(label, value) {
  const row = el('div', 'data-line');
  const displayValue = value === undefined || value === null || value === '' ? 'No disponible' : value;
  row.append(el('span', 'data-label', label), el('span', 'data-value', displayValue));
  return row;
}
function section(title, eyebrow) {
  const wrapper = el('section', 'report-section');
  wrapper.append(el('div', 'eyebrow', eyebrow), el('h3', '', title));
  return wrapper;
}
function setOrderMessage(message, type = 'info') {
  orderMessage.hidden = false;
  orderMessage.className = `form-message ${type}`;
  orderMessage.textContent = message;
}
function scoreLabel(score) {
  if (score === null || score === undefined) return 'No calculable: señales insuficientes';
  if (score === 0) return 'Sin señales destacadas en esta revisión limitada';
  if (score < 25) return 'Señales de baja prioridad';
  if (score < 50) return 'Revisión recomendada';
  if (score < 75) return 'Prioridad alta';
  return 'Prioridad crítica';
}
function formatDate(value) {
  if (!value) return 'No disponible';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat('es-ES', { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}
function scorePill(score) {
  if (score === null || score === undefined) return 'Sin puntuación';
  if (score >= 75) return 'Atención crítica';
  if (score >= 50) return 'Atención alta';
  if (score >= 25) return 'Revisar';
  if (score > 0) return 'Atención baja';
  return 'Sin regla activada';
}

function renderReport(data) {
  reportEl.replaceChildren();
  reportEl.hidden = false;

  const head = el('div', 'report-header');
  const headCopy = el('div', 'report-title');
  headCopy.append(el('div', 'eyebrow', data.commercial?.payment_status === 'paid' ? 'OBSIDIAN INTELLIGENCE RECORD / PAID REPORT' : 'OBSIDIAN INTELLIGENCE RECORD / DEFENSIVE'), el('h2', '', 'Ficha de exposición digital'), el('p', 'report-subtitle', `Activo evaluado: ${data.domain}`));
  if (data.commercial?.payment_status === 'paid') headCopy.append(el('span', 'paid-stamp', `PAGO CONFIRMADO · ${data.commercial.amount_eur} €`));
  if (data.commercial?.domain_control === 'declared') headCopy.append(el('p', 'report-subtitle', 'Control del dominio: declarado por el cliente, no verificado técnicamente (sin registro DNS TXT).'));
  const stamp = el('div', 'report-stamp');
  stamp.append(el('span', '', 'CASE REFERENCE'), el('strong', '', data.case_id), el('span', '', 'DEFENSIVE REVIEW'));
  head.append(headCopy, stamp);
  reportEl.append(head);

  const summary = el('div', 'report-summary');
  const score = el('div', 'score-panel');
  const scoreNumber = el('div', 'score-number');
  if (data.score === null || data.score === undefined) scoreNumber.textContent = '—';
  else scoreNumber.append(document.createTextNode(String(data.score)), el('small', '', '/100'));
  score.append(el('div', 'eyebrow', 'TLS ATTENTION SCORE'), scoreNumber, el('div', 'score-meter'));
  score.querySelector('.score-meter').style.setProperty('--score', `${data.score ?? 0}%`);
  score.append(el('p', 'score-label', scoreLabel(data.score)), el('p', 'score-method-mini', 'No es una puntuación global de seguridad ni un veredicto de reputación IP.'));
  const summaryDetails = el('div', 'summary-details');
  summaryDetails.append(line('Generado', formatDate(data.generated_at)), line('Alcance', data.scope || 'DNS + comprobaciones HTTPS limitadas en 443'), line('Direcciones públicas', data.addresses?.length ?? 0), line('IP con TLS comprobado', `${data.tls_checks_performed ?? 0} / ${data.addresses?.length ?? 0}`), line('Consulta reputación', `${data.reputation_checks_performed ?? 0} / ${data.reputation_checks_limit ?? 4} IP`), line('Hallazgos TLS priorizados', data.findings?.length ?? 0), line('Señales de reputación a revisar', data.reputation_findings?.length ?? 0));
  summary.append(score, summaryDetails);
  reportEl.append(summary);

  const scopeNote = el('div', 'report-notice');
  scopeNote.append(el('strong', '', 'Confianza, cobertura y límites'), el('p', '', data.confidence_summary || 'La confianza depende de cada fuente. Las observaciones son una fotografía temporal; no prueban propiedad ni garantizan cobertura completa.'), el('p', '', 'Un score 0 significa que las reglas TLS configuradas no activaron ninguna señal en las IP comprobadas. No demuestra que el activo sea seguro. Las señales de reputación se mantienen separadas del score TLS.'));
  reportEl.append(scopeNote);

  const scoreSection = section('Cómo se ha calculado la puntuación', 'SCORING / EXPLAINED');
  scoreSection.append(el('p', 'section-explainer', data.score_methodology || 'El score se limita a señales incluidas en las reglas y no representa un riesgo global.'));
  const breakdown = el('div', 'score-breakdown-grid');
  for (const item of (data.score_breakdown || [])) {
    const card = el('article', 'score-breakdown-card');
    const top = el('div', 'finding-top');
    top.append(el('strong', '', item.title || item.rule_id || 'Regla'), el('span', 'finding-weight', item.points === null || item.points === undefined ? 'No puntuado' : `+${item.points} puntos`));
    card.append(top, el('p', '', item.rationale || 'Sin detalle disponible.'), line('IP que contribuye', item.ip || 'Sin contribución por evidencia insuficiente'), line('Fuente', item.source || 'Reglas locales ObsidianCyber'));
    breakdown.append(card);
  }
  scoreSection.append(breakdown);
  const rules = el('div', 'rule-reference');
  rules.append(el('h4', '', 'Reglas activas en esta versión'));
  for (const rule of (data.score_rules || [])) rules.append(line(`${rule.condition} · ${rule.id}`, `${rule.points} puntos · ${rule.meaning}`));
  scoreSection.append(rules);
  reportEl.append(scoreSection);

  const timelineSection = section('Cronología de evidencias', 'EVIDENCE TIMELINE / UTC');
  timelineSection.append(el('p', 'section-explainer', 'La cronología muestra cuándo se observó cada señal y qué fuente la produjo. La hora no implica continuidad ni monitorización histórica.'));
  const timeline = el('div', 'timeline');
  for (const event of (data.timeline || [])) {
    const card = el('article', 'timeline-event');
    const marker = el('span', `timeline-marker timeline-${event.category || 'event'}`);
    const copy = el('div', 'timeline-copy');
    const top = el('div', 'timeline-top');
    top.append(el('span', 'timeline-date', formatDate(event.timestamp)), el('span', 'confidence-pill', event.confidence || 'Confianza no especificada'));
    copy.append(top, el('h4', '', event.title || 'Evento'), el('p', '', event.detail || 'Sin detalle.'), line('Fuente', event.source || 'No especificada'), el('p', 'subtle-note', event.confidence_note || 'Revisa la metodología de la fuente.'));
    card.append(marker, copy);
    timeline.append(card);
  }
  if (!(data.timeline || []).length) timeline.append(el('p', 'empty-state', 'No hay eventos de evidencia disponibles.'));
  timelineSection.append(timeline);
  reportEl.append(timelineSection);

  const ipsSection = section('Direcciones IP y contexto de red', 'EVIDENCE / 01');
  if (!data.addresses?.length) ipsSection.append(el('p', 'empty-state', 'No se obtuvieron direcciones utilizables. Revisa el estado DNS y vuelve a comprobar manualmente.'));
  const ipTable = el('div', 'evidence-table');
  for (const item of (data.addresses || [])) {
    const card = el('article', 'ip-card');
    card.append(el('div', 'ip-address', item.ip), el('span', `status status-${item.tls?.status === 'valid' ? 'live' : item.tls?.status === 'not_checked' ? 'setup' : 'manual'}`, item.version || 'IP'));
    const geo = item.geolocation || {};
    const geoLabel = geo.status === 'available' ? [geo.city, geo.region, geo.country].filter(Boolean).join(', ') || 'Datos parciales' : geo.status === 'not_found' ? 'Sin dato en la base local' : 'No configurada / sin dato';
    card.append(line('Geolocalización aproximada', geoLabel), line('ASN / proveedor', geo.asn ? `${geo.asn}${geo.asn_org ? ` · ${geo.asn_org}` : ''}` : 'No disponible'), line('Coordenadas aproximadas', geo.latitude != null && geo.longitude != null ? `${geo.latitude}, ${geo.longitude}` : 'No disponibles'));
    if (geo.source) card.append(line('Fuente GeoIP', geo.source), line('Observado', formatDate(geo.observed_at)), el('p', 'subtle-note', geo.confidence_note || 'La localización es aproximada; no localiza una persona o domicilio.'));
    const ipTls = item.tls || {};
    const ipTlsLabel = ({ valid: 'TLS verificado', verification_failed: 'Fallo de verificación TLS', error: 'Inconcluso / error de conexión', not_checked: 'No comprobado' })[ipTls.status] || 'No disponible';
    card.append(line('HTTPS / TLS', ipTlsLabel), line('Score de atención TLS', item.score === null || item.score === undefined ? 'No calculable / no comprobada' : `${item.score}/100 · ${scoreLabel(item.score)}`), line('Certificado válido hasta', ipTls.not_after ? formatDate(ipTls.not_after) : 'No disponible'));
    if (ipTls.source) card.append(line('Fuente TLS', ipTls.source), line('Observado', formatDate(ipTls.observed_at)));
    if (geo?.status !== 'available') card.append(el('p', 'subtle-note', geo?.message || 'La geolocalización requiere una fuente de datos con licencia apropiada para uso comercial.'));
    if (ipTls.status === 'not_checked') card.append(el('p', 'subtle-note', ipTls.message || 'No se realizó comprobación TLS para esta IP debido al límite de seguridad de la ejecución.'));
    const rep = item.reputation || {};
    card.append(el('div', 'ip-subhead', 'INTELIGENCIA DE REPUTACIÓN (SEPARADA)'), line('Estado de reputación', rep.status === 'available' ? 'Respuesta de proveedor recibida' : rep.status === 'not_configured' ? 'Fuente no configurada' : rep.status === 'not_consented' ? 'No consultada: sin consentimiento' : rep.status === 'not_checked' ? 'No comprobada' : rep.status === 'provider_error' ? 'Consulta inconclusa' : rep.status || 'No disponible'));
    if (rep.status === 'available') {
      card.append(line('Abuse confidence del proveedor', rep.abuse_confidence_score === null ? 'No disponible' : `${rep.abuse_confidence_score}/100`), line('Reportes / reporteros', `${rep.total_reports ?? 0} / ${rep.distinct_reporters ?? 0}`), line('Último reporte observado', formatDate(rep.last_reported_at)), line('Tipo de uso / ISP', [rep.usage_type, rep.isp].filter(Boolean).join(' · ') || 'No disponible'), line('Fuente de reputación', rep.source || 'Proveedor externo'), el('p', 'subtle-note', rep.message || 'La puntuación del proveedor no confirma actividad maliciosa.'));
      if (rep.shared_infrastructure_likely) card.append(el('p', 'shared-warning', 'POSIBLE INFRAESTRUCTURA COMPARTIDA: CDN, hosting o centro de datos. Validar el contexto antes de atribuir reportes al cliente.'));
    } else card.append(el('p', 'subtle-note', rep.message || 'No se consultó una fuente de reputación para esta IP.'));
    if (geo?.latitude != null && geo?.longitude != null) {
      const mapLink = el('a', 'map-link', 'Ver referencia geográfica aproximada ↗');
      mapLink.href = `https://www.openstreetmap.org/?mlat=${encodeURIComponent(geo.latitude)}&mlon=${encodeURIComponent(geo.longitude)}#map=6/${encodeURIComponent(geo.latitude)}/${encodeURIComponent(geo.longitude)}`;
      mapLink.target = '_blank';
      mapLink.rel = 'noopener noreferrer';
      mapLink.setAttribute('referrerpolicy', 'no-referrer');
      card.append(mapLink);
    }
    ipTable.append(card);
  }
  ipsSection.append(ipTable);
  reportEl.append(ipsSection);

  const dnsSection = section('Resolución DNS', 'EVIDENCE / 02');
  dnsSection.append(line('Estado', data.dns?.status === 'ok' ? 'Resuelto' : data.dns?.status === 'error' ? 'Error / no resuelto' : 'Inconcluso'), line('Fuente', data.dns?.source || 'Resolver DNS del sistema'), line('Fecha de observación', formatDate(data.dns?.observed_at)), line('Detalle', data.dns?.message || 'Se obtuvieron direcciones públicas.'));
  reportEl.append(dnsSection);

  const tlsSection = section('Certificado y conexión TLS', 'EVIDENCE / 03');
  const tls = data.tls || {};
  const tlsStatus = ({ valid: 'Verificación correcta', verification_failed: 'Fallo de verificación', error: 'No comprobado correctamente', not_checked: 'No comprobado' })[tls.status] || 'Inconcluso';
  tlsSection.append(line('Estado', tlsStatus), line('IP comprobada', tls.ip || 'No disponible'), line('Fuente', tls.source || 'Cliente TLS de ObsidianCyber'), line('Observado', formatDate(tls.observed_at)), line('Versión TLS', tls.version || 'No disponible'), line('Cifrado negociado', tls.cipher || 'No disponible'), line('Válido hasta', tls.not_after ? formatDate(tls.not_after) : 'No disponible'), line('Días restantes', tls.days_remaining ?? 'No disponible'), line('Detalle', tls.message || 'Sin detalle adicional'));
  reportEl.append(tlsSection);

  const findingSection = section('Hallazgos TLS y acciones sugeridas', 'ASSESSMENT / 04');
  if (!(data.findings || []).length) findingSection.append(el('p', 'empty-state', data.score === null ? 'No hay base suficiente para puntuar señales. Revisa los errores e interpreta el resultado de forma manual.' : 'Esta comprobación limitada no ha identificado señales TLS que superen las reglas de priorización configuradas. Esto no acredita ausencia de otras exposiciones.'));
  for (const finding of (data.findings || [])) {
    const card = el('article', 'finding-card');
    const top = el('div', 'finding-top');
    top.append(el('span', `severity severity-${finding.severity}`, finding.severity_label || finding.severity), el('span', 'finding-weight', `+${finding.weight} puntos`));
    card.append(top, el('h4', '', finding.title), el('p', '', finding.detail), line('IP asociada', finding.ip || 'Dominio / no especificada'), line('Fuente', finding.source || 'Comprobación TLS local'), line('Observado', formatDate(finding.observed_at)), line('Confianza', finding.confidence || 'Observación técnica puntual'), line('Evidencia', finding.evidence), line('Siguiente paso', finding.recommendation));
    findingSection.append(card);
  }
  reportEl.append(findingSection);

  const repSection = section('Señales de reputación que requieren validación', 'THREAT INTEL / 04B');
  repSection.append(el('p', 'section-explainer', 'Estas observaciones permanecen separadas del score TLS. Reportes de terceros, direcciones de hosting y CDN compartidos pueden producir falsas atribuciones; el equipo debe revisar origen, fechas y contexto antes de comunicar un incidente.'));
  if (!(data.reputation_findings || []).length) repSection.append(el('p', 'empty-state', 'No hay señales de reputación que mostrar. Esto puede significar que la fuente no está conectada, no se autorizó la consulta o que el proveedor no devolvió un indicador por encima del umbral de revisión; no equivale a una IP limpia.'));
  for (const finding of (data.reputation_findings || [])) {
    const card = el('article', 'finding-card');
    const top = el('div', 'finding-top');
    top.append(el('span', `severity severity-${finding.severity}`, finding.severity_label), el('span', 'finding-weight', `Fuente: ${finding.vendor_score}/100`));
    card.append(top, el('h4', '', finding.title), el('p', '', finding.detail), line('IP asociada', finding.ip), line('Reportes de proveedor', finding.total_reports), line('Fuente / hora', `${finding.source || 'Fuente externa'} · ${formatDate(finding.observed_at)}`), line('Confianza', finding.confidence), line('Acción recomendada', finding.recommendation));
    if (finding.shared_infrastructure_likely) card.append(el('p', 'shared-warning', 'Posible infraestructura compartida; no atribuir la actividad al cliente sin evidencias adicionales.'));
    repSection.append(card);
  }
  reportEl.append(repSection);

  const modulesSection = section('Cobertura y límites de esta revisión', 'COLLECTION STATUS / 05');
  const moduleGrid = el('div', 'module-grid');
  for (const module of (data.modules || [])) {
    const card = el('article', 'module-card');
    card.append(el('div', 'module-top', module.label), el('span', `status status-${module.status_class}`, module.status_label), el('p', '', module.detail));
    moduleGrid.append(card);
  }
  modulesSection.append(moduleGrid);
  reportEl.append(modulesSection);

  const sourceSection = section('Fuentes y metodología', 'PROVENANCE / 06');
  const sourceGrid = el('div', 'module-grid source-grid');
  for (const source of (data.sources || [])) {
    const card = el('article', 'module-card');
    card.append(el('div', 'module-top', source.name), el('p', '', source.mode), el('p', '', source.limitation));
    sourceGrid.append(card);
  }
  sourceSection.append(sourceGrid);
  reportEl.append(sourceSection);

  const footer = el('div', 'report-footer');
  const retentionLine = data.commercial?.payment_status === 'paid'
    ? `Pedido pagado: ${data.commercial.order_id}. Informe almacenado hasta ${data.commercial.retention_days} días para permitir la recuperación del resultado. El borrado automático requiere que el servidor permanezca operativo.`
    : 'Documento de demostración/prueba. No se almacena este resultado salvo que proceda del flujo de pedido pagado.';
  footer.append(el('p', '', `${retentionLine} · Verificar cada señal antes de tratarla como incidente confirmado. La ficha no sustituye una auditoría completa.`));
  const actions = el('div', 'actions report-actions');
  const printButton = el('button', 'button primary', 'Imprimir / guardar PDF');
  printButton.type = 'button';
  printButton.addEventListener('click', () => window.print());
  const hideButton = el('button', 'button', 'Cerrar ficha');
  hideButton.type = 'button';
  hideButton.addEventListener('click', () => { reportEl.hidden = true; document.querySelector('#workspace').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
  actions.append(printButton, hideButton);
  footer.append(actions);
  reportEl.append(footer);
  reportEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `El servidor respondió con HTTP ${response.status}.`);
  return payload;
}
function showVerification(order) {
  const isNewOrder = activeOrder?.order_id !== order.order_id;
  if (isNewOrder) {
    activePaypalOrderId = null;
    activePaypalOrderFor = null;
    activePaypalOrderMethod = null;
    inlinePayPalPanel.hidden = true;
    payButton.hidden = false;
    payButton.textContent = 'Mostrar opciones de pago ↗';
    if (paypalButtonContainer) paypalButtonContainer.style.pointerEvents = 'auto';
    if (cardPayButton) cardPayButton.disabled = false;
  }

  activeOrder = order;
  verificationPanel.hidden = false;
  txtNameEl.textContent = order.txt_name;
  txtValueEl.textContent = order.txt_value;
  const dnsRequired = commercialHealth?.dns_verification_required !== false;
  verificationPanel.querySelectorAll('.txt-value, .verification-header p').forEach((node) => { node.hidden = !dnsRequired; });
  verifyDomainButton.hidden = !dnsRequired;
  const verificationTitle = verificationPanel.querySelector('.verification-header h3');
  if (verificationTitle) verificationTitle.textContent = dnsRequired ? 'Publica este registro DNS' : 'Solicitud lista para el pago';
  verifyDomainButton.disabled = false;
  payButton.disabled = !order.verified
    || commercialHealth?.payment_enabled !== true
    || !commercialHealth?.paypal_client_id;
  verificationMessage.textContent = order.verified
    ? (dnsRequired
      ? 'Dominio verificado. Ya puedes mostrar las opciones de pago seguro.'
      : 'Has declarado tener autorización sobre este dominio. Ya puedes mostrar las opciones de pago seguro.')
    : 'Publica el TXT anterior; después vuelve a comprobarlo. No se cobra hasta completar este paso.';
}
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const temporary = document.createElement('textarea');
    temporary.value = text;
    temporary.setAttribute('readonly', '');
    temporary.style.position = 'absolute';
    temporary.style.left = '-9999px';
    document.body.append(temporary);
    temporary.select();
    document.execCommand('copy');
    temporary.remove();
  }
}
document.querySelector('#copyTxtName')?.addEventListener('click', () => copyText(txtNameEl.textContent));
document.querySelector('#copyTxtValue')?.addEventListener('click', () => copyText(txtValueEl.textContent));

async function loadCommercialStatus() {
  try {
    const response = await fetch('/api/health', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`API health respondió HTTP ${response.status}`);
    }

    const health = await response.json();
    commercialHealth = health;
    if (!health || typeof health !== 'object') {
      throw new Error('La API health no devolvió un objeto JSON válido');
    }

    const dnsRequired = health.dns_verification_required !== false;
    const dnsReady = health.dns_txt_verification_ready === true || !dnsRequired;
    const paymentReady = health.payment_enabled === true;
    createOrderButton.disabled = !dnsReady;
    const workspaceIntro = document.querySelector('#workspaceIntro');
    if (workspaceIntro && !dnsRequired) {
      workspaceIntro.textContent = 'Indica tu dominio y confirma que tienes autorización para revisarlo. Después podrás elegir un método de pago disponible. El informe se genera y se muestra únicamente cuando el servidor confirma el pago.';
    }
    if (!dnsRequired) createOrderButton.textContent = 'Preparar pago ↗';
    checkoutStatus.className = `checkout-status ${paymentReady ? 'ready' : 'not-ready'}`;
    checkoutStatus.textContent = paymentReady
      ? (dnsRequired ? '3 pasos: indica tu dominio, publica un registro TXT (unos 2 minutos) y paga con tarjeta o PayPal. El informe aparece al momento.' : 'Confirma la autorización del dominio para continuar. Después podrás elegir un método de pago disponible.')
      : dnsReady
        ? 'Verificación DNS disponible. Los pagos siguen desactivados; no se realizará ningún cobro.'
        : 'Verificación DNS no disponible. Los pagos siguen desactivados; revisa la configuración antes de continuar.';
    if (paymentReady) setOrderMessage(dnsRequired ? 'Rellena el formulario. En el siguiente paso te daremos el registro TXT que demuestra que el dominio es tuyo; después podrás pagar.' : 'Rellena el formulario y pasa directamente al pago seguro.', 'success');
    else if (dnsReady) setOrderMessage('Puedes preparar una solicitud y verificar el dominio. No se cobrará nada mientras los pagos sigan desactivados.', 'info');
    else setOrderMessage('La verificación DNS aún no está disponible. No se crea ni cobra ningún pedido.', 'info');
    const fmtEUR = (cents) => `${(Number(cents || 0) / 100).toLocaleString('es-ES', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} €`;
    const totalCents = Number(health.pilot_price_cents || 7900);
    const price = fmtEUR(totalCents);
    payButton.textContent = `Mostrar opciones de pago · ${price} ↗`;
    document.querySelectorAll('.pilot-price, .pilot-price-total').forEach((node) => { node.textContent = price; });
    document.querySelectorAll('.pilot-price-breakdown').forEach((node) => {
      node.textContent = 'IVA incluido';
    });
    document.querySelectorAll('#cardPayButton').forEach((node) => { node.textContent = `Pagar con tarjeta · ${price}`; });
  } catch (error) {
    console.error('[ObsidianCyber] Error en loadCommercialStatus:', error);
    if (createOrderButton) createOrderButton.disabled = true;
    if (checkoutStatus) {
      checkoutStatus.className = 'checkout-status not-ready';
      checkoutStatus.textContent = 'No podemos consultar el servicio ahora mismo. Inténtalo de nuevo más tarde.';
    }
    if (typeof setOrderMessage === 'function') {
      setOrderMessage('No se pudo confirmar el estado del backend. No se crea ni cobra ningún pedido.', 'error');
    }
  }
}

orderForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (createOrderButton.disabled) return;
  if (!orderAuth.checked || !termsConsent.checked || !immediateDeliveryConsent.checked) {
    setOrderMessage('Confirma la autorización del activo, el alcance del piloto y la entrega inmediata para continuar.', 'error');
    return;
  }
  createOrderButton.disabled = true;
  createOrderButton.textContent = 'Creando solicitud…';
  try {
    const order = await postJson('/api/orders', {
      domain: orderDomain.value.trim(),
      email: orderEmail.value.trim(),
      authorized: true,
      external_intel_consent: externalIntelConsent.checked,
      terms_acknowledged: termsConsent.checked,
      immediate_delivery_consent: immediateDeliveryConsent.checked
    });
    order.verified = order.verified === true;
    localStorage.setItem(`oc-report-token:${order.order_id}`, order.report_access_token);
    sessionStorage.setItem('oc-pending-order', JSON.stringify(order));
    showVerification(order);
    setOrderMessage(order.verified
      ? `Solicitud ${order.order_id} creada. Aún no se ha cobrado nada. Elige tu método de pago.`
      : `Solicitud ${order.order_id} creada. Aún no se ha cobrado nada. Publica el TXT y verifica el dominio.`, 'success');
    verificationPanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (error) {
    setOrderMessage(error.message || 'No se pudo crear la solicitud.', 'error');
  } finally {
    createOrderButton.textContent = commercialHealth?.dns_verification_required === false ? 'Preparar pago ↗' : 'Preparar verificación ↗';
    await loadCommercialStatus();
  }
});

verifyDomainButton?.addEventListener('click', async () => {
  if (!activeOrder?.order_id) return;
  verifyDomainButton.disabled = true;
  verificationMessage.textContent = 'Consultando el registro TXT…';
  try {
    const result = await postJson('/api/orders/verify', { order_id: activeOrder.order_id });
    activeOrder.verified = result.verified === true;
    sessionStorage.setItem('oc-pending-order', JSON.stringify(activeOrder));
    payButton.disabled = !activeOrder.verified;
    verificationMessage.textContent = result.message;
    setOrderMessage(result.message, activeOrder.verified ? 'success' : 'info');
  } catch (error) {
    verificationMessage.textContent = error.message || 'No se pudo comprobar el TXT.';
    setOrderMessage(verificationMessage.textContent, 'error');
  } finally {
    verifyDomainButton.disabled = false;
  }
});

async function loadPayPalSdk() {
  if (window.paypal?.Buttons && window.paypal?.CardFields) return;
  if (paypalSdkPromise) return paypalSdkPromise;

  const clientId = commercialHealth?.paypal_client_id;
  if (!clientId) {
    throw new Error('El backend aún no proporciona el Client ID público de PayPal. Despliega primero la actualización del backend.');
  }

  const params = new URLSearchParams({
    'client-id': clientId,
    currency: 'EUR',
    intent: 'capture',
    components: 'buttons,card-fields'
  });

  paypalSdkPromise = new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = `https://www.paypal.com/sdk/js?${params.toString()}`;
    script.async = true;
    script.dataset.obsidianPaypalSdk = 'true';
    script.onload = () => {
      if (window.paypal?.Buttons && window.paypal?.CardFields) resolve();
      else reject(new Error('PayPal no ha cargado los componentes de checkout esperados.'));
    };
    script.onerror = () => reject(new Error('No se pudo cargar el SDK de PayPal.'));
    document.head.appendChild(script);
  }).catch((error) => {
    paypalSdkPromise = null;
    throw error;
  });

  return paypalSdkPromise;
}

async function createInlinePayPalOrder(paymentMethod) {
  if (!activeOrder?.order_id || activeOrder.verified !== true) {
    throw new Error('Verifica el dominio antes de iniciar el pago.');
  }
  if (commercialHealth?.payment_enabled !== true) {
    throw new Error('El checkout no está habilitado en el backend.');
  }

  if (
    activePaypalOrderId
    && activePaypalOrderFor === activeOrder.order_id
    && activePaypalOrderMethod === paymentMethod
  ) {
    return activePaypalOrderId;
  }

  const checkout = await postJson('/api/checkout', {
    order_id: activeOrder.order_id,
    payment_method: paymentMethod
  });
  const paymentId = checkout.payment_id || checkout.session_id;
  if (!paymentId) throw new Error('PayPal no devolvió un identificador de orden.');

  activePaypalOrderId = paymentId;
  activePaypalOrderFor = activeOrder.order_id;
  activePaypalOrderMethod = paymentMethod;
  localStorage.setItem(`oc-order-for:${paymentId}`, activeOrder.order_id);
  return paymentId;
}

async function handleInlinePayPalApproval(data) {
  const paymentId = data?.orderID;
  if (!paymentId) {
    inlinePaymentMessage.textContent = 'PayPal no devolvió la referencia del pago. No vuelvas a pagar; revisa el estado del pedido.';
    return;
  }

  const orderId = activeOrder?.order_id || localStorage.getItem(`oc-order-for:${paymentId}`);
  if (!orderId) {
    inlinePaymentMessage.textContent = 'No se ha podido asociar el pago con el pedido. No vuelvas a pagar; contacta con soporte.';
    return;
  }

  localStorage.setItem(`oc-order-for:${paymentId}`, orderId);

  const returnUrl = new URL(window.location.href);
  returnUrl.searchParams.set('paypal_return', '1');
  returnUrl.searchParams.set('token', paymentId);
  returnUrl.hash = 'workspace';
  window.history.replaceState(
    {},
    document.title,
    `${returnUrl.pathname}${returnUrl.search}${returnUrl.hash}`
  );

  inlinePaymentMessage.textContent = 'Confirmando el cobro con el servidor. No cierres esta página ni vuelvas a pagar.';
  if (cardPayButton) cardPayButton.disabled = true;
  if (paypalButtonContainer) paypalButtonContainer.style.pointerEvents = 'none';

  await resumePaidReport();
}

async function mountInlinePayPalCheckout() {
  inlinePayPalPanel.hidden = false;
  if (paypalInlineMounted) return;

  await loadPayPalSdk();

  const buttons = window.paypal.Buttons({
    createOrder: () => createInlinePayPalOrder('paypal'),
    onApprove: handleInlinePayPalApproval,
    onCancel: () => {
      activePaypalOrderId = null;
      activePaypalOrderFor = null;
      activePaypalOrderMethod = null;
      inlinePaymentMessage.textContent = 'Pago cancelado. No se ha confirmado ningún cobro; puedes volver a intentarlo.';
    },
    onError: () => {
      inlinePaymentMessage.textContent = 'PayPal no ha podido continuar. No se ha confirmado el pago; vuelve a intentarlo o contacta con soporte.';
    },
    style: {
      layout: 'vertical',
      shape: 'rect',
      color: 'gold',
      label: 'paypal'
    }
  });

  if (!buttons.isEligible()) {
    throw new Error('El botón PayPal no está disponible para esta configuración.');
  }
  await buttons.render('#paypalButtonContainer');

  const cardFieldStyle = {
    input: {
      'font-size': '16px',
      'font-family': 'Arial, sans-serif',
      color: '#17252a'
    },
    '.invalid': { color: '#b42318' }
  };

  activeCardFields = window.paypal.CardFields({
    createOrder: () => createInlinePayPalOrder('card'),
    onApprove: handleInlinePayPalApproval,
    onError: () => {
      activePaypalOrderId = null;
      activePaypalOrderFor = null;
      activePaypalOrderMethod = null;
      if (cardPayButton) cardPayButton.disabled = false;
      inlinePaymentMessage.textContent = 'No se ha confirmado el pago con tarjeta. Comprueba los datos e inténtalo de nuevo.';
    },
    style: cardFieldStyle
  });

  if (activeCardFields.isEligible()) {
    cardFieldsPanel.hidden = false;
    await Promise.all([
      activeCardFields.NameField({ style: cardFieldStyle }).render('#card-name-field-container'),
      activeCardFields.NumberField({ style: cardFieldStyle }).render('#card-number-field-container'),
      activeCardFields.ExpiryField({ style: cardFieldStyle }).render('#card-expiry-field-container'),
      activeCardFields.CVVField({ style: cardFieldStyle }).render('#card-cvv-field-container')
    ]);
    inlinePaymentMessage.textContent = 'Elige PayPal o introduce tu tarjeta en los campos seguros. El informe solo se entrega tras confirmar el cobro.';
  } else {
    cardFieldsPanel.hidden = true;
    inlinePaymentMessage.textContent = 'Los campos de tarjeta integrada no están habilitados para esta cuenta. Puedes utilizar el botón oficial de PayPal.';
  }

  paypalInlineMounted = true;
}

cardPayButton?.addEventListener('click', async () => {
  if (!activeCardFields || !activeOrder?.verified) return;
  cardPayButton.disabled = true;
  inlinePaymentMessage.textContent = 'Procesando el pago con tarjeta de forma segura…';
  try {
    await activeCardFields.submit();
  } catch (error) {
    activePaypalOrderId = null;
    activePaypalOrderFor = null;
    activePaypalOrderMethod = null;
    cardPayButton.disabled = false;
    inlinePaymentMessage.textContent = 'No se pudo procesar la tarjeta. No vuelvas a pagar si no sabes el estado de la transacción; revisa el pedido antes de reintentarlo.';
    setOrderMessage(inlinePaymentMessage.textContent, 'error');
  }
});

payButton?.addEventListener('click', async () => {
  if (!activeOrder?.order_id || !activeOrder.verified) return;
  if (commercialHealth?.payment_enabled !== true) {
    setOrderMessage('El checkout no está disponible en este momento.', 'error');
    return;
  }

  payButton.disabled = true;
  payButton.textContent = 'Cargando opciones de pago…';
  inlinePayPalPanel.hidden = false;

  try {
    await mountInlinePayPalCheckout();
    payButton.hidden = true;
  } catch (error) {
    payButton.disabled = false;
    payButton.textContent = 'Reintentar opciones de pago ↗';
    inlinePayPalPanel.hidden = false;
    inlinePaymentMessage.textContent = error.message || 'No se pudieron mostrar las opciones de pago.';
    setOrderMessage(inlinePaymentMessage.textContent, 'error');
  }
});

function addPdfDownloadButton(sessionId, accessToken, report) {
  reportEl.querySelector('.pdf-download-actions')?.remove();
  const panel = el('div', 'report-notice pdf-download-actions');
  panel.append(el('strong', '', 'Informe comercial disponible'), el('p', '', 'El pago está confirmado por PayPal. Descarga una copia PDF del informe.'));
  const button = el('button', 'button primary', 'Descargar informe PDF ↗');
  button.type = 'button';
  const status = el('p', 'subtle-note', 'El servidor volverá a confirmar el pago antes de entregar el PDF.');
  button.addEventListener('click', async () => {
    button.disabled = true;
    button.textContent = 'Preparando PDF…';
    status.textContent = 'Verificando el pago y generando el PDF…';
    try {
      const response = await fetch(`/api/paid-report-pdf?payment_id=${encodeURIComponent(sessionId)}`, {
        headers: { 'X-Obsidian-Report-Token': accessToken },
        cache: 'no-store'
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.error || `No se autorizó la descarga (HTTP ${response.status}).`);
      }
      const blob = await response.blob();
      if (blob.type && !blob.type.toLowerCase().includes('application/pdf')) {
        throw new Error('El servidor no devolvió un PDF válido.');
      }
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      const safeDomain = String(report?.domain || 'exposure-brief').toLowerCase().replace(/[^a-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '') || 'exposure-brief';
      link.href = url;
      link.download = `obsidiancyber-${safeDomain}.pdf`;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1500);
      status.textContent = 'PDF preparado. Si no aparece, revisa las descargas del navegador.';
    } catch (error) {
      status.textContent = error.message || 'No se pudo descargar el PDF.';
    } finally {
      button.disabled = false;
      button.textContent = 'Descargar informe PDF ↗';
    }
  });
  panel.append(button, status);
  reportEl.append(panel);
}

async function resumePaidReport() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('paypal_cancelled') === '1') {
    window.history.replaceState({}, document.title, `${window.location.pathname}#workspace`);
    setOrderMessage('Pago cancelado. No se ha confirmado ningún cobro; puedes volver a intentarlo cuando quieras.', 'info');
    return;
  }
  const paymentId = params.get('token') || params.get('payment_id');
  if (!paymentId || (params.get('paypal_return') !== '1' && !params.has('token'))) return;
  const orderId = localStorage.getItem(`oc-order-for:${paymentId}`);
  const accessToken = orderId ? localStorage.getItem(`oc-report-token:${orderId}`) : null;
  if (!accessToken) {
    setOrderMessage('No se encontró el token privado del pedido en este navegador. No vuelvas a pagar; contacta con soporte indicando la referencia del pedido.', 'error');
    return;
  }
  setOrderMessage('Confirmando el pago con PayPal…', 'info');
  try {
    const captureResponse = await fetch('/api/paypal/capture', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Obsidian-Report-Token': accessToken
      },
      body: JSON.stringify({ payment_id: paymentId }),
      cache: 'no-store'
    });
    const capturePayload = await captureResponse.json().catch(() => ({}));
    if (captureResponse.status === 202) {
      setOrderMessage(capturePayload.message || 'PayPal aún está procesando el pago. No vuelvas a pagar; espera un momento y recarga esta página.', 'info');
      return;
    }
    if (!captureResponse.ok) throw new Error(capturePayload.error || `PayPal respondió con HTTP ${captureResponse.status}.`);
  } catch (error) {
    setOrderMessage(error.message || 'No se pudo confirmar el pago con PayPal. No vuelvas a pagar; conserva la referencia del pedido y contacta con soporte.', 'error');
    return;
  }
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      const response = await fetch(`/api/paid-report?payment_id=${encodeURIComponent(paymentId)}`, {
        headers: { 'X-Obsidian-Report-Token': accessToken },
        cache: 'no-store'
      });
      const payload = await response.json().catch(() => ({}));
      if (response.status === 202) {
        setOrderMessage('PayPal confirma el proceso, preparando el informe…', 'info');
        await new Promise((resolve) => setTimeout(resolve, 1500));
        continue;
      }
      if (!response.ok) throw new Error(payload.error || `Respuesta del servidor: HTTP ${response.status}`);
      if (payload.status !== 'ready' || !payload.report) throw new Error('El pago se ha confirmado, pero el informe aún no está disponible. Conserva la referencia del pedido y contacta con soporte.');
      window.history.replaceState({}, document.title, `${window.location.pathname}#workspace`);
      setOrderMessage('Pago confirmado por PayPal. Informe generado correctamente.', 'success');
      renderReport(payload.report);
      addPdfDownloadButton(paymentId, accessToken, payload.report);
      return;
    } catch (error) {
      setOrderMessage(error.message || 'No se pudo recuperar el informe pagado.', 'error');
      return;
    }
  }
  setOrderMessage('PayPal ha recibido el pago, pero el informe aún se está preparando. No vuelvas a pagar; vuelve a consultar en unos instantes.', 'info');
}

async function init() {
  await loadCommercialStatus();
  try {
    const stored = sessionStorage.getItem('oc-pending-order');
    if (stored) showVerification(JSON.parse(stored));
  } catch { /* Ignore malformed local session state. */ }
  await resumePaidReport();
}
void init();


// OC_SALES_CHAT_CLIENT_V1
(() => {
  const toggle = document.querySelector('#ocSalesChatToggle');
  const panel = document.querySelector('#ocSalesChatPanel');
  const close = document.querySelector('#ocSalesChatClose');
  const form = document.querySelector('#ocSalesChatForm');
  const input = document.querySelector('#ocSalesChatInput');
  const send = document.querySelector('#ocSalesChatSend');
  const area = document.querySelector('#ocSalesChatMessages');
  const orderLink = document.querySelector('#ocSalesOrderLink');
  if (!toggle || !panel || !form || !input || !send || !area) return;

  const greeting = 'Hola, bienvenido a ObsidianCyber. ¿Gestionas webs de clientes o quieres conocer la exposición pública de tu propio dominio?';
  let history = [{ role: 'assistant', content: greeting }];

  function setOpen(open) {
    panel.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    if (open) input.focus();
  }
  function bubble(role, text, pending = false) {
    const node = document.createElement('div');
    node.className = `oc-sales-bubble ${role}` + (pending ? ' pending' : '');
    node.textContent = text;
    area.appendChild(node);
    area.scrollTop = area.scrollHeight;
    return node;
  }
  toggle.addEventListener('click', () => setOpen(panel.hidden));
  close?.addEventListener('click', () => setOpen(false));
  orderLink?.addEventListener('click', () => setOpen(false));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text || send.disabled) return;
    history.push({ role: 'user', content: text });
    bubble('user', text);
    input.value = '';
    send.disabled = true;
    input.disabled = true;
    const pending = bubble('assistant', 'Estoy preparando una respuesta…', true);

    try {
      const response = await fetch('/api/sales-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: history.slice(-8) }),
        cache: 'no-store'
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'No se pudo responder.');
      const reply = String(data.reply || '').slice(0, 3000);
      if (!reply) throw new Error('El asistente no devolvió una respuesta.');
      pending.classList.remove('pending');
      pending.textContent = reply;
      history.push({ role: 'assistant', content: reply });
      history = history.slice(-8);
    } catch (error) {
      pending.classList.remove('pending');
      pending.textContent = error.message || 'No se pudo conectar con el asistente.';
    } finally {
      send.disabled = false;
      input.disabled = false;
      input.focus();
      area.scrollTop = area.scrollHeight;
    }
  });
})();
// END OC_SALES_CHAT_CLIENT_V1


// Formulario de leads con consentimiento (RGPD): solo se envía si la casilla está marcada.
(() => {
  const form = document.querySelector('#leadForm');
  if (!form) return;
  const box = document.querySelector('#leadMessageBox');
  const submit = document.querySelector('#leadSubmit');
  const show = (text, type) => { box.hidden = false; box.className = `form-message ${type}`; box.textContent = text; };
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = document.querySelector('#leadEmail').value.trim();
    if (!email || !document.querySelector('#leadConsent').checked) {
      show('Escribe tu correo y marca la casilla de consentimiento para que podamos contactarte.', 'error');
      return;
    }
    submit.disabled = true;
    try {
      await postJson('/api/leads', {
        email,
        name: document.querySelector('#leadName').value,
        company: document.querySelector('#leadCompany').value,
        message: document.querySelector('#leadMessage').value,
        company_website_hp: document.querySelector('#leadHp').value,
        consent: true,
        source: 'web'
      });
      form.reset();
      show('Recibido. Te escribiremos a ese correo lo antes posible.', 'success');
    } catch (error) {
      show(error.message || 'No se pudo enviar. Escríbenos a obsidiancyber@hotmail.com.', 'error');
    } finally {
      submit.disabled = false;
    }
  });
})();
