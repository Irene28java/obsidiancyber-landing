'use strict';

const menu = document.querySelector('.menu');
const nav = document.querySelector('nav');
const orderForm = document.querySelector('#orderForm');
const orderDomain = document.querySelector('#orderDomain');
const orderEmail = document.querySelector('#orderEmail');
const orderAuth = document.querySelector('#orderAuth');
const externalIntelConsent = document.querySelector('#externalIntelConsent');
const termsConsent = document.querySelector('#termsConsent');
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
  activeOrder = order;
  verificationPanel.hidden = false;
  txtNameEl.textContent = order.txt_name;
  txtValueEl.textContent = order.txt_value;
  verifyDomainButton.disabled = false;
  payButton.disabled = !order.verified;
  verificationMessage.textContent = order.verified ? 'Dominio verificado. Ya puedes continuar al pago seguro.' : 'Publica el TXT anterior; después vuelve a comprobarlo. No se cobra hasta completar este paso.';
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
    const health = await response.json();
    const dnsReady = health.dns_txt_verification_ready === true;
    const paymentReady = health.payment_enabled === true;
    createOrderButton.disabled = !dnsReady;
    checkoutStatus.className = `checkout-status ${paymentReady ? 'ready' : 'not-ready'}`;
    checkoutStatus.textContent = paymentReady
      ? 'Pagos configurados: primero verifica el dominio por DNS y después podrás continuar a Stripe.'
      : dnsReady
        ? 'Verificación DNS disponible. Los pagos siguen desactivados; no se realizará ningún cobro.'
        : 'Verificación DNS no disponible. Los pagos siguen desactivados; revisa la configuración antes de continuar.';
    if (paymentReady) setOrderMessage('Prepara la solicitud y verifica el control DNS antes de pasar a Stripe.', 'success');
    else if (dnsReady) setOrderMessage('Puedes preparar una solicitud y verificar el dominio. No se cobrará nada mientras los pagos sigan desactivados.', 'info');
    else setOrderMessage('La verificación DNS aún no está disponible. No se crea ni cobra ningún pedido.', 'info');
    const price = `${(Number(health.pilot_price_cents || 7900) / 100).toLocaleString('es-ES', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} €`;
    payButton.textContent = `Continuar al pago seguro · ${price} ↗`;
    document.querySelectorAll('.pilot-price').forEach((node) => { node.textContent = price; });
  } catch {
    createOrderButton.disabled = true;
    checkoutStatus.className = 'checkout-status not-ready';
    checkoutStatus.textContent = 'No se pudo confirmar el estado del backend. El checkout permanece deshabilitado.';
    setOrderMessage('No se pudo contactar con la API de salud. No se crea ni cobra ningún pedido.', 'error');
  }
}

orderForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (createOrderButton.disabled) return;
  if (!orderAuth.checked || !termsConsent.checked) {
    setOrderMessage('Confirma la autorización del activo y el alcance del piloto para continuar.', 'error');
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
      terms_acknowledged: true
    });
    order.verified = false;
    localStorage.setItem(`oc-report-token:${order.order_id}`, order.report_access_token);
    sessionStorage.setItem('oc-pending-order', JSON.stringify(order));
    showVerification(order);
    setOrderMessage(`Solicitud ${order.order_id} creada. Aún no se ha cobrado nada. Publica el TXT y verifica el dominio.`, 'success');
    verificationPanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (error) {
    setOrderMessage(error.message || 'No se pudo crear la solicitud.', 'error');
  } finally {
    createOrderButton.textContent = 'Preparar verificación ↗';
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

payButton?.addEventListener('click', async () => {
  if (!activeOrder?.order_id || !activeOrder.verified) return;
  payButton.disabled = true;
  payButton.textContent = 'Preparando Checkout…';
  try {
    const checkout = await postJson('/api/checkout', { order_id: activeOrder.order_id });
    localStorage.setItem(`oc-order-for:${checkout.session_id}`, activeOrder.order_id);
    window.location.assign(checkout.checkout_url);
  } catch (error) {
    payButton.disabled = false;
    setOrderMessage(error.message || 'No se pudo iniciar el pago.', 'error');
    await loadCommercialStatus();
  }
});

function addPdfDownloadButton(sessionId, accessToken, report) {
  reportEl.querySelector('.pdf-download-actions')?.remove();
  const panel = el('div', 'report-notice pdf-download-actions');
  panel.append(el('strong', '', 'Informe comercial disponible'), el('p', '', 'El pago está confirmado por Stripe. Descarga una copia PDF del informe.'));
  const button = el('button', 'button primary', 'Descargar informe PDF ↗');
  button.type = 'button';
  const status = el('p', 'subtle-note', 'El servidor volverá a confirmar el pago antes de entregar el PDF.');
  button.addEventListener('click', async () => {
    button.disabled = true;
    button.textContent = 'Preparando PDF…';
    status.textContent = 'Verificando el pago y generando el PDF…';
    try {
      const response = await fetch(`/api/paid-report-pdf?session_id=${encodeURIComponent(sessionId)}`, {
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
  const sessionId = params.get('checkout_session_id');
  if (!sessionId) return;
  const orderId = localStorage.getItem(`oc-order-for:${sessionId}`);
  const accessToken = orderId ? localStorage.getItem(`oc-report-token:${orderId}`) : null;
  window.history.replaceState({}, document.title, `${window.location.pathname}#workspace`);
  if (!accessToken) {
    setOrderMessage('No encontramos el token de acceso del pedido en este navegador. No repitas el pago; contacta con soporte y conserva la referencia de Stripe.', 'error');
    return;
  }
  setOrderMessage('Verificando el pago con Stripe y preparando el informe…', 'info');
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      const response = await fetch(`/api/paid-report?session_id=${encodeURIComponent(sessionId)}`, {
        headers: { 'X-Obsidian-Report-Token': accessToken },
        cache: 'no-store'
      });
      const payload = await response.json().catch(() => ({}));
      if (response.status === 202) {
        setOrderMessage('Stripe todavía no confirma el pago. Comprobando de nuevo…', 'info');
        await new Promise((resolve) => setTimeout(resolve, 1500));
        continue;
      }
      if (!response.ok) throw new Error(payload.error || `Respuesta del servidor: HTTP ${response.status}`);
      if (payload.status !== 'ready' || !payload.report) throw new Error('El pago se recibió, pero el informe no está disponible todavía. Conserva la referencia del pedido y contacta con soporte.');
      setOrderMessage('Pago confirmado. Ficha de exposición generada correctamente.', 'success');
      renderReport(payload.report);
      addPdfDownloadButton(sessionId, accessToken, payload.report);
      return;
    } catch (error) {
      setOrderMessage(error.message || 'No se pudo recuperar el informe pagado.', 'error');
      return;
    }
  }
  setOrderMessage('Stripe aún no ha confirmado el pago. No vuelvas a pagar; recarga esta página en unos instantes o contacta con soporte.', 'info');
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
