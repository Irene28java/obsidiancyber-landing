import json
import os
import tempfile
from pathlib import Path
import threading
import unittest
from io import BytesIO
from unittest import mock
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server


class DomainValidationTests(unittest.TestCase):
    def test_accepts_common_domain(self):
        self.assertEqual(server.validate_domain('Example.COM'), 'example.com')

    def test_accepts_valid_domain_starting_http(self):
        self.assertEqual(server.validate_domain('httpbin.org'), 'httpbin.org')

    def test_private_resolution_is_blocked(self):
        original = server.socket.getaddrinfo
        server.socket.getaddrinfo = lambda *args, **kwargs: [(server.socket.AF_INET, server.socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]
        try:
            with self.assertRaisesRegex(ValueError, 'no global'):
                server._public_resolutions('example.com')
        finally:
            server.socket.getaddrinfo = original

    def test_converts_idn(self):
        self.assertEqual(server.validate_domain('mañana.example'), 'xn--maana-pta.example')

    def test_rejects_url_syntax(self):
        for value in ('https://example.com', 'example.com/path', 'name:pass@example.com'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                server.validate_domain(value)

    def test_rejects_literal_ip_and_local_names(self):
        for value in ('8.8.8.8', '127.0.0.1', 'localhost', 'host.internal', 'host.test'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                server.validate_domain(value)


class ScoringTests(unittest.TestCase):
    def test_unresolved_domain_has_no_score(self):
        self.assertEqual(server.score_findings({'status': 'not_checked'}, False), (None, []))

    def test_inconclusive_tls_has_no_score(self):
        self.assertEqual(server.score_findings({'status': 'error'}, True), (None, []))

    def test_valid_certificate_and_no_signals_scores_zero(self):
        score, findings = server.score_findings({'status': 'valid', 'days_remaining': 100}, True)
        self.assertEqual(score, 0)
        self.assertEqual(findings, [])

    def test_expiring_certificate_is_explained(self):
        score, findings = server.score_findings({'status': 'valid', 'days_remaining': 5}, True)
        self.assertEqual(score, 20)
        self.assertEqual(findings[0]['id'], 'tls-expiry-7d')
        self.assertIn('renovación', findings[0]['recommendation'].lower())

    def test_verification_failure_is_scored(self):
        score, findings = server.score_findings({'status': 'verification_failed', 'message': 'hostname mismatch'}, True)
        self.assertEqual(score, 35)
        self.assertEqual(findings[0]['id'], 'tls-verification')


class PerIpAnalysisTests(unittest.TestCase):
    def test_score_is_attached_to_ip_with_observed_tls_signal(self):
        ips = ['8.8.8.8', '1.1.1.1']
        def tls_for_ip(domain, ip):
            if ip == '8.8.8.8':
                return {'status': 'valid', 'days_remaining': 5, 'message': 'test expiry'}
            return {'status': 'valid', 'days_remaining': 100, 'message': 'test ok'}
        with mock.patch.object(server, '_public_resolutions', return_value=ips), \
             mock.patch.object(server, '_geo_context', return_value={'status': 'not_configured', 'message': 'test'}), \
             mock.patch.object(server, '_tls_check', side_effect=tls_for_ip):
            result = server.analyze_domain('example.com')
        self.assertEqual(result['score'], 20)
        self.assertEqual(result['addresses'][0]['score'], 20)
        self.assertEqual(result['addresses'][1]['score'], 0)
        self.assertEqual(result['findings'][0]['ip'], '8.8.8.8')
        self.assertEqual(result['tls_checks_performed'], 2)

    def test_tls_checks_are_bounded_and_unchecked_ips_are_unscored(self):
        ips = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222', '8.8.4.4', '1.0.0.1']
        with mock.patch.object(server, '_public_resolutions', return_value=ips), \
             mock.patch.object(server, '_geo_context', return_value={'status': 'not_configured', 'message': 'test'}), \
             mock.patch.object(server, '_tls_check', return_value={'status': 'valid', 'days_remaining': 100, 'message': 'test ok'}) as tls_mock:
            result = server.analyze_domain('example.com')
        self.assertEqual(tls_mock.call_count, server.MAX_TLS_IP_CHECKS)
        self.assertEqual(result['tls_checks_performed'], server.MAX_TLS_IP_CHECKS)
        self.assertIsNone(result['addresses'][4]['score'])
        self.assertEqual(result['addresses'][4]['tls']['status'], 'not_checked')
        self.assertIsNone(result['addresses'][5]['score'])


class ApiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.LIMITER = server.RateLimiter(100, 60)
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.httpd.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def _post_webhook(self, event, with_signature=True):
        headers = {"Content-Type": "application/json"}
        if with_signature:
            headers.update({
                "PayPal-Auth-Algo": "SHA256withRSA",
                "PayPal-Cert-Url": (
                    "https://api-m.sandbox.paypal.com/"
                    "v1/notifications/certs/test"
                ),
                "PayPal-Transmission-Id": "test-transmission-id",
                "PayPal-Transmission-Sig": "test-signature",
                "PayPal-Transmission-Time": "2026-10-16T00:00:00Z",
            })

        request = Request(
            self.base + "/api/paypal/webhook",
            data=json.dumps(event).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.loads(
                    response.read().decode("utf-8")
                )
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {"raw": body}
            return exc.code, payload

    def test_webhook_rejects_missing_signature_headers(self):
        with mock.patch.object(
            server, "PAYPAL_WEBHOOK_ID", "WH-LOCAL-TEST"
        ), mock.patch.object(server, "_paypal_api") as paypal_mock:
            status, payload = self._post_webhook(
                {"event_type": "CHECKOUT.ORDER.APPROVED"},
                with_signature=False,
            )

        self.assertEqual(status, 400)
        self.assertIn("encabezados", payload["error"])
        paypal_mock.assert_not_called()

    def test_webhook_rejects_invalid_signature(self):
        with mock.patch.object(
            server, "PAYPAL_WEBHOOK_ID", "WH-LOCAL-TEST"
        ), mock.patch.object(
            server,
            "_paypal_api",
            return_value={"verification_status": "FAILURE"},
        ) as paypal_mock:
            status, payload = self._post_webhook(
                {"event_type": "CHECKOUT.ORDER.APPROVED"}
            )

        self.assertEqual(status, 400)
        self.assertIn("Firma", payload["error"])
        self.assertEqual(
            paypal_mock.call_args[0][1],
            "/v1/notifications/verify-webhook-signature",
        )

    def test_webhook_returns_503_if_verification_is_unavailable(self):
        with mock.patch.object(
            server, "PAYPAL_WEBHOOK_ID", "WH-LOCAL-TEST"
        ), mock.patch.object(
            server, "_paypal_api", side_effect=RuntimeError("test failure")
        ):
            status, payload = self._post_webhook(
                {"event_type": "CHECKOUT.ORDER.APPROVED"}
            )

        self.assertEqual(status, 503)
        self.assertIn("verificar", payload["error"])

    def test_webhook_acknowledges_verified_non_payment_event(self):
        event = {
            "id": "WH-EVENT-LOCAL",
            "event_type": "CHECKOUT.ORDER.APPROVED",
            "resource": {"id": "ORDER-LOCAL"},
        }
        with mock.patch.object(
            server, "PAYPAL_WEBHOOK_ID", "WH-LOCAL-TEST"
        ), mock.patch.object(
            server,
            "_paypal_api",
            return_value={"verification_status": "SUCCESS"},
        ) as paypal_mock:
            status, payload = self._post_webhook(event)

        self.assertEqual(status, 200)
        self.assertTrue(payload["received"])
        verification_payload = paypal_mock.call_args[0][2]
        self.assertEqual(
            verification_payload["webhook_id"], "WH-LOCAL-TEST"
        )
        self.assertEqual(verification_payload["webhook_event"], event)

    def test_webhook_checks_completed_payment_and_closes_db(self):
        payment_id = "5O190127TN364715T"
        event = {
            "id": "WH-CAPTURE-LOCAL",
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {
                "supplementary_data": {
                    "related_ids": {"order_id": payment_id}
                }
            },
        }
        order_row = {
            "order_id": "OC-ORDER-LOCAL",
            "paypal_order_id": payment_id,
            "status": "payment_pending",
            "price_cents": 7900,
        }
        select_conn = mock.Mock()
        select_conn.execute.return_value.fetchone.return_value = order_row
        update_conn = mock.Mock()

        with mock.patch.object(
            server, "PAYPAL_WEBHOOK_ID", "WH-LOCAL-TEST"
        ), mock.patch.object(
            server,
            "_paypal_api",
            side_effect=[
                {"verification_status": "SUCCESS"},
                {"status": "COMPLETED"},
            ],
        ) as paypal_mock, mock.patch.object(
            server, "_db_connect",
            side_effect=[select_conn, update_conn],
        ), mock.patch.object(
            server, "_paypal_order_paid", return_value=True
        ) as paid_mock:
            status, payload = self._post_webhook(event)

        self.assertEqual(status, 200)
        self.assertTrue(payload["received"])
        select_conn.close.assert_called_once()
        update_conn.execute.assert_called_once()
        update_conn.commit.assert_called_once()
        update_conn.close.assert_called_once()
        paid_mock.assert_called_once()
        self.assertEqual(paypal_mock.call_count, 2)


    def test_health(self):
        with urlopen(f'{self.base}/api/health', timeout=3) as response:
            data = json.loads(response.read().decode())
            self.assertEqual(response.status, 200)
            self.assertEqual(data['product'], 'ObsidianCyber')
            self.assertTrue(data['persistence'])

    def test_static_landing_served(self):
        with urlopen(self.base + '/', timeout=3) as response:
            page = response.read().decode('utf-8')
            self.assertIn('CENTRO DE ANÁLISIS / 03', page)
            script = urlopen(self.base + '/script.js', timeout=3).read().decode('utf-8')
            self.assertIn('/api/orders', script)
            sample = urlopen(self.base + '/sample-report.html', timeout=3).read().decode('utf-8')
            self.assertIn('TODOS LOS RESULTADOS SON FICTICIOS', sample)
            terms = urlopen(self.base + '/terms.html', timeout=3).read().decode('utf-8')
            privacy = urlopen(self.base + '/privacy.html', timeout=3).read().decode('utf-8')
            for doc in (terms, privacy):
                self.assertNotIn('BORRADOR', doc)
                self.assertNotIn('COMPLETAR', doc)
                self.assertNotIn('[NOMBRE LEGAL', doc)
            self.assertIn('Irene Vaquerizo', terms)
            self.assertIn('79,00 € por dominio, IVA incluido', terms)

    def test_private_project_files_are_not_served(self):
        for path in ('/server.py', '/.env.example', '/README.md', '/tests/test_server.py'):
            with self.subTest(path=path), self.assertRaises(HTTPError) as ctx:
                urlopen(self.base + path, timeout=3)
            self.assertEqual(ctx.exception.code, 404)

    def test_requires_scope_acknowledgement(self):
        request = Request(self.base + '/api/analyze', data=json.dumps({'domain': 'example.com'}).encode(), headers={'Content-Type': 'application/json'}, method='POST')
        previous_free = server.FREE_ANALYSIS_ENABLED
        server.FREE_ANALYSIS_ENABLED = True
        try:
            with self.assertRaises(HTTPError) as ctx:
                urlopen(request, timeout=3)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            server.FREE_ANALYSIS_ENABLED = previous_free


    def test_authorized_request_returns_report_shape_without_external_scan(self):
        fake_result = {
            'case_id': 'OC-20261010-ABC123', 'generated_at': '2026-10-10T12:00:00Z', 'domain': 'example.com',
            'score': 0, 'addresses': [], 'dns': {'status': 'ok', 'message': 'test'},
            'tls': {'status': 'valid', 'message': 'test'}, 'findings': [], 'modules': [],
            'storage': 'not_persisted'
        }
        previous = server.analyze_domain
        previous_free = server.FREE_ANALYSIS_ENABLED
        server.FREE_ANALYSIS_ENABLED = True
        server.analyze_domain = lambda domain, external_intel_consent=False: fake_result
        try:
            payload = {'domain': 'example.com', 'authorized': True, 'scope_acknowledged': True}
            request = Request(self.base + '/api/analyze', data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method='POST')
            with urlopen(request, timeout=3) as response:
                self.assertEqual(response.status, 200)
                data = json.loads(response.read().decode('utf-8'))
                self.assertEqual(data['case_id'], fake_result['case_id'])
                self.assertEqual(data['domain'], 'example.com')
        finally:
            server.analyze_domain = previous
            server.FREE_ANALYSIS_ENABLED = previous_free

    def test_invalid_domain_rejected_before_network_checks(self):
        payload = {'domain': 'https://example.com', 'authorized': True, 'scope_acknowledged': True}
        request = Request(self.base + '/api/analyze', data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method='POST')
        previous_free = server.FREE_ANALYSIS_ENABLED
        server.FREE_ANALYSIS_ENABLED = True
        try:
            with self.assertRaises(HTTPError) as ctx:
                urlopen(request, timeout=3)
            self.assertEqual(ctx.exception.code, 422)
            self.assertIn('solo el dominio', ctx.exception.read().decode('utf-8'))
        finally:
            server.FREE_ANALYSIS_ENABLED = previous_free


    def test_order_allows_purchase_without_optional_external_reputation_consent(self):
        payload = {
            'domain': 'example.com', 'email': 'buyer@example.com',
            'authorized': True, 'terms_acknowledged': True,
            'immediate_delivery_consent': True,
            'external_intel_consent': False
        }
        request = Request(self.base + '/api/orders', data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method='POST')
        old_db = server.DB_PATH
        with tempfile.TemporaryDirectory() as temp_dir:
            server.DB_PATH = Path(temp_dir) / 'orders.sqlite3'
            with mock.patch.object(server, '_commercial_checkout_ready', return_value=True), \
                 mock.patch.object(server, '_create_order', return_value={'order_id': 'OC-ORD-0123456789ABCDEF', 'external_intel_consent': False}) as create_order:
                try:
                    with urlopen(request, timeout=3) as response:
                        result = json.loads(response.read().decode())
                        self.assertEqual(response.status, 201)
                        self.assertFalse(result['external_intel_consent'])
                    create_order.assert_called_once()
                    args, kwargs = create_order.call_args
                    self.assertEqual(args, ('example.com', 'buyer@example.com', False))
                    self.assertTrue(kwargs.get('authorization_acknowledged_at'))
                    self.assertEqual(
                        kwargs.get('terms_acknowledged_at'),
                        kwargs.get('authorization_acknowledged_at'),
                    )
                    self.assertEqual(kwargs.get('terms_version'), 'pilot-v2-2026-10')
                    self.assertEqual(
                        kwargs.get('immediate_delivery_acknowledged_at'),
                        kwargs.get('authorization_acknowledged_at'),
                    )
                finally:
                    server.DB_PATH = old_db

    def test_order_rejected_without_immediate_delivery_consent(self):
        payload = {
            'domain': 'example.com', 'email': 'buyer@example.com',
            'authorized': True, 'terms_acknowledged': True,
            'external_intel_consent': False
        }
        request = Request(self.base + '/api/orders', data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method='POST')
        with mock.patch.object(server, '_commercial_checkout_ready', return_value=True), \
             mock.patch.object(server, '_create_order') as create_order:
            with self.assertRaises(HTTPError) as ctx:
                urlopen(request, timeout=3)
            self.assertEqual(ctx.exception.code, 403)
            create_order.assert_not_called()

    def test_default_price_is_79_vat_included(self):
        self.assertEqual(server.PILOT_PRICE_CENTS, 7900)
        self.assertEqual(server.PILOT_BASE_PRICE_CENTS, 6529)
        self.assertEqual(server._price_text(), '79,00 € (IVA incluido)')


class IntelligenceTests(unittest.TestCase):
    def test_abuseipdb_not_configured_makes_no_external_request(self):
        with mock.patch.dict(os.environ, {"OBSIDIAN_ABUSEIPDB_API_KEY": ""}, clear=False), \
             mock.patch.object(server, "urlopen") as urlopen_mock:
            result = server._abuseipdb_check("8.8.8.8", consented=True)
        self.assertEqual(result["status"], "not_configured")
        urlopen_mock.assert_not_called()

    def test_abuseipdb_requires_consent_before_querying_provider(self):
        with mock.patch.dict(os.environ, {"OBSIDIAN_ABUSEIPDB_API_KEY": "test-key"}, clear=False), \
             mock.patch.object(server, "urlopen") as urlopen_mock:
            result = server._abuseipdb_check("8.8.8.8", consented=False)
        self.assertEqual(result["status"], "not_consented")
        urlopen_mock.assert_not_called()

    def test_abuseipdb_parses_reputation_as_separate_context(self):
        payload = {"data": {
            "abuseConfidenceScore": 82, "totalReports": 12, "numDistinctUsers": 7,
            "lastReportedAt": "2026-10-01T10:00:00+00:00", "usageType": "Content Delivery Network",
            "isp": "Example CDN", "domain": "cdn.example", "countryCode": "ES"
        }}
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
        with mock.patch.dict(os.environ, {"OBSIDIAN_ABUSEIPDB_API_KEY": "test-key"}, clear=False), \
             mock.patch.object(server, "urlopen", return_value=response) as urlopen_mock:
            result = server._abuseipdb_check("8.8.8.8", consented=True)
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["abuse_confidence_score"], 82)
        self.assertTrue(result["shared_infrastructure_likely"])
        urlopen_mock.assert_called_once()

    def test_timeline_and_score_breakdown_are_explained(self):
        with mock.patch.object(server, "_public_resolutions", return_value=["8.8.8.8"]), \
             mock.patch.object(server, "_geo_context", return_value={"status": "not_configured", "message": "no db"}), \
             mock.patch.object(server, "_tls_check", return_value={"status": "valid", "days_remaining": 5, "message": "synthetic tls"}), \
             mock.patch.dict(os.environ, {"OBSIDIAN_ABUSEIPDB_API_KEY": ""}, clear=False):
            result = server.analyze_domain("example.com")
        self.assertEqual(result["score"], 20)
        self.assertEqual(result["score_breakdown"][0]["points"], 20)
        self.assertTrue(any(event["category"] == "dns" for event in result["timeline"]))
        self.assertTrue(any(event["category"] == "tls" for event in result["timeline"]))
        self.assertTrue(any(event["category"] == "report" for event in result["timeline"]))
        self.assertIn("no demuestra", result["disclaimer"].lower())
        self.assertEqual(result["reputation_checks_performed"], 0)

    def test_free_analysis_is_disabled_by_default_in_commercial_mode(self):
        self.assertFalse(server.FREE_ANALYSIS_ENABLED)




class CommercialFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_db = server.DB_PATH
        server.DB_PATH = Path(self.temp_dir.name) / "test.sqlite3"

    def tearDown(self):
        server.DB_PATH = self.old_db
        self.temp_dir.cleanup()

    def test_order_requires_dns_verification_by_default(self):
        created = server._create_order("example.com", "buyer@example.com", False, immediate_delivery_acknowledged_at="2026-10-21T00:00:00Z")
        order = server._order_row(created["order_id"])
        self.assertFalse(created["verified"])
        self.assertEqual(created["status"], "verification_pending")
        self.assertFalse(order["verified"])
        self.assertIsNone(order["domain_control_method"])

    def test_order_can_skip_dns_verification_when_disabled(self):
        with mock.patch.object(server, "REQUIRE_DNS_VERIFICATION", False):
            created = server._create_order("example.com", "buyer@example.com", False, immediate_delivery_acknowledged_at="2026-10-21T00:00:00Z")
        order = server._order_row(created["order_id"])
        self.assertTrue(created["verified"])
        self.assertTrue(order["verified"])
        self.assertEqual(order["domain_control_method"], "declared")

    def test_checkout_ready_without_dnspython_only_when_verification_disabled(self):
        with mock.patch.object(server, "_paypal_is_configured", return_value=True), \
             mock.patch.object(server, "COMMERCIAL_TERMS_READY", True), \
             mock.patch.object(server, "_dns_txt_verification_ready", return_value=False):
            with mock.patch.object(server, "REQUIRE_DNS_VERIFICATION", True):
                self.assertFalse(server._commercial_checkout_ready())
            with mock.patch.object(server, "REQUIRE_DNS_VERIFICATION", False):
                self.assertTrue(server._commercial_checkout_ready())

    def _verified_order(self):
        created = server._create_order("example.com", "buyer@example.com", True)
        conn = server._db_connect()
        try:
            conn.execute("UPDATE orders SET verified = 1, status = 'verified' WHERE order_id = ?", (created["order_id"],))
            conn.commit()
        finally:
            conn.close()
        return created, server._order_row(created["order_id"])

    def test_checkout_cannot_start_without_domain_verification(self):
        created = server._create_order("example.com", "buyer@example.com", True)
        order = server._order_row(created["order_id"])
        with mock.patch.object(server, "_commercial_checkout_ready", return_value=True), \
             mock.patch.object(server, "_paypal_api") as paypal_mock:
            with self.assertRaises(PermissionError):
                server._start_checkout(order)
            paypal_mock.assert_not_called()

    def test_paid_report_requires_access_token_before_paypal_lookup(self):
        created, order = self._verified_order()
        fake_checkout = {
            "id": "5O190127TN364715T",
            "links": [{"rel": "approve", "href": f"https://{'www.sandbox.paypal.com' if server.PAYPAL_ENVIRONMENT == 'sandbox' else 'www.paypal.com'}/checkoutnow?token=5O190127TN364715T"}],
        }
        with mock.patch.object(server, "_commercial_checkout_ready", return_value=True), \
             mock.patch.object(server, "_paypal_api", return_value=fake_checkout):
            checkout = server._start_checkout(order)
        with mock.patch.object(server, "_paypal_api") as paypal_mock:
            status, payload = server._paid_report(checkout["payment_id"], "wrong-token")
        self.assertEqual(status, 403)
        self.assertIn("Token de acceso", payload["error"])
        paypal_mock.assert_not_called()

    def test_capture_requires_access_token_before_paypal_lookup(self):
        created, order = self._verified_order()
        payment_id = "5O190127TN364715T"
        host = "www.sandbox.paypal.com" if server.PAYPAL_ENVIRONMENT == "sandbox" else "www.paypal.com"
        fake_checkout = {
            "id": payment_id,
            "links": [{"rel": "approve", "href": f"https://{host}/checkoutnow?token={payment_id}"}],
        }
        with mock.patch.object(server, "_commercial_checkout_ready", return_value=True), \
             mock.patch.object(server, "_paypal_api", return_value=fake_checkout):
            checkout = server._start_checkout(order)
        with mock.patch.object(server, "_paypal_api") as paypal_mock:
            status, payload = server._capture_paypal_order(checkout["payment_id"], "wrong-token")
        self.assertEqual(status, 403)
        self.assertIn("Token de acceso", payload["error"])
        paypal_mock.assert_not_called()

    def test_paid_report_generates_once_after_confirmed_payment(self):
        created, order = self._verified_order()
        payment_id = "5O190127TN364715T"
        fake_checkout = {
            "id": payment_id,
            "links": [{"rel": "approve", "href": f"https://{'www.sandbox.paypal.com' if server.PAYPAL_ENVIRONMENT == 'sandbox' else 'www.paypal.com'}/checkoutnow?token={payment_id}"}],
        }
        paid_order = {
            "id": payment_id, "status": "COMPLETED",
            "purchase_units": [{
                "reference_id": created["order_id"], "custom_id": created["order_id"],
                "amount": {"currency_code": "EUR", "value": f"{server.PILOT_PRICE_CENTS / 100:.2f}"},
                "payments": {"captures": [{"status": "COMPLETED", "amount": {"currency_code": "EUR", "value": f"{server.PILOT_PRICE_CENTS / 100:.2f}"}}]},
            }],
        }
        fake_report = {"case_id": "OC-TEST-REPORT", "domain": "example.com", "timeline": [], "score": 0}
        with mock.patch.object(server, "_commercial_checkout_ready", return_value=True), \
             mock.patch.object(server, "_paypal_api", side_effect=[fake_checkout, paid_order, paid_order]), \
             mock.patch.object(server, "analyze_domain", return_value=fake_report) as analyze_mock:
            checkout = server._start_checkout(order)
            status, payload = server._paid_report(checkout["payment_id"], created["report_access_token"])
            self.assertEqual(status, 200)
            self.assertEqual(payload["status"], "ready")
            self.assertEqual(payload["report"]["commercial"]["payment_status"], "paid")
            status2, payload2 = server._paid_report(checkout["payment_id"], created["report_access_token"])
            self.assertEqual(status2, 200)
            self.assertEqual(payload2["report"]["case_id"], "OC-TEST-REPORT")
            analyze_mock.assert_called_once()

    def test_paid_report_concurrent_requests_only_generate_once(self):
        import threading
        created, order = self._verified_order()
        payment_id = "5O190127TN364716U"
        fake_checkout = {
            "id": payment_id,
            "links": [{"rel": "approve", "href": f"https://{'www.sandbox.paypal.com' if server.PAYPAL_ENVIRONMENT == 'sandbox' else 'www.paypal.com'}/checkoutnow?token={payment_id}"}],
        }
        paid_order = {
            "id": payment_id, "status": "COMPLETED",
            "purchase_units": [{
                "reference_id": created["order_id"], "custom_id": created["order_id"],
                "amount": {"currency_code": "EUR", "value": f"{server.PILOT_PRICE_CENTS / 100:.2f}"},
                "payments": {"captures": [{"status": "COMPLETED", "amount": {"currency_code": "EUR", "value": f"{server.PILOT_PRICE_CENTS / 100:.2f}"}}]},
            }],
        }
        fake_report = {"case_id": "OC-TEST-CONCURRENT", "domain": "example.com", "timeline": [], "score": 0}
        analysis_started = threading.Event()
        allow_analysis_to_finish = threading.Event()
        first_result = []
        def slow_analysis(*args, **kwargs):
            analysis_started.set()
            if not allow_analysis_to_finish.wait(timeout=5):
                raise TimeoutError("La prueba no liberó el análisis a tiempo.")
            return dict(fake_report)
        def run_first_request():
            first_result.append(server._paid_report(payment_id, created["report_access_token"]))
        with mock.patch.object(server, "_commercial_checkout_ready", return_value=True), \
             mock.patch.object(server, "_paypal_api", return_value=fake_checkout):
            server._start_checkout(order)
        worker = threading.Thread(target=run_first_request, daemon=True)
        with mock.patch.object(server, "_paypal_api", return_value=paid_order), \
             mock.patch.object(server, "analyze_domain", side_effect=slow_analysis) as analyze_mock:
            try:
                worker.start()
                self.assertTrue(analysis_started.wait(timeout=3), "La primera petición no llegó al análisis.")
                status2, payload2 = server._paid_report(payment_id, created["report_access_token"])
                self.assertEqual(status2, 202)
                self.assertEqual(payload2["status"], "report_generating")
            finally:
                allow_analysis_to_finish.set()
                worker.join(timeout=6)
            self.assertFalse(worker.is_alive(), "La primera petición quedó bloqueada.")
            self.assertEqual(len(first_result), 1)
            self.assertEqual(first_result[0][0], 200)
            self.assertEqual(first_result[0][1]["status"], "ready")
            analyze_mock.assert_called_once()

    def test_unpaid_paypal_order_does_not_run_analysis(self):
        created, order = self._verified_order()
        payment_id = "5O190127TN364717V"
        fake_checkout = {
            "id": payment_id,
            "links": [{"rel": "approve", "href": f"https://{'www.sandbox.paypal.com' if server.PAYPAL_ENVIRONMENT == 'sandbox' else 'www.paypal.com'}/checkoutnow?token={payment_id}"}],
        }
        unpaid_order = {
            "id": payment_id, "status": "APPROVED",
            "purchase_units": [{
                "reference_id": created["order_id"], "custom_id": created["order_id"],
                "amount": {"currency_code": "EUR", "value": f"{server.PILOT_PRICE_CENTS / 100:.2f}"},
            }],
        }
        with mock.patch.object(server, "_commercial_checkout_ready", return_value=True), \
             mock.patch.object(server, "_paypal_api", return_value=fake_checkout):
            checkout = server._start_checkout(order)
        with mock.patch.object(server, "_paypal_api", return_value=unpaid_order), \
             mock.patch.object(server, "analyze_domain") as analyze_mock:
            status, payload = server._paid_report(checkout["payment_id"], created["report_access_token"])
        self.assertEqual(status, 202)
        self.assertEqual(payload["status"], "payment_pending")
        analyze_mock.assert_not_called()

if __name__ == '__main__':
    unittest.main()
