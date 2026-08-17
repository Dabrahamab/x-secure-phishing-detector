import importlib
import os

import pytest

import phishing_system
import web_app

app = web_app.app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_home_page_loads(client):
    response = client.get('/')
    assert response.status_code == 200


def test_analysis_endpoint_returns_summary(client):
    response = client.post(
        '/api/analyze', data={'urls': 'https://example.com\nhttps://paypal.com'})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['summary']['total_analyzed'] == 2
    assert 'results' in payload


def test_smtp_config_uses_environment_variables(monkeypatch):
    monkeypatch.setenv('SMTP_SERVER', 'smtp.example.com')
    monkeypatch.setenv('SMTP_PORT', '2525')
    monkeypatch.setenv('SMTP_USERNAME', 'tester@example.com')
    monkeypatch.setenv('SMTP_PASSWORD', 'secret-password')
    monkeypatch.setenv('FROM_EMAIL', 'no-reply@example.com')

    importlib.reload(web_app)

    assert web_app.SMTP_CONFIG['smtp_server'] == 'smtp.example.com'
    assert web_app.SMTP_CONFIG['smtp_port'] == 2525
    assert web_app.SMTP_CONFIG['username'] == 'tester@example.com'
    assert web_app.SMTP_CONFIG['password'] == 'secret-password'
    assert web_app.SMTP_CONFIG['from_email'] == 'no-reply@example.com'

    os.environ.pop('SMTP_SERVER', None)
    os.environ.pop('SMTP_PORT', None)
    os.environ.pop('SMTP_USERNAME', None)
    os.environ.pop('SMTP_PASSWORD', None)
    os.environ.pop('FROM_EMAIL', None)
    importlib.reload(web_app)


def test_random_forest_model_evaluation_metrics():
    system = phishing_system.PhishingTakedownSystem()
    metrics = system.train_model()

    assert 'precision' in metrics
    assert 'recall' in metrics
    assert 'f1_score' in metrics
    assert metrics['precision'] >= 0.0
    assert metrics['recall'] >= 0.0
    assert metrics['f1_score'] >= 0.0


def test_threat_intel_and_evidence_generation():
    system = phishing_system.PhishingTakedownSystem()
    site = system.analyze_url('https://paypa1-security-login.example.com')

    assert hasattr(site, 'hosting_provider')
    assert hasattr(site, 'ip_address')
    assert hasattr(site, 'registrar')
    assert hasattr(site, 'country')
    assert hasattr(site, 'technical_intel')
    assert 'domain' in site.technical_intel
    assert 'network' in site.technical_intel
    assert 'ssl' in site.technical_intel
    assert 'url' in site.technical_intel
    assert 'http' in site.technical_intel
    assert 'html' in site.technical_intel
    assert 'reputation' in site.technical_intel
    assert 'behavior' in site.technical_intel
    assert 'blocklist_status' in site.technical_intel['reputation']
    assert 'async_network_requests' in site.technical_intel['behavior']

    report_path = system.collect_evidence(site)
    assert os.path.exists(report_path)
    assert report_path.endswith('.txt')


def test_analysis_response_includes_technical_intelligence_fields(client):
    response = client.post(
        '/api/analyze', data={'urls': 'https://paypal.com/login/update'}
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['results'][0]['technical_intel']
    assert set(['domain', 'network', 'ssl', 'url', 'http', 'html', 'reputation', 'behavior']).issubset(
        payload['results'][0]['technical_intel'].keys()
    )
