import os
import pytest
import bot_shield
from app import app, TARPIT_TARGET, TARPIT_EXPIRES


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_bot_shield_tarpit_flag():
    os.environ['TARPIT_KNOWN_BOTS'] = 'true'
    v = bot_shield.evaluate_request('Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)', '1.2.3.4', '/')
    assert v['action'] == 'tarpit'
    assert v['reason'] == 'known_bot_tarpit'
    assert v['bot'] == 'GPTBot'
    assert v['difficulty_hint'] == 'tarpit'

    os.environ['TARPIT_KNOWN_BOTS'] = 'false'
    v2 = bot_shield.evaluate_request('Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)', '1.2.3.4', '/')
    assert v2['action'] != 'tarpit'

    os.environ['TARPIT_KNOWN_BOTS'] = 'true'


def test_shield_check_tarpit(client):
    res = client.post(
        '/shield/check',
        headers={'User-Agent': 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)'},
        json={'path': '/'}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['action'] == 'shield'
    assert data['tarpit'] is True
    assert data['challenge']['target'] == '0' * 16
    assert len(data['challenge']['target']) == 16


def test_challenge_tarpit(client):
    res = client.post(
        '/challenge',
        headers={'User-Agent': 'Mozilla/5.0 (compatible; Google-Extended; +https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers)'},
        json={}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['action'] == 'shield'
    assert data['tarpit'] is True
    assert data['challenge']['target'] == '0' * 16


def test_tarpit_redemption_fails(client):
    res = client.post(
        '/shield/check',
        headers={'User-Agent': 'Mozilla/5.0 (compatible; CCBot/2.0; +https://commoncrawl.org/faq/)'},
        json={'path': '/'}
    )
    data = res.get_json()
    res_redeem = client.post('/shield/redeem', json={
        'token': data['token'],
        'solutions': 'bogus_solution_123',
        'challenge_signature': data['challenge']['challenge_signature']
    })
    assert res_redeem.status_code in (400, 403)


def test_challenge_page_served_to_bot(client):
    res = client.get(
        '/challenge-page',
        headers={'User-Agent': 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)'}
    )
    assert res.status_code == 200
    assert b'Verifying you are human' in res.data
    assert b'TIMEOUT_MS = target.length >= 12' in res.data
