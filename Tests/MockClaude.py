#!/usr/bin/env python3
"""Local CDP fixture; never connects to a network or reads an account/profile."""
import json
import os

reader = os.fdopen(3, "rb", buffering=0)
writer = os.fdopen(4, "wb", buffering=0)
timezone = locale = language = None
mode = os.environ.get("MOCK_MODE", "normal")
configured = set()

def send(packet):
    writer.write(json.dumps(packet).encode() + b"\0")

def event(method, params, session="page-1"):
    send({"method": method, "params": params, "sessionId": session})

while True:
    packet = bytearray()
    while True:
        byte = reader.read(1)
        if not byte:
            raise SystemExit(0)
        if byte == b"\0":
            break
        packet += byte
    message = json.loads(packet)
    method, params = message["method"], message.get("params", {})
    result = {}
    if method == "Browser.getVersion":
        result = {"userAgent": "MockClaude/1.0"}
    elif method == "Emulation.setTimezoneOverride":
        if message.get('sessionId') == 'closing-page':
            send({'id': message['id'], 'error': {'message': 'Session with given id not found'}})
            event('Target.detachedFromTarget', {'sessionId': 'closing-page'})
            continue
        if mode == 'duplicate-target' and message.get('sessionId') in configured:
            send({'id': message['id'], 'error': {'message': 'Duplicate configuration'}})
            continue
        configured.add(message.get('sessionId'))
        timezone = params["timezoneId"]
    elif method == "Emulation.setLocaleOverride":
        if mode == "unsupported":
            send({"id": message["id"], "error": {"message": "Method not found"}})
            continue
        if mode.startswith('shared-locale'):
            locale = 'fr_FR' if mode == 'shared-locale-wrong' else 'en_US'
            send({'id': message['id'], 'error': {'message': 'Another locale override is already in effect'}})
            continue
        locale = params["locale"]
    elif method == "Network.setUserAgentOverride":
        language = params["acceptLanguage"]
    elif method == "Runtime.evaluate":
        if mode == 'replaced-context' and params.get('contextId') == 1:
            event('Runtime.executionContextDestroyed', {'executionContextId': 1})
            event('Runtime.executionContextCreated', {'context': {'id': 2, 'auxData': {'isDefault': True}}})
        wrong = mode == 'wrong-profile' or (mode == 'wrong-profile-child' and message.get('sessionId') == 'page-child') or (mode == 'replaced-context' and params.get('contextId') == 1)
        value = {"timezone": "Europe/Moscow" if wrong else timezone,
                 "language": 'ru-RU' if mode == 'shared-locale-language-wrong' else language,
                 "locale": (locale or '').replace('_','-'), "url": 'https://claude.ai/'}
        if mode == 'shared-locale-unverified':
            value.pop('locale')
        result = {"result": {"value": value}}
    elif method == "Network.getResponseBody":
        result = {"body": '{"answer":"hello response","refresh_token":"response-secret"}', "base64Encoded": False}
    send({"id": message["id"], "result": result})
    if method == "Target.setAutoAttach" and not message.get("sessionId"):
        if mode == 'closing-target':
            event('Target.attachedToTarget', {'sessionId': 'closing-page', 'targetInfo': {'type': 'iframe'}, 'waitingForDebugger': True})
        event("Target.attachedToTarget", {"sessionId": "page-1", "targetInfo": {"type": "page"}, "waitingForDebugger": True})
        if mode == 'duplicate-target':
            event("Target.attachedToTarget", {"sessionId": "page-1", "targetInfo": {"type": "page"}, "waitingForDebugger": True})
        if mode == 'wrong-profile-child':
            event('Target.attachedToTarget', {'sessionId': 'page-child', 'targetInfo': {'type': 'iframe'}, 'waitingForDebugger': True})
    if method == "Runtime.enable":
        event("Runtime.executionContextCreated", {"context": {"id": 1, "auxData": {"isDefault": True}}}, message.get('sessionId', 'page-1'))
    if method == "Runtime.runIfWaitingForDebugger":
        assert timezone == "Europe/Amsterdam" and language == "en-US"
        if mode != 'shared-locale-wrong':
            assert locale == 'en_US'
        request = {"method": "POST", "url": "https://claude.ai/api/chat?token=query-secret",
                   "headers": {"Authorization": "Bearer auth-secret", "Cookie": "cookie-secret", "Accept-Language": language},
                   "postData": '{"message":"hello request","access_token":"request-secret","timezone":"Europe/Moscow"}'}
        event("Network.requestWillBeSent", {"requestId": "request-1", "request": request, "type": "Fetch"})
        event("Network.responseReceived", {"requestId": "request-1", "response": {"status": 200, "mimeType": "application/json", "headers": {"Set-Cookie": "response-cookie"}}})
        event("Network.loadingFinished", {"requestId": "request-1"})
