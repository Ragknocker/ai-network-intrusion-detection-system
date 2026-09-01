import json
from lambda_handler import lambda_handler

def test_url_analysis():
    event = {
        "body": json.dumps({"url": "http://paypa1-security-update.xyz/login.php"})
    }
    response = lambda_handler(event, None)
    assert response["statusCode"] == 200
    data = json.loads(response["body"])
    assert data["targetType"] == "URL"
    assert data["analysis"]["status"] == "Phishing / Malicious"
    print("URL Analysis Test Passed!")

def test_code_payload_analysis():
    event = {
        "body": json.dumps({"code_payload": "function test() { eval(atob('cmd')); }"})
    }
    response = lambda_handler(event, None)
    assert response["statusCode"] == 200
    data = json.loads(response["body"])
    assert data["targetType"] == "CodePayload"
    assert data["analysis"]["status"] == "Malicious Function / Exploit"
    print("Code Payload Analysis Test Passed!")

if __name__ == "__main__":
    test_url_analysis()
    test_code_payload_analysis()
