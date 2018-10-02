import os, sys, hmac, hashlib

def validateHMAC(message,secret,hash):
    cleanHash = hash[5:]
    encodedSecret = secret.encode()
    encodedMessage = message.encode()
    expectedHmac = hmac.new(encodedSecret,encodedMessage,hashlib.sha1)

    hmacDigest = expectedHmac.hexdigest()

    if hmacDigest == cleanHash:
        return True
    return False


def handle(req):
    mac = os.getenv("Http_Hmac")
    secret = "mysecret"

    if validateHMAC(req,secret,mac):
        return "Sucessfuly validated here is your response:" + req
    return "HMAC validation failed."

