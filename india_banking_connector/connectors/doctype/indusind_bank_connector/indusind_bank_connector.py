# Copyright (c) 2026, Aerele Technologies Private Limited and contributors
# For license information, please see license.txt

import hashlib
import hmac
import json
from base64 import b64decode, b64encode

from Crypto.Cipher import AES

from india_banking_connector.connectors.bank_connector import BankConnector

GCM_TAG_LENGTH = 16


class IndusIndBankConnector(BankConnector):
	bank = "IndusInd Bank"

	# IndusInd's Batch API uses AES-256-GCM + HMAC-SHA256, which the base class
	# doesn't provide (it only has CBC and JWE-wrapped GCM). Byte layout below
	# (ciphertext|tag, fixed IV from the `iv` field) is per the H2H doc and is
	# unverified against a live UAT sample — confirm before a real UAT call.

	def _aes_key(self) -> bytes:
		return bytes.fromhex(self.get_password("aes_key"))

	def _aes_iv(self) -> bytes:
		return bytes.fromhex(self.get_password("iv"))

	def _encrypt(self, plain: str) -> str:
		cipher = AES.new(self._aes_key(), AES.MODE_GCM, nonce=self._aes_iv())
		ciphertext, tag = cipher.encrypt_and_digest(plain.encode())
		return b64encode(ciphertext + tag).decode()

	def _decrypt(self, blob: str) -> str:
		raw = b64decode(blob)
		ciphertext, tag = raw[:-GCM_TAG_LENGTH], raw[-GCM_TAG_LENGTH:]
		cipher = AES.new(self._aes_key(), AES.MODE_GCM, nonce=self._aes_iv())
		return cipher.decrypt_and_verify(ciphertext, tag).decode()

	def _hash(self, plain: str) -> str:
		return hmac.new(self._aes_key(), plain.encode(), hashlib.sha256).hexdigest()

	def _envelope(self, body: dict, lower: bool) -> dict:
		plain = json.dumps(body, separators=(",", ":"))
		msg_key, hash_key = ("requestMsg", "requestHash") if lower else ("RequestMsg", "RequestHash")
		return {msg_key: self._encrypt(plain), hash_key: self._hash(plain)}
