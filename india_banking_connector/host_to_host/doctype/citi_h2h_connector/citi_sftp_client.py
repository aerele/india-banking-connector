import frappe
import paramiko


class CitiSFTPClient:
	def __init__(
		self,
		host: str,
		username: str,
		private_key_path: str,
		port: int = 22,
		private_key_passphrase: str | None = None,
		timeout: int = 20,
		verify_host_key: bool = True,
	):
		self.host = host
		self.port = port
		self.username = username
		self.private_key_path = private_key_path
		self.private_key_passphrase = private_key_passphrase
		self.timeout = timeout
		self.verify_host_key = verify_host_key

		self.client = None
		self.sftp = None

		self.connect()

	def connect(self) -> bool:
		try:
			self.client = paramiko.SSHClient()

			if self.verify_host_key:
				self.client.load_system_host_keys()
				self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
			else:
				# Explicit opt-out only
				self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

			self.client.connect(
				hostname=self.host,
				port=self.port,
				username=self.username,
				key_filename=self.private_key_path,
				passphrase=self.private_key_passphrase,
				timeout=self.timeout,
				allow_agent=False,
				look_for_keys=False,
				disabled_algorithms={
					"pubkeys": [
						"rsa-sha2-512",
						"rsa-sha2-256",
					],
					"keys": [
						"rsa-sha2-512",
						"rsa-sha2-256",
					],
				},
			)

			self.sftp = self.client.open_sftp()
			return True

		except Exception:
			frappe.log_error(
				"Citi SFTP Connection Failed", frappe.get_traceback(with_context=True)
			)
			return False

	def upload(self, local_path: str, remote_path: str) -> bool:
		try:
			if not self.sftp:
				self.connect()
			self.sftp.put(local_path, remote_path, confirm=False)
			return True

		except Exception:
			frappe.log_error(
				"Citi SFTP Upload Failed", frappe.get_traceback(with_context=True)
			)
			return False

		finally:
			self.close()

	def get(self, remote_path: str, local_path: str) -> bool:
		try:
			if not self.sftp:
				self.connect()

			self.sftp.get(remote_path, local_path)
			return True

		except Exception:
			frappe.log_error(
				"Citi SFTP Download Failed", frappe.get_traceback(with_context=True)
			)
			return False

		finally:
			self.close()

	def list_files(self, remote_path: str = ".", close=True) -> list:
		try:
			if not self.sftp:
				self.connect()
			files = [
				item.filename
				for item in self.sftp.listdir_attr(remote_path)
				if (item.st_mode & 0o100000)
			]
			return files

		except Exception:
			frappe.log_error(
				"Citi SFTP List Files Failed", frappe.get_traceback(with_context=True)
			)
			return []

		finally:
			if close:
				self.close()

	def close(self):
		try:
			if self.sftp:
				self.sftp.close()
		finally:
			self.sftp = None

		try:
			if self.client:
				self.client.close()
		finally:
			self.client = None

		return True
