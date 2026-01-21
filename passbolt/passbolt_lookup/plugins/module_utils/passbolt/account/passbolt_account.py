
class PassboltAccount(object):
    def __init__(self, id: str, key_id: str, email: str, passphrase: str, fullbase_url: str, server_key_id: str):
        self.id = id
        self.key_id = key_id
        self.email = email
        self.passphrase = passphrase
        self.fullbase_url = fullbase_url
        self.server_key_id = server_key_id
