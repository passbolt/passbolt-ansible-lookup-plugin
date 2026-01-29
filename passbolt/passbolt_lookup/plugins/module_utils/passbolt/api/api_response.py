
class APIResponse(object):

    def __init__(self, http_status_code: int, http_headers: dict, content: dict | None):
        self.http_status_code = http_status_code
        self.http_headers = http_headers
        if isinstance(content, dict) and "header" in content and "body" in content:
            self.header = content["header"]
            self.body = content["body"]
        else:
            self.header = None
            self.body = None

    def is_success(self):
        return (self.http_status_code == 200
                and isinstance(self.header, dict)
                and "status" in self.header
                and self.header["status"] == "success")