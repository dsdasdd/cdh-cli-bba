class JsonResponseMock:
    def __init__(self, status_code: int, json_data: dict):
        self.json_data = json_data
        self.status_code = status_code
        self.ok = False
        if status_code == 200:
            self.ok = True
        self.text = str(json_data)

    def json(self) -> dict:
        return self.json_data


def get_fake_json_response(status_code: int, json_data: dict) -> JsonResponseMock:

    return JsonResponseMock(status_code, json_data)
