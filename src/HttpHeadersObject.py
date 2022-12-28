class HTTPHeadersObject:
    def __init__(self):
        self.report = \
            {
                "request":
                    {
                        "method": None,
                        "http_version": None,
                        "host": None,
                        "path": None,
                        "connection_close": False,
                        "modified": None,
                        "range": None,
                        "if_range": None,
                        "accept": None,
                        "accept_language": None,
                        "accept_charset": None,
                        "accept_encoding": None,
                        "negotiate": None,
                        "referrer": None,
                        "user_agent": None,
                        "authorization": None
                    },
                "response":
                    {
                        "status_code": None,
                        "etag": None,
                        "content_length": None,
                        "content_type": None,
                        "current_date": None,
                        "last_modified": None,
                        "allow": None,
                        "location": None,
                        "content_encoding": None,
                        "payload": None,
                        "content_range": None,
                        "transfer_encoding": None,
                        "vary": None,
                        "content_location": None,
                        "accept_ranges": None,
                        "content_language": None,
                        "character_set": None,
                        "TCN": None,
                        "alternatives": None,
                        "www_authenticate": None,
                        "authorization_info": None
                    },
                "connection": None
            }
