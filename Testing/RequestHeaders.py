# Request Header for Response Code: 200
TEST_200 = 'GET / HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

'''
Test HTTP Version (Response Code: 505)
'''
TEST_HTTP_VERSION = 'GET / HTTP/3.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

'''
Test HTTP Method (Response Code: 501)
'''
TEST_HTTP_METHOD = 'FOO / HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code: 200
TEST_PPT_MIME_TYPE = 'GET /a1-test/1/1.3/assignment1.ppt HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_XML_MIME_TYPE = 'GET /a1-test/1/1.2/arXiv.org.Idenitfy.repsonse.xml HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_HTML_MIME_TYPE = 'GET /a1-test/1/1.4/escape%this.html HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_NO_MIME_TYPE = 'GET /a1-test/1/1.4/test:.HTM HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_JPEG_MIME_TYPE = 'GET /a1-test/2/0.jpeg HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_GIF_MIME_TYPE = 'GET /a1-test/2/6.gif HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_TEXT_MIME_TYPE = 'GET /a1-test/4/thisfileisempty.txt HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_NO_EXTENTION = 'GET /a1-test/4/directory3isempty HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_HTML_SPACE_MIME_TYPE = 'GET /a1-test/1/1.1/go%20hokies!.html HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_HEAD_HTML_SPACE_MIME_TYPE = 'HEAD /a1-test/1/1.1/go%20hokies!.html HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# TRACE Method
TEST_TRACE_HEADER = 'TRACE / HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
Testing-1: TINTIN-SAILOR\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# OPTIONS Method
TEST_OPTIONS_HEADER = 'OPTIONS / HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
Testing-1: TINTIN-SAILOR\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

#
TEST_400 = "GET /foo HTTP/1.1\r\n\
Host: 127.0.0.1\r\n\
Header with missing colon\r\n\r\n"

TEST_HEADER = "GET / HTTP/1.1\r\n\
Host: cs531-msiddique:80\r\n\
Connection: close\r\n\r\n"

# OPTIONS Method
TEST_403 = 'OPTIONS /Debug.log HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
Testing-1: TINTIN-SAILOR\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# OPTIONS Method
TEST_403_FOLDER = 'OPTIONS /ErrorPage/Error400.html HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
Testing-1: TINTIN-SAILOR\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# OPTIONS Method
TEST_HTTP_MISSING = 'OPTIONS /ErrorPage/Error400.html HTML/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
Testing-1: TINTIN-SAILOR\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# OPTIONS Method
TEST_HOST_MISSING = 'OPTIONS /ErrorPage/Error400.html HTTP/1.1\r\n\
Testing-1: TINTIN-SAILOR\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_ABSOLUTE_URI = 'HEAD 127.0.0.1:5010/a1-test/1/1.1/go%20hokies!.html HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'

# Request Header for Response Code:200
TEST_ABSOLUTE_URI_1 = 'HEAD 127.0.0.1:5010/a1-test/2/0.jpeg HTTP/1.1\r\n\
Host: 127.0.0.1:5010\r\n\
User-Agent: Tester/0.1\r\n\
Accept: */*\r\n\
Connection: close\r\n\r\n'