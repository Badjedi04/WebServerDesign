Author: Prashant 

Old Dominion University

## Docker Command
Build Docker Image

docker build --tag web:v1.0 .


Run Docker Image

docker run --rm -it -p 3001:80 -v ${PWD}:/app --entrypoint bash web:v1.1


## Course Details

- **Instructor:** Dr. Sawood Alam (@ibnesayeed)
- **Institution:** Old Dominion University (ODU)

## Topics Covered

The course covers a wide range of topics related to web server design, including but not limited to:

1. **HTTP Basics**  
   - Introduction to HTTP
   - Web Architecture (W3C)
   - Using `telnet`, `curl`, and `wget`
2. **URIs, Logs, and MIME Types**
   - Git/GitHub workflow
   - Socket Programming
   - Python for Web Servers
3. **Conditionals & Redirections**
   - ETags and Date-time
   - Introduction to Docker
4. **Long-lived Connections & Pipelines**
5. **Range and Partial Content Handling**
6. **Character, Content, and Transfer Encodings**
7. **Content Negotiation**
8. **Authentication and Authorization**
9. **Unsafe Methods & CGI**
10. **HTTPS, HTTP/2, HTTP/3**
11. **REST and HATEOAS Concepts**
12. **Web Archiving (WARC, IPFS, IPWB)**


## References

- [RFC 7230 - HTTP/1.1 Message Syntax](https://datatracker.ietf.org/doc/html/rfc7230)
- [RFC 7231 - HTTP/1.1 Semantics and Content](https://datatracker.ietf.org/doc/html/rfc7231)
- [Docker Official Documentation](https://docs.docker.com/)
- [Memento 101](https://www.mementoweb.org/guide/quick-intro/)

