
def create_html_page(status_code, status_text):
    body = """
        <!DOCTYPE html>
        <html>
        <head>
        <title>Error Page</title>
        </head>
        <body>

        <h1>$(status_code)</h1>
        <p>$(status_text)</p>

        </body>
        </html>
    """

    body = body.replace("$(status_code)", status_code)
    body = body.replace("$(status_text)", status_text)

    return body




