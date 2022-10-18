from jinja2 import Environment
import os

import utils

def create_dynamic_page(title="", heading="", body=""):
    html_content = """
        <!DOCTYPE html>
        <html>
            <head>
                <title>{{title}}</title>
            </head>
            <body>
                <h1>{{heading}}</h1>
                {{body}}
            </body>
        </html>
    """

    html_content = Environment().from_string(html_content).render(title=title,
                                                               heading=heading,body=body)
    return html_content

def create_error_page(report):
    title = report["response"]["status_code"] + "-" + report["response"]["status_text"]
    heading = report["response"]["status_code"] + "-" + report["response"]["status_text"]
    body = "This is an error page"
    return create_dynamic_page(title, heading, body)

def create_directory_listing(report, config):
    directory_listing = [f for f in os.listdir(report["request"]["path"])]

    table_rows = ""
    for i in range(0, len(directory_listing)):
        modified_time = utils.get_file_last_modified_time(report["request"]["path"])
        if os.path.isfile(config["MAPPING"]["root_dir"]  + report["request"]["path"] + directory_listing[i]):
            file_size = str(os.path.getsize(config["MAPPING"]["root_dir"] + report["request"]["path"] + "/"
                                            + directory_listing[i]))
        else:
            file_size = "--"
        html_a_tag = """<a href= {{file_link}} > {{file_name}} </a>"""
        if os.path.isfile(config["MAPPING"]["root_dir"] + report["request"]["path"] + directory_listing[i]):
            links_to_listings = Environment().from_string(html_a_tag).render(file_link=report["request"]["path"]
                                                                                       + directory_listing[i],
                                                                             file_name=directory_listing[i])
        else:
            links_to_listings = Environment().from_string(html_a_tag).render(file_link=report["request"]["path"]
                                                                                       + directory_listing[i]
                                                                                       + "/",
                                                                             file_name=directory_listing[i]
                                                                                       + "/")
        html_table_row = """
        <tr>
        <td> {{file_info}} </td>
        <td> {{modified_time}} </td>
        <td> {{file_size}} </td>
        </tr>
        """

        table_content = Environment().from_string(html_table_row).render(file_info=links_to_listings,
                                                                         modified_time=modified_time,
                                                                         file_size=file_size)
        table_rows += table_content

    table_html = """
    <table>
    <tr>
    <th>Name </th>
    <th> Last Modified Time</th>
    <th> Size</th>
    </tr>
    {{table_rows}}
    </table>
    """
    directory_listing_table = Environment().from_string(table_html).render(table_rows=table_rows)
    payload = create_dynamic_page("Directory Listing", "Index of " + report["request"]["path"] + " :", directory_listing_table)
    return payload



