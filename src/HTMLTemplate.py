from src.Constants import *
from jinja2 import Environment
import os
import glob
from src.UtilityMethods import check_file_modified_time
from src.UtilityMethods import check_file_extensions
from src.UtilityMethods import set_alternatives_header


HTML_BODY = """
<!DOCTYPE html>
<html>
<head>
<title>{{ title_text }}</title>
</head>
<body>
<h1> {{heading_text}} </h1>
{{ body_text }}
</body>
</html>
"""


'''
Function to create dynamic page
'''


def create_dynamic_page(title_text="", heading_text="", body_text=""):
    html_content = Environment().from_string(HTML_BODY).render(title_text=title_text, heading_text=heading_text,
                                                               body_text=body_text)

    return html_content


'''
Function to get status code text
'''


def add_status_code_text(report):
    if report["response"]["status_code"] == STATUS_OK:
        return ' OK'
    elif report["response"]["status_code"] == STATUS_PARTIAL_CONTENT:
        return ' Partial Content'
    elif report["response"]["status_code"] == STATUS_MOVED_PERMANENTLY:
        return ' Moved Permanently'
    elif report["response"]["status_code"] == STATUS_FOUND:
        return ' Found'
    elif report["response"]["status_code"] == STATUS_UNMODIFIED:
        return ' Unmodified'
    elif report["response"]["status_code"] == STATUS_BAD_REQUEST:
        return ' Bad Request'
    elif report["response"]["status_code"] == STATUS_FORBIDDEN:
        return ' Forbidden'
    elif report["response"]["status_code"] == STATUS_NOT_FOUND:
        return ' Not Found'
    elif report["response"]["status_code"] == STATUS_REQUEST_TIMEOUT:
        return ' Request Timeout'
    elif report["response"]["status_code"] == STATUS_PRECONDITION_FAILED:
        return ' Precondition Failed'
    elif report["response"]["status_code"] == STATUS_MULTIPLE_CHOICE:
        return ' Multiple Choice'
    elif report["response"]["status_code"] == STATUS_NOT_ACCEPTABLE:
        return ' Not Acceptable'
    elif report["response"]["status_code"] == STATUS_REQUESTED_RANGE_NOT_SATISFIABLE:
        return ' Requested Range Not Satisfiable'
    elif report["response"]["status_code"] == STATUS_INTERNAL_SERVER_ERROR:
        return ' Internal Server Error'
    elif report["response"]["status_code"] == STATUS_NOT_IMPLEMENTED:
        return " Not Implemented"
    elif report["response"]["status_code"] == STATUS_HTTP_VERSION_NOT_SUPPORTED:
        return ' HTTP Version Not Supported'
    else:
        return str(report["response"]["status_code"])


'''
Function to create response 300 page
'''


def create_response_300_page(report, config_instance, config_mime_type, content_encoding, content_language,
                             charset_parser):
    payload_body = None
    # 0: Meme Type
    # 1: Charset
    # 2: Language
    # 3: Encoding
    list_extensions = [[], [], [], []]
    list_file_length = []
    list_files = []
    for files in glob.glob(config_instance.root_folder + report["request"]["path"] + "*"):
        mime_type, content_encoding_ext, content_language_ext, character_set_encoding_ext = \
            check_file_extensions(files, config_mime_type, content_encoding, content_language, charset_parser)
        list_extensions[0].append(mime_type)
        list_extensions[1].append(character_set_encoding_ext)
        list_extensions[2].append(content_language_ext)
        list_extensions[3].append(content_encoding_ext)
        file_handle = open(files, "rb")
        list_file_length.append(len(file_handle.read()))
        file_handle.close()
        list_files.append(files)
    if report["response"]["alternatives"] is None:
        report = set_alternatives_header(report, list_files, list_extensions, list_file_length)
    error_code_text = str(report["response"]["status_code"]) + ": " + add_status_code_text(report)
    heading_text = "Multiple Choices"
    body_text = create_body_for_300(list_files, list_extensions)
    payload = create_dynamic_page(title_text=error_code_text, heading_text=heading_text, body_text=body_text)
    file_handle = open(config_instance.error_folder + "/Error" + str(report["response"]["status_code"]) + ".html", "w")
    file_handle.write(payload)
    file_handle.close()
    return config_instance.error_folder + "/Error" + str(report["response"]["status_code"]) + ".html"


'''
Function to fill body of status code 300
'''


def create_body_for_300(list_files, list_extensions):
    html_body_content = """
    Available Variants:
    <ul>
    {{list_rows}}
    </ul>
    """
    html_list_rows = """
    <li><a> {{file_link}} </a> {{file_info}} </li>
    """
    rows_content = ""
    for index_files in range(0, len(list_files)):
        file_info = list_files[index_files].split(FORWARD_SLASH)[-1]
        for extension in range(0, len(list_extensions)):
            if list_extensions[extension][index_files] is not None:
                if extension == 0:
                    file_info += ", type " + list_extensions[extension][index_files]
                elif extension == 1:
                    file_info += ", character set " + list_extensions[extension][index_files]
                elif extension == 2:
                    file_info += ", language " + list_extensions[extension][index_files]
                elif extension == 3:
                    file_info += ", encoding " + list_extensions[extension][index_files]
        rows_content += Environment().from_string(html_list_rows).render(file_link=list_files[index_files],
                                                                         file_info=file_info)
    body_content = Environment().from_string(html_body_content).render(list_rows=rows_content)
    return body_content


'''
Function to create directory listings
'''


def create_directory_listing(report, config_instance):
    if report["request"]["path"] != FORWARD_SLASH:
        directory_listing = [f for f in os.listdir(config_instance.root_folder + report["request"]["path"])]
    else:
        directory_listing = [f for f in os.listdir(config_instance.root_folder)]
    table_rows = ""
    for i in range(0, len(directory_listing)):
        modified_time = check_file_modified_time(report, config_instance)
        if os.path.isfile(config_instance.root_folder + report["request"]["path"] + directory_listing[i]):
            file_size = str(os.path.getsize(config_instance.root_folder + report["request"]["path"] + FORWARD_SLASH
                                            + directory_listing[i]))
        else:
            file_size = "--"
        html_a_tag = """<a href= {{file_link}} > {{file_name}} </a>"""
        if os.path.isfile(config_instance.root_folder + report["request"]["path"] + directory_listing[i]):
            links_to_listings = Environment().from_string(html_a_tag).render(file_link=report["request"]["path"]
                                                                                       + directory_listing[i],
                                                                             file_name=directory_listing[i])
        else:
            links_to_listings = Environment().from_string(html_a_tag).render(file_link=report["request"]["path"]
                                                                                       + directory_listing[i]
                                                                                       + FORWARD_SLASH,
                                                                             file_name=directory_listing[i]
                                                                                       + FORWARD_SLASH)
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
    payload = create_dynamic_page(title_text="Directory Listing", heading_text="Index of " + report["request"]["path"]
                                                                               + " :",
                                  body_text=directory_listing_table)
    file_handle = open(config_instance.error_folder + "/DirectoryListing.html", "w")
    file_handle.write(payload)
    file_handle.close()
    return config_instance.error_folder + "/DirectoryListing.html"


'''
Function to create dynamic error pages
'''


def create_dynamic_error_pages(report, config_instance):
    error_code_text = str(report["response"]["status_code"]) + ":" + add_status_code_text(report)
    payload = create_dynamic_page(title_text=error_code_text, heading_text=error_code_text,
                                  body_text="This is an error page")

    file_handle = open(config_instance.error_folder + "/Error" + str(report["response"]["status_code"]) + ".html", "w")
    file_handle.write(payload)
    file_handle.close()
    return config_instance.error_folder + "/Error" + str(report["response"]["status_code"]) + ".html"
